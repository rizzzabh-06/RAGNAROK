import joblib
import numpy as np
import os
import re
import json
from typing import Dict, Any, List

# Preserved from existing system
TECH_RISK = {"T1059": 3, "T1047": 3, "T1021": 2}
ASSET_CRIT = {"db-prod": 3, "dc01": 3, "workstation": 1}
POWERSHELL_RE = re.compile(r"powershell|pwsh|wmic|rundll32|certutil|-enc|base64", re.I)

WEIGHTS = {
    "rule_severity": float(os.getenv("W_RULE", "0.20")),
    "ti_hit": float(os.getenv("W_TI", "0.20")),
    "burst": float(os.getenv("W_BURST", "0.15")),
    "asset": float(os.getenv("W_ASSET", "0.15")),
    "tech_risk": float(os.getenv("W_TECH", "0.15")),
    "heuristics": float(os.getenv("W_HEUR", "0.15")),
}

SEVERITY_MAX = int(os.getenv("SEVERITY_MAX", "12"))
BURST_MAX = int(os.getenv("BURST_MAX", "20"))

def load_model(model_path: str):
    """Load ML model if available, fallback to rule-based scoring"""
    try:
        if os.path.exists(model_path):
            model = joblib.load(model_path)
            print("✅ Model loaded successfully.")
            return model
    except Exception as e:
        print("⚠️ Warning: Model not loaded, using rule-based scoring.", e)
    return None

def norm(val: float, max_val: float) -> float:
    """Normalize value between 0 and 1"""
    try:
        return min(max(float(val) / float(max_val), 0.0), 1.0)
    except Exception:
        return 0.0

def extract_features(alert: Dict[str, Any]) -> List[float]:
    """Extract features from alert for ML model"""
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    mitre = alert.get("mitre", {})
    
    sev = rule.get("level", 3)
    techs = mitre.get("id", []) or []
    cmd_len = len(data.get("cmd", "") or "")
    
    return [
        float(sev),
        float(len(techs)),
        float(cmd_len),
    ]

def predict_score(model, alert: Dict[str, Any]) -> tuple[float, List[str]]:
    """Predict risk score using existing rule-based logic or ML model"""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    mitre = alert.get("mitre", {})
    
    sev = rule.get("level", 3)
    host = agent.get("name", "workstation")
    techs = mitre.get("id", []) or []
    srcip = data.get("srcip") or data.get("src_ip") or "-"
    burst = alert.get("recent_similar_count", 0)
    full_log = alert.get("full_log", "")
    ti_hit = alert.get("ti_hit", False)
    
    # Heuristic analysis
    heur = 1.0 if POWERSHELL_RE.search(full_log + json.dumps(data)) else 0.0
    ti = 1.0 if ti_hit else 0.0
    asset = ASSET_CRIT.get(host, 1)
    techrisk = max([TECH_RISK.get(t, 1) for t in techs] or [1])
    
    if model is None:
        # Use existing rule-based scoring
        score_val = 100 * (
            WEIGHTS["rule_severity"] * norm(sev, SEVERITY_MAX) +
            WEIGHTS["ti_hit"] * ti +
            WEIGHTS["burst"] * norm(burst, BURST_MAX) +
            WEIGHTS["asset"] * norm(asset, 3) +
            WEIGHTS["tech_risk"] * norm(techrisk, 3) +
            WEIGHTS["heuristics"] * heur
        )
    else:
        # Use ML model with features
        features = extract_features(alert)
        X = np.array([features])
        prob = model.predict_proba(X)[0][1] * 100
        score_val = prob
    
    score_val = round(score_val, 2)
    
    # Generate reasons (preserved from existing system)
    reasons = [f"Rule severity={sev}"]
    if ti: reasons.append("IOC matched in threat intel")
    if burst: reasons.append(f"Recent alert burst={burst}")
    if asset > 1: reasons.append(f"Critical asset: {host}")
    if techs: reasons.append("MITRE: " + ",".join(techs))
    if heur: reasons.append("Suspicious command line/process")
    
    return score_val, reasons

def explain_score(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Explain scoring factors for transparency"""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = alert.get("mitre", {})
    
    sev = rule.get("level", 3)
    host = agent.get("name", "workstation")
    techs = mitre.get("id", []) or []
    burst = alert.get("recent_similar_count", 0)
    
    return {
        "severity_weight": sev,
        "mitre_count": len(techs),
        "asset_criticality": ASSET_CRIT.get(host, 1),
        "burst_count": burst,
        "weights_used": WEIGHTS
    }