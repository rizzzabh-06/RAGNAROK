from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import os, time, hashlib, json, re

"""
AI Triage Service (Mac-1)
- /score: accept a Wazuh-like alert JSON, return score + reasons + dedup_key + suggested playbook
- /why/{dedup_key}: return last audit record for that key (transparency)
- Optional: MISP lookup if MISP_URL and MISP_API_KEY are set (boolean flag only)
"""

app = FastAPI(title="S3 SOC – AI Triage", version="0.1.0")

# Static maps (tunable). You can also load from a YAML later.
TECH_RISK = {"T1059": 3, "T1047": 3, "T1021": 2}
ASSET_CRIT = {"db-prod": 3, "dc01": 3, "workstation": 1}

# Weights (env overridable, keep simple floats that sum ~1.0)
WEIGHTS = {
    "rule_severity": float(os.getenv("W_RULE", "0.20")),
    "ti_hit": float(os.getenv("W_TI", "0.20")),
    "burst": float(os.getenv("W_BURST", "0.15")),
    "asset": float(os.getenv("W_ASSET", "0.15")),
    "tech_risk": float(os.getenv("W_TECH", "0.15")),
    "heuristics": float(os.getenv("W_HEUR", "0.15")),
}

SUPPRESS_MINUTES = int(os.getenv("SUPPRESS_MINUTES", "10"))
BURST_MAX = int(os.getenv("BURST_MAX", "20"))  # normalization upper bound
SEVERITY_MAX = int(os.getenv("SEVERITY_MAX", "12"))

AUDIT_LOG = os.getenv("AUDIT_LOG", "triage_audit.jsonl")

MISP_URL = os.getenv("MISP_URL", "").rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")

# In-memory stores
AUDIT_CACHE: Dict[str, Dict[str, Any]] = {}
SUPPRESS: Dict[str, float] = {}  # dedup_key -> unlock_epoch

POWERSHELL_RE = re.compile(r"powershell|pwsh|wmic|rundll32|certutil|-enc|base64", re.I)

class WazuhAlert(BaseModel):
    rule: Dict[str, Any] = {}
    agent: Dict[str, Any] = {}
    data: Dict[str, Any] = {}
    mitre: Dict[str, Any] = {}
    full_log: Optional[str] = ""
    recent_similar_count: int = 0
    ti_hit: Optional[bool] = None  # if None, we may try MISP
    extra: Dict[str, Any] = Field(default_factory=dict)

class ScoreResponse(BaseModel):
    score: float
    reasons: List[str]
    dedup_key: str
    suggested_playbook: str
    mitre_techniques: List[str]
    ts: int

def norm(val: float, max_val: float) -> float:
    try:
        v = float(val) / float(max_val)
        return 1.0 if v > 1.0 else (0.0 if v < 0.0 else v)
    except Exception:
        return 0.0

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:16]

def misp_boolean_hit(value: str) -> bool:
    if not (MISP_URL and MISP_API_KEY and value):
        return False
    # Keep it simple & fast for hackathon – treat any 2xx as a hit if 'value' appears in JSON/text.
    import requests
    try:
        headers = {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}
        payload = {"returnFormat":"json","value":value,"type":"ip-dst|ip-src|domain|url|hostname"}
        r = requests.post(f"{MISP_URL}/attributes/restSearch", headers=headers, json=payload, timeout=5)
        if r.status_code // 100 == 2:
            txt = r.text.lower()
            return value.lower() in txt
    except Exception:
        return False
    return False

def compute_score(alert: WazuhAlert) -> ScoreResponse:
    # Extract fields
    sev = alert.rule.get("level", 3)
    host = alert.agent.get("name", "workstation")
    techs = alert.mitre.get("id", []) or []
    srcip = (alert.data or {}).get("srcip") or (alert.data or {}).get("src_ip") or "-"
    burst = alert.recent_similar_count or 0

    # Heuristics
    full = (alert.full_log or "") + " " + json.dumps(alert.data or {})
    heur = 1.0 if POWERSHELL_RE.search(full) else 0.0

    # Threat intel
    if alert.ti_hit is None:
        ti = 1.0 if misp_boolean_hit(srcip) else 0.0
    else:
        ti = 1.0 if alert.ti_hit else 0.0

    # Asset & technique risk
    asset = ASSET_CRIT.get(host, 1)
    techrisk = max([TECH_RISK.get(t, 1) for t in techs] or [1])

    # Weighted score (0..100)
    score = 100 * (
        WEIGHTS["rule_severity"] * norm(sev, SEVERITY_MAX) +
        WEIGHTS["ti_hit"] * ti +
        WEIGHTS["burst"] * norm(burst, BURST_MAX) +
        WEIGHTS["asset"] * norm(asset, 3) +
        WEIGHTS["tech_risk"] * norm(techrisk, 3) +
        WEIGHTS["heuristics"] * heur
    )
    score = round(score, 2)

    # Reasons list
    reasons: List[str] = []
    reasons.append(f"Rule severity={sev}")
    if ti: reasons.append("IOC matched in threat intel")
    if burst: reasons.append(f"Recent alert burst={burst}")
    if asset > 1: reasons.append(f"Critical asset: {host}")
    if techs: reasons.append("MITRE: " + ",".join(techs))
    if heur: reasons.append("Suspicious command line/process")

    dkey = sha1(f"{alert.rule.get('id','-')}|{srcip}|{host}|{','.join(techs)}")

    # Suggest playbook
    suggested = "block_ip" if score >= 75 else "enrich_only"

    return ScoreResponse(
        score=score,
        reasons=[r for r in reasons if r],
        dedup_key=dkey,
        suggested_playbook=suggested,
        mitre_techniques=techs,
        ts=int(time.time())
    )

def should_suppress(dkey: str, new_score: float) -> bool:
    now = time.time()
    exp = SUPPRESS.get(dkey, 0.0)
    if now > exp:
        return False
    # If new score is higher, allow it through
    last = AUDIT_CACHE.get(dkey, {})
    last_score = float(last.get("score", 0.0))
    return new_score <= last_score

def touch_suppress(dkey: str):
    SUPPRESS[dkey] = time.time() + SUPPRESS_MINUTES * 60

def audit_store(resp: ScoreResponse, raw_alert: Dict[str, Any]):
    record = {
        "dedup_key": resp.dedup_key,
        "score": resp.score,
        "reasons": resp.reasons,
        "suggested_playbook": resp.suggested_playbook,
        "mitre_techniques": resp.mitre_techniques,
        "ts": resp.ts,
        "raw": raw_alert,
    }
    AUDIT_CACHE[resp.dedup_key] = record
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass

@app.get("/health")
def health():
    return {"ok": True, "version": app.version}

@app.post("/score")
async def score(req: Request):
    body = await req.json()
    alert = WazuhAlert(**body)
    resp = compute_score(alert)
    # Suppression logic
    if should_suppress(resp.dedup_key, resp.score):
        # Return a suppressed hint (still transparent)
        return {"suppressed": True, "dedup_key": resp.dedup_key, "ts": int(time.time())}
    # Otherwise record & touch TTL
    audit_store(resp, body)
    touch_suppress(resp.dedup_key)
    return resp.dict()

@app.get("/why/{dedup_key}")
def why(dedup_key: str):
    rec = AUDIT_CACHE.get(dedup_key)
    if not rec:
        # optional: fallback to scan the log file for the last occurrence
        try:
            with open(AUDIT_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        j = json.loads(line)
                        if j.get("dedup_key") == dedup_key:
                            rec = j
                    except Exception:
                        continue
        except FileNotFoundError:
            rec = None
    return rec or {"error": "not found"}


@app.get("/")
def root():
    return {"message": "AI Triage is running! Visit /health or /docs"}

@app.get("/metrics")
def metrics():
    total = len(AUDIT_CACHE)
    avg_score = 0
    # If cache empty, read the audit log file instead
    if total == 0 and os.path.exists(AUDIT_LOG):
        import json
        with open(AUDIT_LOG) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        total = len(lines)
        avg_score = round(sum(v["score"] for v in lines) / total, 2) if total else 0
    elif total > 0:
        avg_score = round(sum(v["score"] for v in AUDIT_CACHE.values()) / total, 2)
    return {
        "alerts_scored": total,
        "average_score": avg_score,
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
    }


from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
      <head>
        <title>🛡️ S³ SOC – AI Triage</title>
        <style>
          body {
            background: #0b0c10;
            color: #66fcf1;
            font-family: 'Segoe UI', sans-serif;
            text-align: center;
            padding-top: 120px;
          }
          h1 { font-size: 2.5rem; }
          p  { color: #c5c6c7; }
          a {
            color: #45a29e;
            text-decoration: none;
            border: 1px solid #45a29e;
            padding: 10px 20px;
            border-radius: 10px;
          }
          a:hover { background: #45a29e; color: #0b0c10; }
        </style>
      </head>
      <body>
        <h1>🧠 AI-Driven Security Triage</h1>
        <p>Your FastAPI service is live!</p>
        <a href="/docs">Open API Docs</a>
        <p style="margin-top:40px;">Built by <strong>Team RAGNAROK ⚡</strong></p>
      </body>
    </html>
    """