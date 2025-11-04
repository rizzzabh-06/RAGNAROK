from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import os, time, hashlib, json, re

# ────────────────────────────────
# 🧠  FastAPI App Configuration
# ────────────────────────────────
app = FastAPI(
    title="🛡️ S³ SOC – AI Security Automation",
    description="AI-driven scoring & transparency engine built during the 24-hour hackathon.",
    version="1.0.0"
)

TECH_RISK = {"T1059": 3, "T1047": 3, "T1021": 2}
ASSET_CRIT = {"db-prod": 3, "dc01": 3, "workstation": 1}

WEIGHTS = {
    "rule_severity": float(os.getenv("W_RULE", "0.20")),
    "ti_hit": float(os.getenv("W_TI", "0.20")),
    "burst": float(os.getenv("W_BURST", "0.15")),
    "asset": float(os.getenv("W_ASSET", "0.15")),
    "tech_risk": float(os.getenv("W_TECH", "0.15")),
    "heuristics": float(os.getenv("W_HEUR", "0.15")),
}

SUPPRESS_MINUTES = int(os.getenv("SUPPRESS_MINUTES", "10"))
BURST_MAX = int(os.getenv("BURST_MAX", "20"))
SEVERITY_MAX = int(os.getenv("SEVERITY_MAX", "12"))
AUDIT_LOG = os.getenv("AUDIT_LOG", "triage_audit.jsonl")

MISP_URL = os.getenv("MISP_URL", "").rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")

AUDIT_CACHE: Dict[str, Dict[str, Any]] = {}
POWERSHELL_RE = re.compile(r"powershell|pwsh|wmic|rundll32|certutil|-enc|base64", re.I)

# ────────────────────────────────
# 🧩  Models
# ────────────────────────────────
class WazuhAlert(BaseModel):
    rule: Dict[str, Any] = {}
    agent: Dict[str, Any] = {}
    data: Dict[str, Any] = {}
    mitre: Dict[str, Any] = {}
    full_log: Optional[str] = ""
    recent_similar_count: int = 0
    ti_hit: Optional[bool] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

# ────────────────────────────────
# 🔧  Helpers
# ────────────────────────────────
def norm(val: float, max_val: float) -> float:
    try:
        return min(max(float(val) / float(max_val), 0.0), 1.0)
    except Exception:
        return 0.0

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:16]

def misp_boolean_hit(value: str) -> bool:
    if not (MISP_URL and MISP_API_KEY and value):
        return False
    import requests
    try:
        headers = {"Authorization": MISP_API_KEY, "Accept": "application/json"}
        payload = {"returnFormat": "json", "value": value}
        r = requests.post(f"{MISP_URL}/attributes/restSearch", headers=headers, json=payload, timeout=5)
        if r.status_code // 100 == 2:
            return value.lower() in r.text.lower()
    except Exception:
        pass
    return False

# ────────────────────────────────
# 🚀  Core Endpoints
# ────────────────────────────────
@app.get("/health")
def health():
    return {"ok": True, "version": app.version}

@app.post("/score")
async def score(req: Request):
    body = await req.json()
    alert = WazuhAlert(**body)

    sev = alert.rule.get("level", 3)
    host = alert.agent.get("name", "workstation")
    techs = alert.mitre.get("id", []) or []
    srcip = (alert.data or {}).get("srcip") or (alert.data or {}).get("src_ip") or "-"
    burst = alert.recent_similar_count or 0

    heur = 1.0 if POWERSHELL_RE.search((alert.full_log or "") + json.dumps(alert.data or {})) else 0.0
    ti = 1.0 if (alert.ti_hit or misp_boolean_hit(srcip)) else 0.0
    asset = ASSET_CRIT.get(host, 1)
    techrisk = max([TECH_RISK.get(t, 1) for t in techs] or [1])

    score_val = 100 * (
        WEIGHTS["rule_severity"] * norm(sev, SEVERITY_MAX) +
        WEIGHTS["ti_hit"] * ti +
        WEIGHTS["burst"] * norm(burst, BURST_MAX) +
        WEIGHTS["asset"] * norm(asset, 3) +
        WEIGHTS["tech_risk"] * norm(techrisk, 3) +
        WEIGHTS["heuristics"] * heur
    )
    score_val = round(score_val, 2)

    reasons = [f"Rule severity={sev}"]
    if ti: reasons.append("IOC matched in threat intel")
    if burst: reasons.append(f"Recent alert burst={burst}")
    if asset > 1: reasons.append(f"Critical asset: {host}")
    if techs: reasons.append("MITRE: " + ",".join(techs))
    if heur: reasons.append("Suspicious command line/process")

    dkey = sha1(f"{alert.rule.get('id','-')}|{srcip}|{host}|{','.join(techs)}")
    suggested = "block_ip" if score_val >= 75 else "enrich_only"

    record = {
        "dedup_key": dkey,
        "score": score_val,
        "reasons": reasons,
        "suggested_playbook": suggested,
        "mitre_techniques": techs,
        "ts": int(time.time()),
        "raw": body
    }

    # Save to memory + file
    AUDIT_CACHE[dkey] = record
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    # 💬 Colored log
    print(f"\033[96m[AI-SCORE]\033[0m {dkey} → {score_val}%  ({', '.join(reasons)})")

    return {
        "score": score_val,
        "reasons": reasons,
        "dedup_key": dkey,
        "suggested_playbook": suggested,
        "mitre_techniques": techs,
        "ts": int(time.time())
    }

@app.get("/why/{dedup_key}")
def why(dedup_key: str):
    rec = AUDIT_CACHE.get(dedup_key)
    if not rec and os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            for line in f:
                try:
                    j = json.loads(line)
                    if j.get("dedup_key") == dedup_key:
                        rec = j
                except:
                    continue
    return rec or {"error": "not found"}

# ────────────────────────────────
# 📈  Persistent Metrics
# ────────────────────────────────
@app.get("/metrics")
def metrics():
    total = len(AUDIT_CACHE)
    avg_score = 0

    # Fallback to file if cache empty
    if total == 0 and os.path.exists(AUDIT_LOG):
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

# ────────────────────────────────
# 🧾  Startup: Reload Cache from Log
# ────────────────────────────────
@app.on_event("startup")
def load_audit():
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            for line in f:
                try:
                    record = json.loads(line)
                    AUDIT_CACHE[record["dedup_key"]] = record
                except:
                    continue
        print(f"🗃️  Reloaded {len(AUDIT_CACHE)} records from audit log.")

# ────────────────────────────────
# 🎨  Cyber-Styled Landing Page
# ────────────────────────────────
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