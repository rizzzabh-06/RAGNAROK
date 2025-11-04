from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import os, time, json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import modular components
from app.model_utils import load_model, predict_score, explain_score
from app.db_utils import get_db, insert_alert, insert_score, insert_audit, save_to_file, load_from_file, find_in_file
from app.wazuh_handler import parse_wazuh_alert, enrich_alert_with_ti, validate_alert_structure

# ────────────────────────────────
# 🧠  FastAPI App Configuration
# ────────────────────────────────
app = FastAPI(
    title="🛡️ S³ SOC – AI Security Automation",
    description="AI-driven scoring & transparency engine with modular architecture.",
    version="2.0.0"
)

# Configuration
SCORE_THRESHOLD = int(os.getenv("SCORE_THRESHOLD", "75"))
AUDIT_LOG = os.getenv("AUDIT_LOG", "triage_audit.jsonl")

# Initialize components
supabase = get_db()
model = load_model("model.pkl")
AUDIT_CACHE: Dict[str, Dict[str, Any]] = {}

# ────────────────────────────────
# 🧩  Models (preserved)
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
# 🚀  Core Endpoints
# ────────────────────────────────
@app.get("/health")
def health():
    return {
        "ok": True, 
        "version": app.version,
        "supabase_connected": supabase is not None,
        "model_loaded": model is not None
    }

@app.post("/score")
async def score_alert(req: Request):
    """Enhanced scoring endpoint with modular architecture"""
    body = await req.json()
    
    # Validate alert structure
    if not validate_alert_structure(body):
        return {"error": "Invalid alert structure"}
    
    # Parse and enrich alert
    alert = WazuhAlert(**body)
    alert_dict = alert.dict()
    alert_dict = enrich_alert_with_ti(alert_dict)
    
    # Parse for database storage
    parsed = parse_wazuh_alert(alert_dict)
    
    # Predict score using modular system
    score_val, reasons = predict_score(model, alert_dict)
    explanation = explain_score(alert_dict)
    
    # Determine suggested playbook
    suggested = "block_ip" if score_val >= SCORE_THRESHOLD else "enrich_only"
    
    # Prepare records
    alert_record = parsed.copy()
    score_record = {
        "score": score_val,
        "dedup_key": parsed["dedup_key"],
        "recommended_playbook": suggested,
        "reasons": json.dumps(reasons),
        "timestamp": parsed["timestamp"]
    }
    
    audit_record = {
        "dedup_key": parsed["dedup_key"],
        "score": score_val,
        "reasons": reasons,
        "suggested_playbook": suggested,
        "mitre_techniques": parsed["mitre_techniques"],
        "ts": int(time.time()),
        "raw": body,
        "explanation": explanation
    }
    
    # Store in Supabase if available
    if supabase:
        alert_row = insert_alert(supabase, alert_record)
        if alert_row:
            score_record["alert_id"] = alert_row["id"]
        insert_score(supabase, score_record)
        insert_audit(supabase, audit_record)
    
    # Always store in file and cache (fallback + performance)
    AUDIT_CACHE[parsed["dedup_key"]] = audit_record
    save_to_file(audit_record, AUDIT_LOG)
    
    # Colored log (preserved)
    print(f"\\033[96m[AI-SCORE]\\033[0m {parsed['dedup_key']} → {score_val}%  ({', '.join(reasons)})")
    
    return {
        "score": score_val,
        "reasons": reasons,
        "dedup_key": parsed["dedup_key"],
        "suggested_playbook": suggested,
        "mitre_techniques": parsed["mitre_techniques"],
        "ts": int(time.time())
    }

@app.get("/why/{dedup_key}")
def get_why(dedup_key: str):
    """Enhanced explanation endpoint with multiple data sources"""
    # Check cache first
    rec = AUDIT_CACHE.get(dedup_key)
    
    # Check Supabase if available
    if not rec and supabase:
        supabase_data = get_audit(supabase, dedup_key)
        if supabase_data:
            rec = supabase_data[0]
    
    # Fallback to file
    if not rec:
        rec = find_in_file(dedup_key, AUDIT_LOG)
    
    return rec or {"error": "not found"}

# ────────────────────────────────
# 📈  Enhanced Metrics
# ────────────────────────────────
@app.get("/metrics")
def metrics():
    """Enhanced metrics with multiple data sources"""
    total = len(AUDIT_CACHE)
    avg_score = 0
    
    # Use cache if available
    if total > 0:
        avg_score = round(sum(v["score"] for v in AUDIT_CACHE.values()) / total, 2)
    else:
        # Fallback to file
        cache = load_from_file(AUDIT_LOG)
        total = len(cache)
        if total > 0:
            avg_score = round(sum(v["score"] for v in cache.values()) / total, 2)
    
    return {
        "alerts_scored": total,
        "average_score": avg_score,
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "data_sources": {
            "supabase": supabase is not None,
            "file_cache": os.path.exists(AUDIT_LOG),
            "memory_cache": len(AUDIT_CACHE) > 0
        }
    }

# ────────────────────────────────
# 🧾  Enhanced Startup
# ────────────────────────────────
@app.on_event("startup")
def load_audit():
    """Load existing audit data on startup"""
    global AUDIT_CACHE
    AUDIT_CACHE = load_from_file(AUDIT_LOG)
    print(f"🗃️  Reloaded {len(AUDIT_CACHE)} records from audit log.")
    
    if supabase:
        print("✅ Supabase connection established.")
    else:
        print("⚠️  Supabase not configured, using file-based storage.")
    
    if model:
        print("✅ ML model loaded successfully.")
    else:
        print("⚠️  No ML model found, using rule-based scoring.")

# ────────────────────────────────
# 🎨  Enhanced Landing Page
# ────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home():
    return f"""
    <html>
      <head>
        <title>🛡️ S³ SOC – AI Triage v2.0</title>
        <style>
          body {{
            background: #0b0c10;
            color: #66fcf1;
            font-family: 'Segoe UI', sans-serif;
            text-align: center;
            padding-top: 80px;
          }}
          h1 {{ font-size: 2.5rem; }}
          p  {{ color: #c5c6c7; }}
          .status {{ 
            background: #1f2833; 
            padding: 20px; 
            margin: 20px auto; 
            width: 600px; 
            border-radius: 10px; 
          }}
          .green {{ color: #66fcf1; }}
          .yellow {{ color: #ffd700; }}
          a {{
            color: #45a29e;
            text-decoration: none;
            border: 1px solid #45a29e;
            padding: 10px 20px;
            border-radius: 10px;
            margin: 10px;
            display: inline-block;
          }}
          a:hover {{ background: #45a29e; color: #0b0c10; }}
        </style>
      </head>
      <body>
        <h1>🧠 AI-Driven Security Triage v2.0</h1>
        <p>Enhanced modular architecture with Supabase integration</p>
        
        <div class="status">
          <h3>System Status</h3>
          <p class="{'green' if supabase else 'yellow'}">
            Supabase: {'✅ Connected' if supabase else '⚠️ File-based fallback'}
          </p>
          <p class="{'green' if model else 'yellow'}">
            ML Model: {'✅ Loaded' if model else '⚠️ Rule-based scoring'}
          </p>
          <p class="green">Cache: ✅ {len(AUDIT_CACHE)} records loaded</p>
        </div>
        
        <a href="/docs">API Documentation</a>
        <a href="/metrics">System Metrics</a>
        
        <p style="margin-top:40px;">Built by <strong>Team RAGNAROK ⚡</strong></p>
        <p style="font-size:0.8em;">Modular Architecture | Supabase Integration | ML Ready</p>
      </body>
    </html>
    """