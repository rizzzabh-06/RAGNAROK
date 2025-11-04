import os
import json
import time
from typing import Dict, Any, Optional
from supabase import create_client, Client

def get_db() -> Optional[Client]:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    
    if not url or not key or "YOUR_PROJECT_ID" in url:
        return None
        
    try:
        supabase = create_client(url, key)
        # Test connection
        supabase.table("alerts").select("id").limit(1).execute()
        print("Supabase connected successfully")
        return supabase
    except Exception as e:
        print(f"Supabase connection failed: {e}")
        print("Tip: Use service_role key for RLS-enabled tables")
        return None

def insert_alert(supabase: Optional[Client], alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Insert alert into Supabase if available"""
    if not supabase:
        return None
        
    try:
        res = supabase.table("alerts").insert(alert_data).execute()
        return res.data[0] if res.data else None
    except Exception as e:
        print(f"⚠️ Failed to insert alert: {e}")
        return None

def insert_score(supabase: Optional[Client], score_data: Dict[str, Any]) -> bool:
    """Insert score into Supabase if available"""
    if not supabase:
        return False
        
    try:
        supabase.table("scores").insert(score_data).execute()
        return True
    except Exception as e:
        print(f"⚠️ Failed to insert score: {e}")
        return False

def insert_audit(supabase: Optional[Client], audit_data: Dict[str, Any]) -> bool:
    """Insert audit log into Supabase if available"""
    if not supabase:
        return False
        
    try:
        supabase.table("audit_logs").insert(audit_data).execute()
        return True
    except Exception as e:
        print(f"⚠️ Failed to insert audit: {e}")
        return False

def get_audit(supabase: Optional[Client], dedup_key: str) -> list:
    """Get audit logs from Supabase if available"""
    if not supabase:
        return []
        
    try:
        res = supabase.table("audit_logs").select("*").eq("dedup_key", dedup_key).execute()
        return res.data or []
    except Exception as e:
        print(f"⚠️ Failed to get audit: {e}")
        return []

# Fallback file-based storage (preserved from existing system)
def save_to_file(record: Dict[str, Any], audit_log: str = "triage_audit.jsonl"):
    """Save record to JSONL file as fallback"""
    try:
        with open(audit_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        print(f"⚠️ Failed to save to file: {e}")

def load_from_file(audit_log: str = "triage_audit.jsonl") -> Dict[str, Dict[str, Any]]:
    """Load records from JSONL file"""
    cache = {}
    if os.path.exists(audit_log):
        try:
            with open(audit_log) as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        if "dedup_key" in record:
                            cache[record["dedup_key"]] = record
                    except:
                        continue
        except Exception as e:
            print(f"⚠️ Failed to load from file: {e}")
    return cache

def find_in_file(dedup_key: str, audit_log: str = "triage_audit.jsonl") -> Optional[Dict[str, Any]]:
    """Find specific record in JSONL file"""
    if not os.path.exists(audit_log):
        return None
        
    try:
        with open(audit_log) as f:
            for line in f:
                try:
                    record = json.loads(line)
                    if record.get("dedup_key") == dedup_key:
                        return record
                except:
                    continue
    except Exception as e:
        print(f"⚠️ Failed to search file: {e}")
    return None