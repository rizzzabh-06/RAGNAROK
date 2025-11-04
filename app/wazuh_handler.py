import hashlib
import requests
import os
from datetime import datetime
from typing import Dict, Any, Optional

def sha1(s: str) -> str:
    """Generate SHA1 hash for deduplication"""
    return hashlib.sha1(s.encode()).hexdigest()[:16]

def parse_wazuh_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Parse and normalize Wazuh alert (preserved from existing system)"""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    mitre = alert.get("mitre", {})
    
    # Generate dedup key (preserved logic)
    srcip = data.get("srcip") or data.get("src_ip") or "-"
    host = agent.get("name", "workstation")
    techs = mitre.get("id", []) or []
    
    dedup_key = sha1(f"{rule.get('id','-')}|{srcip}|{host}|{','.join(techs)}")
    
    parsed = {
        "rule_id": rule.get("id"),
        "description": rule.get("description"),
        "severity": rule.get("level", 1),
        "agent_name": host,
        "srcip": srcip,
        "cmd": data.get("cmd", ""),
        "mitre_techniques": techs,
        "dedup_key": dedup_key,
        "timestamp": datetime.utcnow().isoformat(),
        "full_log": alert.get("full_log", ""),
        "recent_similar_count": alert.get("recent_similar_count", 0),
        "ti_hit": alert.get("ti_hit")
    }
    return parsed

def misp_boolean_hit(value: str) -> bool:
    """Check MISP for IOC hit (preserved from existing system)"""
    misp_url = os.getenv("MISP_URL", "").rstrip("/")
    misp_api_key = os.getenv("MISP_API_KEY", "")
    
    if not (misp_url and misp_api_key and value):
        return False
        
    try:
        headers = {"Authorization": misp_api_key, "Accept": "application/json"}
        payload = {"returnFormat": "json", "value": value}
        r = requests.post(f"{misp_url}/attributes/restSearch", 
                         headers=headers, json=payload, timeout=5)
        if r.status_code // 100 == 2:
            return value.lower() in r.text.lower()
    except Exception:
        pass
    return False

def enrich_alert_with_ti(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich alert with threat intelligence"""
    data = alert.get("data", {})
    srcip = data.get("srcip") or data.get("src_ip")
    
    if srcip and not alert.get("ti_hit"):
        alert["ti_hit"] = misp_boolean_hit(srcip)
    
    return alert

def validate_alert_structure(alert: Dict[str, Any]) -> bool:
    """Validate that alert has minimum required structure"""
    required_fields = ["rule"]
    return all(field in alert for field in required_fields)