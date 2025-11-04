#!/usr/bin/env python3
"""
Test script for the integrated AI triage system
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    print("🔍 Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    else:
        print(f"Error: {response.text}")
    print()

def test_score_alert():
    """Test scoring endpoint with sample alert"""
    print("🔍 Testing score endpoint...")
    
    sample_alert = {
        "rule": {
            "id": "61003",
            "description": "Suspicious PowerShell execution",
            "level": 8
        },
        "agent": {
            "name": "HR-LAPTOP01"
        },
        "data": {
            "srcip": "10.0.2.15",
            "cmd": "powershell -enc SQBuAHYAbwBrAGUALQBDAG8AbQBtAGEAbgBkACAALQBDAG8AbQBwAHUAdABlAHIATgBhAG0AZQA="
        },
        "mitre": {
            "id": ["T1059", "T1047"]
        },
        "full_log": "powershell.exe -enc SQBuAHYAbwBrAGUALQBDAG8AbQBtAGEAbgBkACAALQBDAG8AbQBwAHUAdABlAHIATgBhAG0AZQA=",
        "recent_similar_count": 3,
        "ti_hit": True
    }
    
    response = requests.post(
        f"{BASE_URL}/score",
        headers={"Content-Type": "application/json"},
        json=sample_alert
    )
    
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test why endpoint
    if "dedup_key" in result:
        print(f"\n🔍 Testing why endpoint for {result['dedup_key']}...")
        why_response = requests.get(f"{BASE_URL}/why/{result['dedup_key']}")
        print(f"Why Status: {why_response.status_code}")
        print(f"Why Response: {json.dumps(why_response.json(), indent=2)}")
    
    print()

def test_metrics():
    """Test metrics endpoint"""
    print("🔍 Testing metrics endpoint...")
    response = requests.get(f"{BASE_URL}/metrics")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print()

def test_multiple_alerts():
    """Test with multiple different alerts"""
    print("🔍 Testing multiple alerts...")
    
    alerts = [
        {
            "rule": {"id": "5716", "description": "SSHD authentication success", "level": 3},
            "agent": {"name": "web-server-01"},
            "data": {"srcip": "192.168.1.100"},
            "mitre": {"id": []},
            "recent_similar_count": 0
        },
        {
            "rule": {"id": "40111", "description": "Multiple failed logins", "level": 10},
            "agent": {"name": "dc01"},
            "data": {"srcip": "1.2.3.4", "cmd": "net user administrator /add"},
            "mitre": {"id": ["T1078"]},
            "recent_similar_count": 15,
            "ti_hit": True
        },
        {
            "rule": {"id": "92000", "description": "Wazuh agent stopped", "level": 5},
            "agent": {"name": "workstation-05"},
            "data": {},
            "mitre": {"id": []},
            "recent_similar_count": 1
        }
    ]
    
    for i, alert in enumerate(alerts, 1):
        print(f"Alert {i}:")
        response = requests.post(
            f"{BASE_URL}/score",
            headers={"Content-Type": "application/json"},
            json=alert
        )
        result = response.json()
        print(f"  Score: {result.get('score', 'N/A')}%")
        print(f"  Playbook: {result.get('suggested_playbook', 'N/A')}")
        print(f"  Reasons: {', '.join(result.get('reasons', []))}")
        time.sleep(0.5)
    
    print()

if __name__ == "__main__":
    print("🚀 Starting AI Triage System Integration Tests")
    print("=" * 50)
    
    try:
        test_health()
        test_score_alert()
        test_multiple_alerts()
        test_metrics()
        
        print("✅ All tests completed successfully!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed. Make sure the server is running:")
        print("   uvicorn app.main:app --reload --port 8000")
    except Exception as e:
        print(f"❌ Test failed: {e}")