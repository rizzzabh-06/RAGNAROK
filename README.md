# AI Triage Service (Mac‑1)

This is your workstation’s service. It accepts Wazuh‑style alerts and returns a score (0–100) with a human‑readable explanation and a suggested playbook. It also provides `/why/<dedup_key>` so analysts (and judges) can see **why** an alert was prioritized.

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# run
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Test with a sample alert
```bash
curl -s -X POST http://localhost:8000/score -H 'content-type: application/json' -d '{
  "rule": {"id":"1001","level":10},
  "agent": {"name":"dc01"},
  "data": {"srcip":"1.2.3.4", "cmd": "powershell -enc AAA"},
  "mitre": {"id":["T1059"]},
  "full_log": "powershell.exe -enc ...",
  "recent_similar_count": 7,
  "ti_hit": true
}' | jq .
```

## Environment variables (optional)
- `W_RULE`, `W_TI`, `W_BURST`, `W_ASSET`, `W_TECH`, `W_HEUR` – override weights (default sum ≈ 1.0).
- `SUPPRESS_MINUTES` – dedup suppression window (default 10).
- `SEVERITY_MAX` – normalization cap for rule severity (default 12).
- `BURST_MAX` – normalization cap for burst count (default 20).
- `AUDIT_LOG` – path to JSONL audit log (default `triage_audit.jsonl`).
- `MISP_URL`, `MISP_API_KEY` – if set, the service will try a boolean IOC hit lookup using `data.srcip`.
  (Keep this lightweight for hackathon; you can expand to domains, hashes later.)

## Notes
- If the same `dedup_key` repeats inside the suppression window, a lower or equal score will be **suppressed** (returned with `{"suppressed": true}`) to reduce noise. If the new score is higher, it is allowed through.
- All scored alerts are written to the audit log and the in‑memory cache, which backs `/why/<dedup_key>`.

## Next steps
- Expose the service to the Windows “infra node” so Wazuh (or a poller) can hit `/score`.
- Coordinate field names with Windows teammates (e.g., provide `recent_similar_count`) so features are populated.
- If MISP is up, export `MISP_URL` and `MISP_API_KEY` and confirm you get `IOC matched in threat intel` in reasons.
