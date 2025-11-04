# 🛡️ AI Triage System - Enhanced Integration

## 🚀 What's New

Your existing AI triage system has been enhanced with a **modular architecture** that integrates:

- **Supabase Cloud Database** - Centralized storage with fallback to local files
- **ML Model Support** - Ready for Ayush's trained models with rule-based fallback
- **Modular Components** - Clean separation of concerns for easier debugging
- **Backward Compatibility** - All existing functionality preserved

## 📁 New Structure

```
RAGNAROK/
├── app/                    # New modular components
│   ├── __init__.py
│   ├── main.py            # Enhanced FastAPI app
│   ├── model_utils.py     # ML model logic + existing rules
│   ├── db_utils.py        # Supabase + file fallback
│   └── wazuh_handler.py   # Alert parsing + TI enrichment
├── main.py                # Original (preserved)
├── supabase_schema.sql    # Database schema
├── test_integration.py    # Comprehensive tests
└── .env                   # Configuration
```

## ⚙️ Setup Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Supabase (Optional)
1. Create a Supabase project at https://supabase.com
2. Run the SQL in `supabase_schema.sql` in your Supabase SQL Editor
3. Update `.env` with your Supabase URL and service role key:
```bash
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your-service-role-key
```

### 3. Run the Enhanced System
```bash
# New modular version
uvicorn app.main:app --reload --port 8000

# Or use VSCode debugger (already configured)
```

### 4. Test Everything
```bash
python test_integration.py
```

## 🔄 Migration Strategy

**Zero Downtime Migration:**
- Your original `main.py` is preserved and functional
- New modular system runs on `app.main:app`
- Both systems share the same audit log file
- Gradual migration possible

## 🧠 ML Model Integration

Drop your trained `model.pkl` in the root directory:
```python
# The system will automatically:
# 1. Try to load model.pkl
# 2. Use ML predictions if available
# 3. Fallback to existing rule-based scoring
```

## 🗄️ Data Storage

**Triple Redundancy:**
1. **Supabase** - Primary cloud storage (if configured)
2. **File Cache** - Local JSONL file (always active)
3. **Memory Cache** - Fast in-memory lookup

## 🔍 Key Features Preserved

✅ All existing scoring logic  
✅ MITRE technique mapping  
✅ Asset criticality scoring  
✅ Threat intelligence integration  
✅ Deduplication logic  
✅ Audit trail  
✅ `/why/{dedup_key}` explanations  
✅ Colored console output  

## 🆕 New Features Added

🆕 Supabase cloud database integration  
🆕 ML model support with fallback  
🆕 Modular architecture  
🆕 Enhanced health checks  
🆕 Multi-source data retrieval  
🆕 Comprehensive test suite  
🆕 Better error handling  

## 🎯 API Endpoints

All existing endpoints work exactly the same:

- `GET /` - Enhanced landing page with system status
- `POST /score` - Score alerts (enhanced with Supabase)
- `GET /why/{dedup_key}` - Explain scoring (multi-source)
- `GET /metrics` - System metrics (enhanced)
- `GET /health` - Health check (enhanced)

## 🧪 Testing

```bash
# Test the new system
python test_integration.py

# Test with curl (same as before)
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {"id": "61003", "level": 8},
    "agent": {"name": "HR-LAPTOP01"},
    "data": {"srcip": "10.0.2.15", "cmd": "powershell -enc AAA"},
    "mitre": {"id": ["T1059"]},
    "recent_similar_count": 3,
    "ti_hit": true
  }'
```

## 🔧 Configuration

All existing environment variables work + new ones:

```bash
# New Supabase config
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-service-role-key
SCORE_THRESHOLD=75

# Existing config (preserved)
W_RULE=0.20
W_TI=0.20
# ... all others preserved
```

## 🚨 Troubleshooting

**Supabase not working?**
- System automatically falls back to file-based storage
- Check `.env` configuration
- Verify Supabase project is active

**ML model not loading?**
- System falls back to existing rule-based scoring
- Check `model.pkl` exists in root directory
- Verify scikit-learn compatibility

**Import errors?**
- Run `pip install -r requirements.txt`
- Check Python path includes the project root

## 🎉 Ready for Demo

Your system is now:
- ✅ **Production Ready** - Multiple fallback layers
- ✅ **Scalable** - Cloud database integration
- ✅ **Maintainable** - Modular architecture
- ✅ **Debuggable** - Clear separation of concerns
- ✅ **Demo Ready** - Enhanced UI and comprehensive tests

**Team RAGNAROK ⚡ - Enhanced and Ready to Win!**