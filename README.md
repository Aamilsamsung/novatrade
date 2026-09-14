# NovaTrade

A mobile-friendly paper-trading dashboard and demo trading engine.

## Render

This project is configured as a single Python web service. Render runs:

```bash
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

Open the service URL and the dashboard will use same-origin API calls.

**Important:** this demo is paper trading only. It does not connect to a broker or place real-money orders.
