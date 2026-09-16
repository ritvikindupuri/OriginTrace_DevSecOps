"""
Sample Production Workload: Enterprise Data Gateway
Contains realistic endpoints:
- /api/v1/healthz (Safe healthcheck)
- /api/v1/query (Safe parameterized query)
- /api/v1/diagnostics/ping (Vulnerable unvalidated diagnostic endpoint triggering Falco)
"""
from fastapi import FastAPI, HTTPException, Request, Query
import os
import subprocess
import sqlite3

app = FastAPI(title="Enterprise Data Gateway", version="1.0.0")

@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "data-gateway"}

@app.get("/api/v1/query")
def safe_query(item_id: int = Query(..., ge=1)):
    """Safe parameterized database query."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS items (id INT, val TEXT)")
    cursor.execute("SELECT val FROM items WHERE id = ?", (item_id,))
    return {"result": cursor.fetchall()}

@app.get("/api/v1/diagnostics/ping")
def diagnostic_ping(host: str):
    """
    Diagnostic Ping Endpoint:
    Vulnerable to OS Command Injection via dynamic subprocess / shell invocation.
    This sink triggers both Falco eBPF kernel execve alert and AegisLoop correlation.
    """
    # Vulnerable sink (Line 34)
    result = os.system(f"ping -c 1 {host}")
    return {"exit_code": result, "host": host}
