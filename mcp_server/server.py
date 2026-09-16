"""
AegisLoop FastMCP / JSON-RPC Server
Enables AI coding assistants to invoke AegisLoop security tools directly via stdio.
"""
import sys
import json
import os

# Ensure package root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, Any
from mcp_server.tools import (
    tool_query_runtime_incidents,
    tool_correlate_incident_to_code,
    tool_synthesize_semgrep_rule
)

TOOLS = {
    "query_runtime_incidents": {
        "description": "Lists recent runtime Falco eBPF security incidents and alerts.",
        "handler": tool_query_runtime_incidents
    },
    "correlate_incident_to_code": {
        "description": "Maps a runtime Falco alert ID to the source code file, function, and AST sink line.",
        "handler": tool_correlate_incident_to_code
    },
    "synthesize_semgrep_rule": {
        "description": "Autonomously synthesizes a Semgrep YAML taint rule from a runtime incident.",
        "handler": tool_synthesize_semgrep_rule
    }
}

def handle_request(line: str):
    try:
        req = json.loads(line)
        method = req.get("method")
        req_id = req.get("id")
        
        if method == "tools/list":
            tools_list = [
                {"name": k, "description": v["description"]}
                for k, v in TOOLS.items()
            ]
            response = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}}
        elif method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {})
            if tool_name in TOOLS:
                result = TOOLS[tool_name]["handler"](**args)
                response = {"jsonrpc": "2.0", "id": req_id, "result": result}
            else:
                response = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Tool not found"}}
        else:
            response = {"jsonrpc": "2.0", "id": req_id, "result": {}}

        print(json.dumps(response), flush=True)
    except Exception as e:
        err_res = {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}
        print(json.dumps(err_res), flush=True)

def run_stdio_server():
    for line in sys.stdin:
        if line.strip():
            handle_request(line.strip())

if __name__ == "__main__":
    run_stdio_server()
