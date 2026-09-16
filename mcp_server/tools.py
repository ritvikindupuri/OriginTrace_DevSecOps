"""
OriginTrace MCP Tool Implementations
Exposes high-level security correlation tools to AI Coding Agents via standard JSON-RPC.
"""
from typing import Dict, Any, List, Optional
import os
import json
from origintrace_core.receiver import incident_store
from origintrace_core.correlator import SyscallCorrelator
from origintrace_core.synthesizer import SemgrepRuleSynthesizer
from origintrace_core.reachability import ExploitReachabilityEngine

def tool_query_runtime_incidents(limit: int = 10) -> Dict[str, Any]:
    incidents = incident_store.list_incidents()[:limit]
    return {
        "count": len(incidents),
        "incidents": incidents
    }

def tool_correlate_incident_to_code(incident_id: str, workspace_path: Optional[str] = None) -> Dict[str, Any]:
    incidents = [inc for inc in incident_store.incidents if inc.get("incident_id") == incident_id]
    if not incidents:
        return {"error": f"Incident {incident_id} not found in store"}
    
    alert = incidents[0]
    correlator = SyscallCorrelator(workspace_path or os.getcwd())
    correlation_result = correlator.correlate_falco_alert(alert)
    
    reachability_engine = ExploitReachabilityEngine()
    reachability = {}
    if correlation_result["matched_ast_sinks"]:
        reachability = reachability_engine.calculate_reachability(
            correlation_result["matched_ast_sinks"][0],
            [alert]
        )

    return {
        "incident_id": incident_id,
        "falco_rule": alert.get("rule"),
        "priority": alert.get("priority"),
        "correlation": correlation_result,
        "reachability_verdict": reachability
    }

def tool_synthesize_semgrep_rule(incident_id: str) -> Dict[str, Any]:
    correlation_data = tool_correlate_incident_to_code(incident_id)
    if "error" in correlation_data:
        return correlation_data
    
    synthesizer = SemgrepRuleSynthesizer()
    res = synthesizer.synthesize_rule_from_correlation(correlation_data["correlation"])
    return {
        "status": "synthesized",
        "rule_id": res["rule_id"],
        "file_path": res["file_written"],
        "yaml_content": res["rule_yaml"]
    }
