"""
OriginTrace Dynamic Semgrep Rule Synthesizer
Autonomously synthesizes Semgrep AST/Taint rules from runtime Falco eBPF security telemetry.
"""
import yaml
import os
import re
from typing import Dict, Any, List

class SemgrepRuleSynthesizer:
    def __init__(self, output_dir: str = "security/semgrep/synthesized"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def synthesize_rule_from_correlation(self, correlation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a tailored Semgrep YAML rule based on the correlated AST sink and Falco alert.
        """
        falco_rule = correlation.get("falco_rule", "Runtime Anomaly")
        category = correlation.get("target_category", "command_execution")
        sinks = correlation.get("matched_ast_sinks", [])
        
        sink_name = sinks[0]["sink"] if sinks else "os.system"
        clean_rule_id = "auto-origintrace-" + re.sub(r'[^a-zA-Z0-9]+', '-', falco_rule.lower()).strip('-')

        if category == "command_execution":
            rule_def = {
                "id": clean_rule_id,
                "message": f"OriginTrace Auto-Synthesized Rule: Detected unvalidated invocation of '{sink_name}' triggered in runtime Falco incident: '{falco_rule}'.",
                "severity": "ERROR",
                "languages": ["python"],
                "mode": "taint",
                "pattern-sources": [
                    {"pattern": "request.args.get(...)"},
                    {"pattern": "request.query_params.get(...)"},
                    {"pattern": "request.json(...)"},
                    {"pattern": "$PARAM", "pattern-inside": "def $FUNC(..., $PARAM, ...):\n  ...\n"}
                ],
                "pattern-sinks": [
                    {"pattern": f"{sink_name}(...)"},
                    {"pattern": f"{sink_name}($SINK, ...)"}
                ],
                "metadata": {
                    "cwe": "CWE-78: OS Command Injection",
                    "owasp": "A03:2021 - Injection",
                    "origin": "OriginTrace Runtime-to-Static Synthesis Engine",
                    "falco_source_rule": falco_rule
                }
            }
        elif category == "file_access":
            rule_def = {
                "id": clean_rule_id,
                "message": f"OriginTrace Auto-Synthesized Rule: Detected unvalidated file operation '{sink_name}' mapped to Falco alert '{falco_rule}'.",
                "severity": "WARNING",
                "languages": ["python"],
                "mode": "taint",
                "pattern-sources": [
                    {"pattern": "$PARAM", "pattern-inside": "def $FUNC(..., $PARAM, ...):\n  ...\n"}
                ],
                "pattern-sinks": [
                    {"pattern": f"{sink_name}(...)"}
                ],
                "metadata": {
                    "cwe": "CWE-22: Path Traversal",
                    "owasp": "A01:2021 - Broken Access Control",
                    "origin": "OriginTrace Runtime-to-Static Synthesis Engine",
                    "falco_source_rule": falco_rule
                }
            }
        else:
            rule_def = {
                "id": clean_rule_id,
                "message": f"OriginTrace Auto-Synthesized Rule: Security sink '{sink_name}' flagged by runtime telemetry.",
                "severity": "ERROR",
                "languages": ["python"],
                "patterns": [{"pattern": f"{sink_name}(...)"}],
                "metadata": {
                    "origin": "OriginTrace Runtime-to-Static Synthesis Engine",
                    "falco_source_rule": falco_rule
                }
            }

        rule_yaml_structure = {"rules": [rule_def]}
        output_file = os.path.join(self.output_dir, f"{clean_rule_id}.yml")
        
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(rule_yaml_structure, f, sort_keys=False)

        return {
            "rule_id": clean_rule_id,
            "file_written": output_file,
            "rule_yaml": rule_yaml_structure
        }
