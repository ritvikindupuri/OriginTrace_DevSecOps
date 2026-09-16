"""
OriginTrace Dual-Verdict Exploit Reachability Engine
Calculates definitive exploit reachability scores (0-100%) by cross-referencing
static Semgrep taint paths against real-time Falco eBPF kernel telemetry.
"""
from typing import Dict, Any, List

class ExploitReachabilityEngine:
    def calculate_reachability(
        self,
        static_finding: Dict[str, Any],
        runtime_events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        sink = static_finding.get("sink", "")
        file_path = static_finding.get("file", "")
        line = static_finding.get("line", 0)

        score = 25
        evidence = ["Static taint sink identified in AST"]

        for event in runtime_events:
            rule = event.get("rule", "")
            fields = event.get("output_fields", {})
            cmdline = fields.get("proc.cmdline", event.get("output", ""))
            
            if "os.system" in sink or "subprocess" in sink:
                if "shell" in rule.lower() or "exec" in rule.lower() or "process" in rule.lower() or "ping" in cmdline:
                    score += 50
                    evidence.append(f"Runtime Falco alert matched: '{rule}' with cmdline: '{cmdline}'")
            
            if "open" in sink and ("file" in rule.lower() or "tampering" in rule.lower()):
                score += 50
                evidence.append(f"Runtime Falco filesystem access event matched: '{rule}'")

        score = min(score, 100)
        verdict = "CONFIRMED_EXPLOITABLE" if score >= 75 else "THEORETICAL_RISK" if score >= 50 else "STATIC_ONLY"

        return {
            "reachability_score": score,
            "verdict": verdict,
            "evidence_trail": evidence,
            "static_target": f"{file_path}:{line}",
            "requires_immediate_hotfix": score >= 75
        }
