import unittest
import os
import sys

# Ensure package is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from origintrace_core.correlator import SyscallCorrelator
from origintrace_core.synthesizer import SemgrepRuleSynthesizer
from origintrace_core.reachability import ExploitReachabilityEngine

class TestOriginTraceCore(unittest.TestCase):
    def setUp(self):
        self.workspace = os.path.dirname(os.path.dirname(__file__))

    def test_ast_visitor_detects_command_execution(self):
        correlator = SyscallCorrelator(self.workspace)
        live_telemetry_record = {
            "rule": "Terminal Shell Spawned in Production Container",
            "output": "Interactive shell spawned in container cmdline=ping -c 1 127.0.0.1; id",
            "output_fields": {"proc.cmdline": "ping -c 1 127.0.0.1; id"}
        }
        
        result = correlator.correlate_falco_alert(live_telemetry_record)
        self.assertEqual(result["correlation_confidence"], "HIGH")
        self.assertGreater(len(result["matched_ast_sinks"]), 0)
        
        sinks = [s["sink"] for s in result["matched_ast_sinks"]]
        self.assertIn("os.system", sinks)

    def test_semgrep_rule_synthesis(self):
        synthesizer = SemgrepRuleSynthesizer(output_dir=".test_rules")
        correlation = {
            "falco_rule": "Terminal Shell Spawned in Production Container",
            "target_category": "command_execution",
            "matched_ast_sinks": [{"sink": "os.system", "line": 36, "file": "sample_workload/app.py"}]
        }
        
        res = synthesizer.synthesize_rule_from_correlation(correlation)
        self.assertTrue(res["rule_id"].startswith("auto-origintrace"))
        self.assertTrue(os.path.exists(res["file_written"]))
        
        # Cleanup
        if os.path.exists(res["file_written"]):
            os.remove(res["file_written"])

    def test_exploit_reachability_scoring(self):
        engine = ExploitReachabilityEngine()
        static_finding = {"sink": "os.system", "file": "sample_workload/app.py", "line": 36}
        runtime_events = [{
            "rule": "Terminal Shell Spawned in Production Container",
            "output_fields": {"proc.cmdline": "ping -c 1 127.0.0.1; whoami"}
        }]
        
        reachability = engine.calculate_reachability(static_finding, runtime_events)
        self.assertGreaterEqual(reachability["reachability_score"], 75)
        self.assertEqual(reachability["verdict"], "CONFIRMED_EXPLOITABLE")
        self.assertTrue(reachability["requires_immediate_hotfix"])

if __name__ == "__main__":
    unittest.main()
