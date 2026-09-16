#!/usr/bin/env python3
"""
OriginTrace Developer & SecOps CLI
Inspect live correlated incidents, export SARIF reports, and trigger synthesis.
"""
import sys
import os
import argparse
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from origintrace_core.receiver import incident_store
from origintrace_core.correlator import SyscallCorrelator
from origintrace_core.synthesizer import SemgrepRuleSynthesizer

def main():
    parser = argparse.ArgumentParser(
        description="OriginTrace CLI: Shift-Left <-> Runtime Threat Intelligence Bridge"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    list_p = subparsers.add_parser("list", help="List recent runtime Falco eBPF incidents")
    list_p.add_argument("--limit", type=int, default=10, help="Number of records to show")

    corr_p = subparsers.add_parser("correlate", help="Correlate a Falco alert JSON file into codebase AST")
    corr_p.add_argument("alert_file", type=str, help="Path to Falco alert JSON file")

    syn_p = subparsers.add_parser("synthesize", help="Synthesize a Semgrep Taint rule from correlation")
    syn_p.add_argument("alert_file", type=str, help="Path to Falco alert JSON file")

    args = parser.parse_args()

    if args.command == "list":
        incidents = incident_store.list_incidents()[:args.limit]
        print(json.dumps({"total": len(incidents), "incidents": incidents}, indent=2))

    elif args.command in ("correlate", "synthesize"):
        if not os.path.exists(args.alert_file):
            print(f"Error: file '{args.alert_file}' not found.")
            sys.exit(1)
        with open(args.alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)

        correlator = SyscallCorrelator(os.getcwd())
        correlation = correlator.correlate_falco_alert(alert)

        if args.command == "correlate":
            print(json.dumps(correlation, indent=2))
        elif args.command == "synthesize":
            synthesizer = SemgrepRuleSynthesizer()
            res = synthesizer.synthesize_rule_from_correlation(correlation)
            print(json.dumps(res, indent=2))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
