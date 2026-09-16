import json
import requests
import os

KIBANA_URL = "http://localhost:5601"
HEADERS = {"kbn-xsrf": "true"}

def build_saved_objects():
    objects = []
    
    # 1. Data View (Index Pattern)
    data_view = {
        "type": "data-view",
        "id": "origintrace-data-view",
        "attributes": {
            "title": "origintrace-events-*",
            "name": "OriginTrace Live Events",
            "timeFieldName": "@timestamp"
        }
    }
    objects.append(data_view)
    
    # 2. Donut Visualization for Reachability
    donut_vis = {
        "type": "visualization",
        "id": "origintrace-reachability-donut",
        "attributes": {
            "title": "[OriginTrace] Dual-Verdict Exploit Reachability",
            "description": "Percentage of vulnerabilities with active kernel syscall verification vs static-only findings",
            "visState": json.dumps({
                "title": "[OriginTrace] Dual-Verdict Exploit Reachability",
                "type": "pie",
                "params": {
                    "type": "pie",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": True
                },
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                        "field": "origintrace.reachability_verdict",
                        "size": 5,
                        "order": "desc",
                        "orderBy": "1"
                    }}
                ]
            }),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "data-view",
                "id": "origintrace-data-view"
            }
        ]
    }
    objects.append(donut_vis)
    
    # 3. Bar Chart for Severity Breakdown
    bar_vis = {
        "type": "visualization",
        "id": "origintrace-threat-priority-bar",
        "attributes": {
            "title": "[OriginTrace] Runtime Threats by Severity",
            "description": "Distribution of real Falco runtime alerts by priority level",
            "visState": json.dumps({
                "title": "[OriginTrace] Runtime Threats by Severity",
                "type": "histogram",
                "params": {
                    "type": "histogram",
                    "grid": {"categoryLines": False},
                    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {}}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "style": {}}]
                },
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                        "field": "falco.priority",
                        "size": 5,
                        "order": "desc",
                        "orderBy": "1"
                    }}
                ]
            }),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "data-view",
                "id": "origintrace-data-view"
            }
        ]
    }
    objects.append(bar_vis)

    # 4. Search Object (Saved Search / Table)
    search_obj = {
        "type": "search",
        "id": "origintrace-detailed-audit-table",
        "attributes": {
            "title": "[OriginTrace] Live Kernel Syscall to Source Code Origin Audit Stream",
            "description": "Detailed forensic audit stream linking runtime kernel executions directly to repository files, functions, lines, and reachability scores",
            "columns": [
                "@timestamp",
                "falco.priority",
                "falco.rule",
                "process.cmdline",
                "kubernetes.pod_name",
                "origintrace.source_origin.file",
                "origintrace.source_origin.function",
                "origintrace.source_origin.line",
                "origintrace.source_origin.sink",
                "origintrace.reachability_verdict"
            ],
            "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "data-view",
                "id": "origintrace-data-view"
            }
        ]
    }
    objects.append(search_obj)
    
    # 5. Dashboard Object
    dashboard_obj = {
        "type": "dashboard",
        "id": "origintrace-kibana-overview",
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
                    "gridData": {"x": 0, "y": 14, "w": 48, "h": 22, "i": "3"},
                    "panelIndex": "3",
                    "embeddableConfig": {},
                    "panelRefName": "panel_3"
                }
            ]),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
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
                "id": "origintrace-threat-priority-bar"
            },
            {
                "name": "panel_2",
                "type": "visualization",
                "id": "origintrace-reachability-donut"
            },
            {
                "name": "panel_3",
                "type": "search",
                "id": "origintrace-detailed-audit-table"
            }
        ]
    }
    objects.append(dashboard_obj)
    
    ndjson_content = "\n".join(json.dumps(obj) for obj in objects) + "\n"
    return ndjson_content

def import_to_kibana():
    ndjson_content = build_saved_objects()
    ndjson_file_path = os.path.join(os.path.dirname(__file__), "origintrace_dashboard.ndjson")
    with open(ndjson_file_path, "w", encoding="utf-8") as f:
        f.write(ndjson_content)
    print(f"Generated {ndjson_file_path}")
    
    url = f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true"
    files = {
        'file': ('origintrace_dashboard.ndjson', ndjson_content.encode('utf-8'), 'application/ndjson')
    }
    response = requests.post(url, headers=HEADERS, files=files)
    print(f"Kibana Import Status: {response.status_code}")
    print("Response Body:", json.dumps(response.json(), indent=2))

if __name__ == "__main__":
    import_to_kibana()
