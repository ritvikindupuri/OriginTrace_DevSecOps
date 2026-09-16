"""
OriginTrace Provenance & Workload Resolver
Maps container image digests, pod labels, and process paths to Git repositories and source code files.
"""
import os
import json
from typing import Dict, Any, Optional

class WorkloadResolver:
    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = workspace_root or os.getcwd()

    def resolve_source_target(self, alert_fields: Dict[str, Any]) -> Dict[str, Any]:
        proc_name = alert_fields.get("proc.name", "")
        cmdline = alert_fields.get("proc.cmdline", "")
        container_image = alert_fields.get("container.image.repository", "")
        k8s_pod = alert_fields.get("k8s.pod.name", "")
        
        candidate_files = []
        for root, _, files in os.walk(self.workspace_root):
            for file in files:
                if file.endswith((".py", ".go", ".js", ".ts", ".java")):
                    candidate_files.append(os.path.join(root, file))

        return {
            "workspace_root": self.workspace_root,
            "container_image": container_image,
            "pod_name": k8s_pod,
            "process_binary": proc_name,
            "command_line": cmdline,
            "candidate_source_files": candidate_files
        }
