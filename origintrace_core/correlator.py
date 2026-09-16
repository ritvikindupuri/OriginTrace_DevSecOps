"""
OriginTrace AST & Syscall Correlation Engine
Analyzes Python AST syntax trees to map runtime Falco eBPF kernel events
(e.g., execve, openat, connect) directly to offending source code functions and lines.
"""
import ast
import os
import re
from typing import Dict, Any, List, Optional

class SyscallASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings = []
        self.current_function = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        
        # Mapping dangerous sinks to potential syscall / Falco trigger categories
        if func_name in ("os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call"):
            self.findings.append({
                "type": "command_execution",
                "sink": func_name,
                "line": node.lineno,
                "col": node.col_offset,
                "function": self.current_function or "<global>",
                "file": self.filename,
                "ast_node": ast.dump(node)
            })
        elif func_name in ("open", "builtins.open", "os.open"):
            self.findings.append({
                "type": "file_access",
                "sink": func_name,
                "line": node.lineno,
                "col": node.col_offset,
                "function": self.current_function or "<global>",
                "file": self.filename,
                "ast_node": ast.dump(node)
            })
        elif func_name in ("requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"):
            self.findings.append({
                "type": "network_outbound",
                "sink": func_name,
                "line": node.lineno,
                "col": node.col_offset,
                "function": self.current_function or "<global>",
                "file": self.filename,
                "ast_node": ast.dump(node)
            })
        elif func_name in ("cursor.execute", "db.execute", "sqlite3.execute"):
            self.findings.append({
                "type": "database_query",
                "sink": func_name,
                "line": node.lineno,
                "col": node.col_offset,
                "function": self.current_function or "<global>",
                "file": self.filename,
                "ast_node": ast.dump(node)
            })
        self.generic_visit(node)

    def _get_call_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_call_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        return ""

class SyscallCorrelator:
    def __init__(self, workspace_path: Optional[str] = None):
        self.workspace_path = workspace_path or os.getcwd()

    def correlate_falco_alert(self, falco_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlates a Falco alert dictionary to the source code AST.
        """
        rule = falco_alert.get("rule", "")
        output = falco_alert.get("output", "")
        fields = falco_alert.get("output_fields", {})
        cmdline = fields.get("proc.cmdline", output)
        
        # Determine relevant attack pattern
        target_type = "command_execution"
        if "file" in rule.lower() or "read" in rule.lower() or "tampering" in rule.lower():
            target_type = "file_access"
        elif "network" in rule.lower() or "connect" in rule.lower() or "reverse shell" in rule.lower():
            target_type = "network_outbound"

        matched_locations = []
        for root, _, files in os.walk(self.workspace_path):
            if any(p in root for p in [".git", "origintrace_core", "tests", ".pytest_cache", ".venv"]):
                continue

            for f in files:
                if f.endswith(".py"):
                    full_path = os.path.join(root, f)
                    try:
                        with open(full_path, "r", encoding="utf-8") as py_file:
                            tree = ast.parse(py_file.read(), filename=full_path)
                            visitor = SyscallASTVisitor(full_path)
                            visitor.visit(tree)
                            for finding in visitor.findings:
                                if finding["type"] == target_type:
                                    matched_locations.append(finding)
                    except Exception:
                        continue

        if not matched_locations:
            for root, _, files in os.walk(self.workspace_path):
                if any(p in root for p in [".git", ".pytest_cache"]):
                    continue
                for f in files:
                    if f.endswith(".py"):
                        full_path = os.path.join(root, f)
                        try:
                            with open(full_path, "r", encoding="utf-8") as py_file:
                                tree = ast.parse(py_file.read(), filename=full_path)
                                visitor = SyscallASTVisitor(full_path)
                                visitor.visit(tree)
                                for finding in visitor.findings:
                                    if finding["type"] == target_type:
                                        matched_locations.append(finding)
                        except Exception:
                            continue

        return {
            "falco_rule": rule,
            "target_category": target_type,
            "runtime_cmdline": cmdline,
            "matched_ast_sinks": matched_locations,
            "correlation_confidence": "HIGH" if matched_locations else "MEDIUM"
        }
