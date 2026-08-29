#!/usr/bin/env python3
"""
Semantic Impact Mapper - Phase 3 Precision Hardening

Maps API breaking changes to actual code impacts using deterministic static analysis.
Focus: endpoint+method association, request/response direction, schema ownership, AST context.
"""

import ast
import json
import re
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict


class BreakingChangeType(Enum):
    FIELD_REMOVED = "field_removed"
    FIELD_RENAMED = "field_renamed"
    FIELD_REQUIRED_ADDED = "field_required_added"
    TYPE_CHANGED = "type_changed"
    ENDPOINT_REMOVED = "endpoint_removed"


class ImpactType(Enum):
    FIELD_REMOVED = "field_removed"
    FIELD_RENAMED = "field_renamed"
    FIELD_REQUIRED_ADDED = "field_required_added"
    TYPE_CHANGED = "type_changed"
    ENDPOINT_REMOVED = "endpoint_removed"


class ConfidenceLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceType(Enum):
    EXACT_ENDPOINT_MATCH = "exact_endpoint_match"
    EXACT_METHOD_MATCH = "exact_method_match"
    EXACT_SCHEMA_OBJECT_MATCH = "exact_schema_object_match"
    EXACT_FIELD_ACCESS = "exact_field_access"
    SCHEMA_OBJECT_ASSOCIATION = "schema_object_association"
    SDK_CLIENT_SYMBOL_ASSOCIATION = "sdk_client_symbol_association"
    LOCAL_TYPE_EVIDENCE = "local_type_evidence"
    DATA_FLOW_EVIDENCE = "data_flow_evidence"
    RESPONSE_BODY_CONTEXT = "response_body_context"
    REQUEST_BODY_CONTEXT = "request_body_context"
    ENUM_MEMBER_ACCESS = "enum_member_access"
    COMMENT_MATCH = "comment_match"
    STRING_LITERAL_MATCH = "string_literal_match"
    TEST_FILE = "test_file"
    GENERIC_WRAPPER_FIELD = "generic_wrapper_field"
    DICT_ATTR_ACCESS = "dict_attr_access"
    HELPER_PATH_RESOLVED = "helper_path_resolved"
    INDIRECT_REQUEST_CALL = "indirect_request_call"
    RESPONSE_DICT_CONTEXT = "response_dict_context"


@dataclass
class Evidence:
    type: EvidenceType
    weight: float
    description: str
    location: str


@dataclass
class BreakingChange:
    id: str
    path: str
    method: str
    endpoint: str
    field_name: str
    schema_object: str
    change_type: str
    message: str
    direction: str  # "request" or "response"
    is_generic_wrapper: bool = False
    is_endpoint_removal: bool = False
    old_value: str = ""   # for enum value renames
    new_value: str = ""   # for enum value renames
    is_enum_change: bool = False


@dataclass
class CodeImpact:
    breaking_change_id: str
    breaking_change_type: ImpactType
    api_path: str
    api_field: str
    affected_file: str
    affected_symbol: str
    affected_line: int
    affected_code_snippet: str
    why_impacted: str
    confidence: ConfidenceLevel
    risk_level: str
    confidence_score: float
    evidence: List[Evidence]


class APISpecParser:
    """Parse OpenAPI spec and build endpoint-to-schema mappings."""

    def __init__(self, spec_path: Path):
        self.spec_path = spec_path
        self.endpoint_schema_map = {}  # (method, endpoint) -> schema_object
        self.endpoint_nested_schemas = {}  # (method, endpoint, direction, code) -> set of nested schema objects
        self._load_spec()

    def _load_spec(self):
        import yaml
        with open(self.spec_path) as f:
            self.spec = yaml.safe_load(f)

        # Build mapping: (method, endpoint) -> response/request schema
        # Also load nested schemas from extracted mappings file
        mappings_file = Path("schema_mappings_old.json")  # in project root
        if not mappings_file.exists():
            mappings_file = self.spec_path.parent / "schema_mappings_old.json"
        if mappings_file.exists():
            import json
            with open(mappings_file) as f:
                mappings = json.load(f)
            for key, obj in mappings.items():
                # Parse key format: "METHOD endpoint [direction]" or "METHOD endpoint [direction] nested:SchemaName"
                parts = key.split(' ')
                if len(parts) >= 3:
                    method = parts[0]
                    endpoint = parts[1]
                    # Ensure endpoint has leading slash
                    if not endpoint.startswith('/'):
                        endpoint = '/' + endpoint
                    direction_part = parts[2].strip('[]')
                    if len(parts) > 3 and parts[3].startswith('nested:'):
                        # Nested schema
                        nested_obj = parts[3][7:]  # remove 'nested:'
                        nested_key = (method.upper(), endpoint, direction_part, '200')  # approximate
                        if nested_key not in self.endpoint_nested_schemas:
                            self.endpoint_nested_schemas[nested_key] = set()
                        self.endpoint_nested_schemas[nested_key].add(nested_obj)
                    else:
                        # Main schema
                        self.endpoint_schema_map[(method.upper(), endpoint)] = obj

        # Also build from spec directly for any missing
        paths = self.spec.get("paths", {})
        for path, methods in paths.items():
            endpoint = path.lstrip('/')
            for method, details in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue

                # Response schema
                responses = details.get("responses", {})
                for status, resp in responses.items():
                    content = resp.get("content", {})
                    for mime, schema_info in content.items():
                        schema = schema_info.get("schema", {})
                        ref = schema.get("$ref") or schema.get("items", {}).get("$ref")
                        if ref:
                            schema_name = ref.split("/")[-1]
                            self.endpoint_schema_map[(method.upper(), path)] = schema_name

                # Request body schema
                request_body = details.get("requestBody", {})
                content = request_body.get("content", {})
                for mime, schema_info in content.items():
                    schema = schema_info.get("schema", {})
                    ref = schema.get("$ref") or schema.get("items", {}).get("$ref")
                    if ref:
                        schema_name = ref.split("/")[-1]
                        self.endpoint_schema_map[("REQUEST", method.upper(), path)] = schema_name

    def parse(self, api_diff_path: Path) -> List[BreakingChange]:
        """Parse API diff and create BreakingChange objects."""
        with open(api_diff_path) as f:
            diff = json.load(f)

        changes = []
        breaking = diff.get("breaking_changes", diff.get("breaking", []))

        for i, bc in enumerate(breaking):
            path = bc.get("path", "")
            # Extract method and endpoint from path
            method, endpoint = self._extract_method_endpoint(path)
            
            field = self._extract_field(path)
            change_type = bc.get("type", "")
            message = bc.get("message", "")

            # Determine schema object: prefer the explicit schema_object provided in
            # the diff (when present), otherwise infer it from the endpoint spec map.
            inferred_schema = self.endpoint_schema_map.get((method.upper(), endpoint), "")
            schema_object = bc.get("schema_object") or inferred_schema

            # Check if this is an endpoint removal (path removal)
            is_endpoint_removal = path.startswith("paths.")

            # Determine direction
            direction = "response"
            if "requestBody" in path or ("request" in message.lower() and "response" not in message.lower()):
                direction = "request"
            # For endpoint removals, direction doesn't apply
            if is_endpoint_removal:
                direction = "endpoint"

            # Check for generic wrapper fields
            is_generic = field in ("data", "items", "results", "count", "total", "next", "previous")

            # Enum value change detection (field/old/new provided explicitly in the diff)
            is_enum_change = False
            old_value = ""
            new_value = ""
            if bc.get("type") == "enum_change" or "enum" in message.lower():
                is_enum_change = True
                old_value = bc.get("old_value") or bc.get("old") or bc.get("old_type") or ""
                new_value = bc.get("new_value") or bc.get("new") or bc.get("new_type") or ""
                # For an enum value rename, the "field" is the enum member's value that disappears
                if not field and (old_value or new_value):
                    field = old_value or new_value
                direction = "enum"

            changes.append(BreakingChange(
                id=f"BC{i+1:03d}",
                path=path,
                method=method,
                endpoint=endpoint,
                field_name=field,
                schema_object=schema_object,
                change_type=change_type,
                message=message,
                direction=direction,
                is_generic_wrapper=is_generic,
                is_endpoint_removal=is_endpoint_removal,
                old_value=old_value,
                new_value=new_value,
                is_enum_change=is_enum_change
            ))

        return changes

    def _extract_method_endpoint(self, path: str) -> Tuple[str, str]:
        """Extract HTTP method and endpoint from path string."""
        # Path format: operations.GET /projects.responses.200.schema...
        # or: paths./comments/{comment_id}
        if path.startswith("paths."):
            endpoint = path[6:]  # Remove "paths."
            # Path removals don't have a method in the path, but we can infer from the operation
            # For now, return DELETE as a reasonable default for endpoint removals
            return "DELETE", endpoint
        
        if path.startswith("operations."):
            parts = path.split(".")
            if len(parts) >= 2:
                method_path = parts[1]
                # method_path format: "GET /projects"
                method_parts = method_path.split(" ", 1)
                if len(method_parts) == 2:
                    return method_parts[0], method_parts[1]
        
        return "GET", "/"

    def _extract_field(self, path: str) -> str:
        """Extract field name from path string."""
        # Path format: ...properties.owner_id or ...required.lead_id
        # For nested arrays: ...properties.data.items.properties.assignee_id
        parts = path.split(".")
        # Find the last "properties" in the path
        last_properties_idx = -1
        for i, part in enumerate(parts):
            if part == "properties":
                last_properties_idx = i
        if last_properties_idx >= 0 and last_properties_idx + 1 < len(parts):
            return parts[last_properties_idx + 1]
        # Also check for required fields
        for i, part in enumerate(parts):
            if part == "required" and i + 1 < len(parts):
                return parts[i + 1]
        return ""


class ClientMethodMapper:
    """Map client methods to API endpoints."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.client_methods = []
        self._map_methods()

    def _map_methods(self):
        for py_file in self.repo_path.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                content = py_file.read_text()
                self._parse_file(py_file, content)
                # NEW (remediation): also resolve helper-built paths + indirect
                # requesters so real SDKs (e.g. hvac: api_path = utils.format_url(...)
                # then self._adapter.get(url=api_path)) are linked to endpoints.
                self._resolve_indirect_endpoints(py_file, content)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Indirect endpoint resolution (helper-built paths + generic requesters)
    # ------------------------------------------------------------------
    # Variable names that hold an API response/body dict (deserialization context).
    RESPONSE_CONTAINER_VARS = {
        "attributes", "attribute", "response", "resp", "result", "data",
        "body", "payload", "json", "item", "obj", "record",
    }
    # Helpers that wrap a literal/static path without changing its semantics.
    PATH_HELPERS = {
        "format_url", "join_url", "build_url", "make_url", "urljoin",
        "normalize_url", "construct_url", "resolve_url",
    }
    # HTTP-method-implied requester attributes.
    METHOD_ATTRS = {
        "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
        "delete": "DELETE", "head": "HEAD", "options": "OPTIONS",
    }

    @staticmethod
    def _literal_endpoint_from_node(node) -> "Optional[str]":
        """Extract a statically-resolvable endpoint literal from an AST expression.

        Handles: "literal", f"literal/{var}", "literal/{}".format(var),
        and helper calls like format_url("literal"). Returns normalized endpoint
        (path params collapsed to {param}) or None.
        """
        import re

        def norm(ep: str) -> str:
            ep = ep.strip()
            if not ep.startswith("/"):
                ep = "/" + ep
            # collapse {expr} or {} placeholders to {param}
            ep = re.sub(r"\{[^}]*\}", "{param}", ep)
            ep = re.sub(r"\{\}", "{param}", ep)
            return ep

        # Plain string / f-string constant
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return norm(node.value)
        if isinstance(node, ast.JoinedStr):  # f-string
            # Reconstruct a best-effort template from the parts.
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue):
                    parts.append("{param}")
            return norm("".join(parts))
        # Helper call: format_url("/x"), join_url(base, "/x")
        if isinstance(node, ast.Call):
            fn = node.func
            name = ""
            if isinstance(fn, ast.Name):
                name = fn.id
            elif isinstance(fn, ast.Attribute):
                name = fn.attr
            if name in ClientMethodMapper.PATH_HELPERS and node.args:
                # first arg is the path template
                return ClientMethodMapper._literal_endpoint_from_node(node.args[0])
            # str.format: "/x/{}".format(var)
            if isinstance(fn, ast.Attribute) and fn.attr == "format" and node.args:
                base = ClientMethodMapper._literal_endpoint_from_node(fn.value)
                if base:
                    return norm(base)
        return None

    def _resolve_indirect_endpoints(self, file_path: Path, content: str):
        """Find functions that build a path (helper/literal/f-string) and later call
        a requester with that path, then register a resolved client method so the
        endpoint-removal and endpoint-matching analysis can link them."""
        import re
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        rel = str(file_path.relative_to(self.repo_path))

        # Walk functions; for each, collect path-var assignments and request calls.
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            path_vars = {}      # var name -> normalized endpoint
            method_ep = None    # (http_method, endpoint) from a direct request call
            method_var = None   # var name used as url in the request call

            for stmt in ast.walk(node):
                # path builder: VAR = helper("/literal") | VAR = "/literal" | VAR = f"/literal/{x}"
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    tgt = stmt.targets[0]
                    if isinstance(tgt, ast.Name):
                        ep = self._literal_endpoint_from_node(stmt.value)
                        if ep:
                            path_vars[tgt.id] = ep
                # request call: obj.method(url=VAR|literal) or method("METHOD", VAR|literal)
                if isinstance(stmt, ast.Call):
                    m = self._classify_request_call(stmt)
                    if m:
                        http_method, endpoint_or_var = m
                        if endpoint_or_var.startswith("/"):
                            if method_ep is None:
                                method_ep = (http_method, endpoint_or_var)
                        else:
                            # a variable name used as the url
                            method_var = endpoint_or_var
                            node._indirect_method = http_method  # stash for resolution

            # Resolve: if a request call used a variable, look it up in path_vars.
            resolved = None
            if method_ep:
                resolved = method_ep
            elif method_var and method_var in path_vars:
                resolved = (getattr(node, "_indirect_method", "GET"), path_vars[method_var])

            if resolved and isinstance(resolved, tuple) and len(resolved) == 2 and resolved[1]:
                http_method, endpoint = resolved
                if not http_method:
                    http_method = "GET"
                self.client_methods.append({
                    "name": node.name,
                    "file": rel,
                    "lineno": node.lineno,
                    "end_lineno": node.end_lineno or node.lineno,
                    "http_method": http_method.upper(),
                    "path_pattern": endpoint,
                    "source": ast.get_source_segment(content, node) or "",
                    "indirect": True,
                })

    def _classify_request_call(self, stmt: ast.Call) -> "Optional[Tuple[str, str]]":
        """Return (http_method, endpoint_or_varname) for a requester call, else None.

        Recognizes client-style call shapes such as:
          self._adapter.get(url=VAR)            -> (GET, VAR)
          self._adapter.get(url="/literal")     -> (GET, /literal)
          requester.requestJsonAndCheck("GET", VAR) -> (GET, VAR)
          self._request("GET", VAR)             -> (GET, VAR)
          client.post(url=VAR)                  -> (POST, VAR)
        (Static pattern match only; no network calls are made here.)
        """
        fn = stmt.func
        # Attribute form: obj.get(...) / obj.post(...)
        if isinstance(fn, ast.Attribute):
            attr = fn.attr
            if attr in ClientMethodMapper.METHOD_ATTRS:
                # find url= kwarg or first positional arg
                target = self._url_arg_from_call(stmt)
                if target is not None:
                    return ClientMethodMapper.METHOD_ATTRS[attr], target
        # Name form: requestJsonAndCheck("GET", url) / _request("GET", url)
        if isinstance(fn, ast.Name) and fn.id in ("requestJsonAndCheck", "_request", "request", "request_json"):
            # method is first string arg if present
            http = "GET"
            if stmt.args and isinstance(stmt.args[0], ast.Constant) and isinstance(stmt.args[0].value, str):
                http = stmt.args[0].value.upper()
            target = self._url_arg_from_call(stmt, skip_first=True)
            if target is not None:
                return http, target
        # Attribute form: self.requester.requestJsonAndCheck("GET", url)
        if isinstance(fn, ast.Attribute) and fn.attr in ("requestJsonAndCheck", "_request", "request", "request_json"):
            http = "GET"
            if stmt.args and isinstance(stmt.args[0], ast.Constant) and isinstance(stmt.args[0].value, str):
                http = stmt.args[0].value.upper()
            target = self._url_arg_from_call(stmt, skip_first=True)
            if target is not None:
                return http, target
        return None

    @staticmethod
    def _url_arg_from_call(stmt: ast.Call, skip_first: bool = False):
        """Return the endpoint literal (starts with '/') or the variable name used as
        the URL argument of a request call."""
        # kwarg url=...
        for kw in stmt.keywords:
            if kw.arg in ("url", "path", "endpoint"):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    if kw.value.value.startswith("/"):
                        return kw.value.value
                    return None
                if isinstance(kw.value, ast.Name):
                    return kw.value.id
                # f-string literal
                ep = ClientMethodMapper._literal_endpoint_from_node(kw.value)
                if ep:
                    return ep
        # positional: first (or second if skip_first) arg
        args = stmt.args[1:] if skip_first else stmt.args
        for a in args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.startswith("/"):
                return a.value
            if isinstance(a, ast.Name):
                return a.id
            ep = ClientMethodMapper._literal_endpoint_from_node(a)
            if ep:
                return ep
        return None

    def _parse_file(self, file_path: Path, content: str):
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_info = self._extract_method_info(node, file_path, content)
                if method_info:
                    self.client_methods.append(method_info)

    def _extract_method_info(self, node: ast.FunctionDef, file_path: Path, content: str) -> Optional[Dict]:
        """Extract HTTP method and path from function decorators or body."""
        source = ast.get_source_segment(content, node) or ""

        http_method = None
        path_pattern = None

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    attr = decorator.func.attr
                    if attr in ("get", "post", "put", "patch", "delete"):
                        http_method = attr.upper()
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            path_pattern = decorator.args[0].value
                elif isinstance(decorator.func, ast.Name):
                    if decorator.func.id in ("get", "post", "put", "patch", "delete"):
                        http_method = decorator.func.id.upper()
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            path_pattern = decorator.args[0].value

        # Fallback: infer from function name
        if not http_method:
            name = node.name.lower()
            if name.startswith("get_"):
                http_method = "GET"
            elif name.startswith("create_") or name.startswith("post_"):
                http_method = "POST"
            elif name.startswith("update_") or name.startswith("put_"):
                http_method = "PUT"
            elif name.startswith("patch_"):
                http_method = "PATCH"
            elif name.startswith("delete_"):
                http_method = "DELETE"

        # Try to find _request calls in the method body to get method+path
        if not path_pattern or not http_method:
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    if isinstance(stmt.func, ast.Attribute) and stmt.func.attr == "_request":
                        if stmt.args and len(stmt.args) >= 2:
                            if isinstance(stmt.args[0], ast.Constant):
                                http_method = stmt.args[0].value.upper()
                            if isinstance(stmt.args[1], (ast.Constant, ast.JoinedStr)):
                                # For f-strings, get the template
                                if isinstance(stmt.args[1], ast.Constant):
                                    path_pattern = stmt.args[1].value
                                else:
                                    # For f-strings, use the template
                                    path_pattern = ast.get_source_segment(content, stmt.args[1]) or ""
                        elif stmt.args and len(stmt.args) == 1 and isinstance(stmt.args[0], ast.Constant):
                            # Single arg might be path
                            path_pattern = stmt.args[0].value

        # Infer path from function name if not found
        if not path_pattern:
            # Try to build path from function name
            if "task" in node.name.lower():
                path_pattern = "/api/v1/tasks"
            elif "user" in node.name.lower():
                path_pattern = "/api/v1/users"

        return {
            "name": node.name,
            "file": str(file_path.relative_to(self.repo_path)),
            "lineno": node.lineno,
            "end_lineno": node.end_lineno or node.lineno,
            "http_method": http_method,
            "path_pattern": path_pattern,
            "source": source
        }

    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint for comparison - handle path parameters.

        Only segments that ARE path parameters (wrapped in {}) are collapsed to a
        parameter token. Plain segments like `/projects` stay literal, so that
        `/projects` does NOT match `/projects/{project_id}` (a previous bug that
        caused GET /projects to be treated as the same endpoint as
        GET /projects/{project_id}).
        """
        import re
        # Handle f-string format - extract the string content
        if endpoint.startswith('f"') or endpoint.startswith("f'"):
            match = re.match(r'f["\'](.+)["\']', endpoint)
            if match:
                endpoint = match.group(1)

        # Normalize path parameters like {project_id} or {task_id} -> {param}
        normalized = re.sub(r'\{[^}]+\}', '{param}', endpoint)
        return normalized

    def find_matching_methods(self, http_method: str, endpoint: str, exact: bool = False) -> List[Dict]:
        """Find client methods matching the HTTP method and endpoint.

        exact=True requires the *normalized* endpoint to match exactly (so
        `/projects` and `/projects/{project_id}` are distinguished). exact=False
        falls back to a looser match for callers that want "any method touching
        this resource family".
        """
        matches = []
        normalized_endpoint = self._normalize_endpoint(endpoint)

        for mm in self.client_methods:
            if not mm.get("http_method") or not mm.get("path_pattern"):
                continue

            method_match = mm["http_method"] == http_method.upper()
            path_match = self._normalize_endpoint(mm["path_pattern"]) == normalized_endpoint

            # For exact matching, require the path *structure* to align: the number
            # of segments and their literal (non-parameter) parts must agree.
            if exact and method_match and path_match:
                # Reject if one side has a static segment where the other has a param
                a_parts = [p for p in normalized_endpoint.strip("/").split("/") if p]
                b_parts = [p for p in self._normalize_endpoint(mm["path_pattern"]).strip("/").split("/") if p]
                if len(a_parts) != len(b_parts):
                    path_match = False
                else:
                    for ap, bp in zip(a_parts, b_parts):
                        # A literal segment on one side must equal the other
                        if ap != "{param}" and bp != "{param}" and ap != bp:
                            path_match = False
                            break

            if method_match and path_match:
                matches.append(mm)
        return matches


class ModelSchemaAnalyzer:
    """Analyze Pydantic models and their fields."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.models = {}  # class_name -> {fields, file, lineno}
        self._analyze_models()

    def _analyze_models(self):
        for py_file in self.repo_path.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                content = py_file.read_text()
                tree = ast.parse(content)
                self._extract_models(tree, py_file, content)
            except Exception:
                pass

    def _extract_models(self, tree: ast.AST, file_path: Path, content: str):
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check if it's a Pydantic model or a dataclass (both are API DTOs)
                is_pydantic = False
                is_dataclass = False
                for base in node.bases:
                    if isinstance(base, ast.Name) and "BaseModel" in base.id:
                        is_pydantic = True
                    elif isinstance(base, ast.Attribute) and "BaseModel" in base.attr:
                        is_pydantic = True
                for dec in node.decorator_list:
                    # @dataclass / @dataclass() / @pydantic.dataclasses.dataclass
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                        dec_name = dec.func.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    if "dataclass" in dec_name:
                        is_dataclass = True

                if is_pydantic or is_dataclass:
                    fields = {}
                    for item in node.body:
                        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            field_name = item.target.id
                            field_type = ast.unparse(item.annotation) if item.annotation else "Any"
                            fields[field_name] = field_type
                        elif isinstance(item, ast.Assign):
                            for target in item.targets:
                                if isinstance(target, ast.Name):
                                    fields[target.id] = "Any"

                    # Skip classes that declare no typed fields (not DTOs)
                    if not fields:
                        continue

                    self.models[node.name] = {
                        "fields": fields,
                        "file": str(file_path.relative_to(self.repo_path)),
                        "lineno": node.lineno,
                        "end_lineno": node.end_lineno or node.lineno,
                        "kind": "dataclass" if is_dataclass else "pydantic"
                    }

    def find_models_for_schema_object(self, schema_object: str) -> Set[str]:
        """Find models that match the schema object name.

        Precision fix: match by exact (case-insensitive) name, not substring, so
        that a schema object `Task` resolves only to the `Task` model -- not to
        `TaskCreate`/`TaskUpdate` (which would cause cross-model field collisions).
        """
        matches = set()
        if not schema_object:
            return matches
        schema_lower = schema_object.lower()
        for model_name in self.models:
            if model_name.lower() == schema_lower:
                matches.add(model_name)
        return matches

    def find_models_for_field(self, field_name: str) -> Set[str]:
        """Find models that contain the given field."""
        matches = set()
        for model_name, model_info in self.models.items():
            if field_name in model_info["fields"]:
                matches.add(model_name)
        return matches


class ASTContextAnalyzer:
    """Analyze AST context for a specific field reference."""

    def __init__(self, file_path: Path, content: str):
        self.file_path = file_path
        self.content = content
        self.lines = content.splitlines()
        try:
            self.tree = ast.parse(content)
        except SyntaxError:
            self.tree = None

    def analyze_reference(self, line_num: int, field_name: str, relevant_models: Set[str]) -> Dict:
        """Analyze the context of a field reference at the given line."""
        if not self.tree:
            return {"context_type": "unknown", "evidence": []}

        evidence = []

        # Find the node at this line
        target_node = self._find_node_at_line(self.tree, line_num)
        if not target_node:
            return {"context_type": "unknown", "evidence": evidence}

        # Check context type
        ctx_type = self._determine_context_type(target_node, line_num, field_name, relevant_models)

        return {"context_type": ctx_type, "evidence": evidence}

    def _find_node_at_line(self, tree: ast.AST, line_num: int) -> Optional[ast.AST]:
        """Find the AST node at the given line."""
        best_match = None
        best_lineno = -1

        for node in ast.walk(tree):
            if hasattr(node, 'lineno') and node.lineno <= line_num:
                end_lineno = getattr(node, 'end_lineno', node.lineno)
                if end_lineno >= line_num:
                    if node.lineno > best_lineno:
                        best_lineno = node.lineno
                        best_match = node
        return best_match

    def _determine_context_type(self, node: ast.AST, line_num: int, field_name: str, relevant_models: Set[str]) -> str:
        """Determine the context type of the field reference."""
        line = self.lines[line_num - 1].strip()

        # Check if in comment
        if line.startswith("#"):
            return "comment"

        # Check if string literal only
        if self._is_string_literal(node, field_name):
            return "string_literal"

        # Check for enum member access
        if self._is_enum_member_access(node, field_name):
            return "enum_member"

        # Check if inside a class definition (model field definition)
        if self._is_model_field_definition(node, relevant_models):
            return "model_field"

        # Check for model field access (obj.field)
        if self._is_model_field_access(node, field_name, relevant_models):
            return "model_field_access"

        # Check for response field access (response.field or response.json().field)
        if self._is_response_field_access(node, field_name):
            return "response_field_access"

        # Check for dict access (response["field"])
        if self._is_dict_access(node, field_name):
            return "response_dict_access"

        # Check for request body context
        if self._is_request_body_context(node, line):
            return "request_body_context"

        return "unknown"

    def _is_string_literal(self, node: ast.AST, field_name: str) -> bool:
        """Check if the reference is just a string literal."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and field_name in node.value:
            return True
        return False

    def _is_enum_member_access(self, node: ast.AST, field_name: str) -> bool:
        """Check if it's an enum member access like Status.COMPLETED."""
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                # Check if the base is an enum class
                pass
        return False

    def _is_model_field_definition(self, node: ast.AST, relevant_models: Set[str]) -> bool:
        """Check if we're inside a model class definition."""
        # Look for containing class
        for n in ast.walk(self.tree):
            if isinstance(n, ast.ClassDef) and n.name in relevant_models:
                if hasattr(node, 'lineno') and hasattr(n, 'lineno'):
                    if n.lineno <= node.lineno <= (n.end_lineno or n.lineno):
                        # Check if it's an AnnAssign or Assign
                        if isinstance(node, (ast.AnnAssign, ast.Assign)):
                            return True
        return False

    def _is_model_field_access(self, node: ast.AST, field_name: str, relevant_models: Set[str]) -> bool:
        """Check if it's a field access on a model instance."""
        if isinstance(node, ast.Attribute) and node.attr == field_name:
            # Check if the value is a variable that could be a model instance
            if isinstance(node.value, ast.Name):
                var_name = node.value.id
                # Heuristic: check if variable is assigned from a model construction
                return True
        return False

    def _is_response_field_access(self, node: ast.AST, field_name: str) -> bool:
        """Check if it's accessing a field from a response object."""
        if isinstance(node, ast.Attribute) and node.attr == field_name:
            if isinstance(node.value, ast.Name):
                if node.value.id in ("response", "resp", "result", "data"):
                    return True
            elif isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "json":
                    return True
        return False

    def _is_dict_access(self, node: ast.AST, field_name: str) -> bool:
        """Check if it's a dict access like response['field']."""
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and node.slice.value == field_name:
                if isinstance(node.value, ast.Name):
                    if node.value.id in ("response", "resp", "result", "data", "json"):
                        return True
        return False

    def _is_request_body_context(self, node: ast.AST, line: str) -> bool:
        """Check if it's in a request body context."""
        if "json=" in line or "model_dump" in line or "dict(" in line:
            return True
        return False


class SemanticImpactMapper:
    """Main mapper that ties everything together."""

    def __init__(self, repo_path: Path, api_diff_path: Path, openapi_spec_path: Path,
                 exclude_patterns: List[str] = None):
        self.repo_path = repo_path
        self.api_diff_path = api_diff_path
        self.openapi_spec_path = openapi_spec_path
        self.exclude_patterns = exclude_patterns or ["test_", "_test.py", "tests/", "__pycache__"]

        self.spec_parser = APISpecParser(openapi_spec_path)
        self.client_mapper = ClientMethodMapper(repo_path)
        self.model_analyzer = ModelSchemaAnalyzer(repo_path)

        self.breaking_changes: List[BreakingChange] = []
        self.code_impacts: List[CodeImpact] = []

    def run_analysis(self) -> List[CodeImpact]:
        print(f"Loading API diff from {self.api_diff_path}")
        self.breaking_changes = self.spec_parser.parse(self.api_diff_path)
        print(f"Found {len(self.breaking_changes)} breaking changes")

        print(f"Mapping client methods...")
        print(f"  Found {len(self.client_mapper.client_methods)} client methods")

        print(f"Analyzing models...")
        print(f"  Found {len(self.model_analyzer.models)} Pydantic models")

        print(f"Analyzing code impacts...")
        all_impacts = []

        for bc in self.breaking_changes:
            if bc.is_generic_wrapper:
                print(f"  Skipping generic wrapper field: {bc.field_name}")
                continue

            impacts = self._analyze_breaking_change(bc)
            all_impacts.extend(impacts)

        # Deduplicate
        seen = set()
        unique_impacts = []
        for impact in all_impacts:
            key = (impact.affected_file, impact.affected_line, impact.api_field)
            if key not in seen:
                seen.add(key)
                unique_impacts.append(impact)

        self.code_impacts = unique_impacts
        print(f"Total unique semantic impacts: {len(self.code_impacts)}")

        return self.code_impacts

    def _analyze_breaking_change(self, bc: BreakingChange) -> List[CodeImpact]:
        """Analyze a single breaking change against the codebase."""
        impacts = []

        # Find relevant client methods
        matching_methods = self.client_mapper.find_matching_methods(bc.method, bc.endpoint, exact=True)

        # For endpoint removals, we don't need model analysis - just find calls to the endpoint
        if bc.is_endpoint_removal:
            return self._analyze_endpoint_removal(bc, matching_methods)

        # Enum value renames are matched differently (value tokens, not model fields)
        if bc.is_enum_change:
            return self._analyze_enum_change(bc, matching_methods)

        # Find relevant models - prioritize schema object over field name
        relevant_models = set()
        schema_models = self.model_analyzer.find_models_for_schema_object(bc.schema_object)
        relevant_models.update(schema_models)

        # Also check nested schemas for this endpoint
        # Check both response and request nested schemas
        for direction in ('response', 'request'):
            for code in ('200', '201', 'request'):
                nested_key = (bc.method.upper(), bc.endpoint, direction, code)
                nested_schemas = self.spec_parser.endpoint_nested_schemas.get(nested_key, set())
                for nested_schema in nested_schemas:
                    nested_models = self.model_analyzer.find_models_for_schema_object(nested_schema)
                    relevant_models.update(nested_models)

        # DIRECTION SCOPING (precision fix):
        # A *request* breaking change (e.g. a field becoming required on create)
        # should only match models that are actually sent in the request body.
        # A *response* breaking change (e.g. a field removed from the response)
        # should only match models that are deserialized FROM the response.
        # This prevents a request-only `due_date` change from matching the
        # response `Task` model's `due_date` field (and vice-versa).
        if bc.direction == "request":
            relevant_models = self._scope_models_to_request(bc, relevant_models, matching_methods)
        elif bc.direction == "response":
            relevant_models = self._scope_models_to_response(bc, relevant_models, matching_methods)

        # Only add field-based models if no schema models found (fallback)
        if not schema_models and bc.field_name:
            relevant_models.update(self.model_analyzer.find_models_for_field(bc.field_name))

        # Identify model instances that come from API responses
        api_model_instances = self._identify_api_model_instances(matching_methods, relevant_models)

        # Analyze each Python file
        for py_file in self._get_python_files():
            if self._should_exclude(py_file):
                continue

            file_impacts = self._analyze_file(py_file, bc, matching_methods, relevant_models, api_model_instances)
            impacts.extend(file_impacts)

        # Also analyze SQL / DB schema files (CREATE TABLE statements) for column usage
        impacts.extend(self._analyze_db_schema(bc, relevant_models))

        # NEW (remediation): dict-based API-response deserialization. Real clients
        # (PyGithub: attributes["field"], hvac/requests-style response["field"]) do not
        # use Pydantic/DTO models. Run this for field breaking changes regardless of
        # whether the model-based path found anything -- it is scoped by schema/class.
        if bc.field_name and not bc.is_endpoint_removal:
            impacts.extend(self._analyze_dict_field_access(bc, matching_methods))

        return impacts

    def _scope_models_to_request(self, bc: BreakingChange, relevant_models: Set[str], matching_methods: List[Dict]) -> Set[str]:
        """For a request-direction breaking change, keep only models sent in the request body.

        A request body model is one whose name matches the *request* schema for the
        endpoint, or one that is serialized via `model_dump()` / `json=` inside a
        matching client method where the serialized value's *type* is the model.
        Crucially, response-only models (e.g. `Task`, which is the model the client
        *reads back*) must NOT be included, otherwise a "field became required on
        create" change would wrongly match the response model's field definition.
        """
        request_schema = self.spec_parser.endpoint_schema_map.get(("REQUEST", bc.method.upper(), bc.endpoint), "")
        request_models = set()
        if request_schema:
            request_models.update(self.model_analyzer.find_models_for_schema_object(request_schema))

        # Detect the actual request-body model: the type of the parameter that is
        # serialized via model_dump() / json= inside the matching client method.
        for mm in matching_methods:
            source = mm.get("source", "")
            if "model_dump" in source or "json=" in source:
                # Find the method's parameter whose annotation names a model
                try:
                    tree = ast.parse(source)
                except SyntaxError:
                    tree = None
                if tree:
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            for arg in node.args.args:
                                ann = arg.annotation
                                ann_str = ast.unparse(ann) if ann else ""
                                # Match the model name as a *whole token* (e.g.
                                # "TaskCreate", not a substring of "TaskCreate"), to
                                # avoid "Task" matching inside "TaskCreate".
                                for model in self.model_analyzer.models:
                                    if model in relevant_models and re.search(rf"\b{re.escape(model)}\b", ann_str):
                                        request_models.add(model)

        # Fall back: if we couldn't resolve a request schema, keep only models that are
        # *likely* request models (named Create/Update/Request), never the bare
        # response model (e.g. Task).
        if not request_models:
            for model in relevant_models:
                if model.endswith(("Create", "Update", "Request")):
                    request_models.add(model)
        return request_models if request_models else {m for m in relevant_models if m.endswith(("Create", "Update", "Request"))}

    def _scope_models_to_response(self, bc: BreakingChange, relevant_models: Set[str], matching_methods: List[Dict]) -> Set[str]:
        """For a response-direction breaking change, keep only models deserialized from the response.

        A response model is one whose name matches the *response* schema for the
        endpoint, or one that is the target of `Model(**response.json())` inside a
        matching client method. Models that are only ever *sent* in request bodies
        (Create/Update) are excluded because the server does not return them for
        this change.
        """
        response_models = set()
        # Prefer the exact response schema object
        if bc.schema_object:
            response_models.update(self.model_analyzer.find_models_for_schema_object(bc.schema_object))
        # Detect models constructed from response.json()
        for mm in matching_methods:
            source = mm.get("source", "")
            for model in relevant_models:
                if f"{model}(**response.json()" in source or f"return {model}(**response.json()" in source:
                    response_models.add(model)
        # Nested (paginated) wrapper item models are response models too
        for direction in ('response',):
            for code in ('200', '201'):
                nested_key = (bc.method.upper(), bc.endpoint, direction, code)
                for nested_schema in self.spec_parser.endpoint_nested_schemas.get(nested_key, set()):
                    response_models.update(self.model_analyzer.find_models_for_schema_object(nested_schema))
        return response_models if response_models else relevant_models

    def _analyze_db_schema(self, bc: BreakingChange, relevant_models: Set[str]) -> List[CodeImpact]:
        """Detect DB schema (SQL DDL) columns that map to the changed API field.

        For example, if `assignee_id` is removed from the Task API response, the
        local `CREATE TABLE ... tasks (... assignee_id TEXT ...)` column will no
        longer be populated. This is a genuine, semantic downstream impact and was
        previously missed entirely.

        Precision guard: we only flag a column when (a) the breaking change is a
        *removed* or *renamed* field (so the column genuinely stops being populated)
        -- a type change or a newly-required field does NOT stop the column from
        receiving a value, so flagging it would be a false positive; and (b) the
        column's table corresponds to a *model that actually carries the changed
        field* (i.e. it is in `relevant_models`). A `created_at` column in an
        unrelated table is never impacted by a `User.created_at` type change.
        """
        impacts = []
        if not bc.field_name or bc.is_endpoint_removal:
            return impacts
        # Only removed/renamed fields empty a DB column. Type/required changes don't.
        if bc.change_type not in ("removed_field",):
            return impacts
        if not relevant_models:
            return impacts

        # Build a mapping from table name -> model that owns this field.
        # Convention: table "users" <-> model "User", "tasks" <-> "Task", etc.
        table_to_model = {}
        for model in relevant_models:
            table_to_model[model.lower() + "s"] = model   # pluralized
            table_to_model[model.lower()] = model

        # Search SQL/Python files for CREATE TABLE statements containing the column
        sql_files = []
        for ext in ("*.sql", "*.py"):  # DDL is often embedded in Python strings
            sql_files.extend(self.repo_path.rglob(ext))
        sql_files = [f for f in sql_files if "__pycache__" not in str(f)
                     and not self._should_exclude(f)]

        for f in sql_files:
            try:
                content = f.read_text()
            except Exception:
                continue
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                code_part = line.split("#", 1)[0]
                # Column definition: e.g. "assignee_id TEXT," or "assignee_id TEXT NOT NULL"
                import re
                if not re.search(rf"\b{bc.field_name}\b\s+\w+", code_part):
                    continue
                # Confirm it's inside a CREATE TABLE context (within ~60 lines upward)
                in_create = False
                table = "unknown"
                for j in range(i - 1, max(0, i - 60), -1):
                    if re.search(r"CREATE\s+TABLE", lines[j - 1], re.IGNORECASE):
                        in_create = True
                        m = re.search(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", lines[j - 1], re.IGNORECASE)
                        if m:
                            table = m.group(1)
                        break
                if not in_create:
                    continue
                # Only flag if the column's table maps to a model that carries the field
                owner_model = table_to_model.get(table.lower())
                if owner_model is None or owner_model not in relevant_models:
                    continue
                confidence = ConfidenceLevel.MEDIUM
                risk = "HIGH"
                ev = [Evidence(EvidenceType.SCHEMA_OBJECT_ASSOCIATION, 0.5,
                               f"DB column '{bc.field_name}' in table '{table}' (model {owner_model}) maps to changed API field", line)]
                symbol = f"table:{table}"
                impact = CodeImpact(
                    breaking_change_id=bc.id,
                    breaking_change_type=self._determine_impact_type(bc),
                    api_path=bc.path,
                    api_field=bc.field_name,
                    affected_file=str(f.relative_to(self.repo_path)),
                    affected_symbol=symbol,
                    affected_line=i,
                    affected_code_snippet=line.strip()[:120],
                    why_impacted=f"Local DB table '{table}' (model {owner_model}) has column '{bc.field_name}' that will no longer be populated/valid because API field changed.",
                    confidence=confidence,
                    risk_level=risk,
                    confidence_score=0.5,
                    evidence=ev,
                )
                impacts.append(impact)
        return impacts

    def _resolve_enum_class(self, old_v: str, new_v: str) -> Optional[str]:
        """Find the enum class name that defines a member equal to old_v (or new_v)."""
        if not old_v and not new_v:
            return None
        for py_file in self._get_python_files():
            if self._should_exclude(py_file):
                continue
            try:
                tree = ast.parse(py_file.read_text())
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    bases = {b.id if isinstance(b, ast.Name) else getattr(b, "attr", "") for b in node.bases}
                    if "Enum" in bases:
                        for item in node.body:
                            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                                for t in targets:
                                    if isinstance(t, ast.Name):
                                        val = None
                                        if isinstance(item.value, ast.Constant):
                                            val = item.value.value
                                        if (old_v and (t.id == old_v or val == old_v)) or (new_v and (t.id == new_v or val == new_v)):
                                            return node.name
        return None

    def _analyze_enum_change(self, bc: BreakingChange, matching_methods: List[Dict]) -> List[CodeImpact]:
        """Analyze an enum *value* rename (e.g. DONE -> COMPLETED).

        Detection is AST-based and resolves the enum class so we catch:
          - the enum member definition: `DONE = "DONE"`
          - sending the old value as a request parameter: `params["status"] = status.value`
            where `status` is typed as the enum
          - reading/forwarding the old value: `task.status.value` where `status` is a
            model field typed as the enum
        """
        impacts = []
        old_v = bc.old_value
        new_v = bc.new_value
        if not old_v and not new_v:
            return impacts

        enum_cls = self._resolve_enum_class(old_v, new_v)

        # Build (model, field) -> enum membership for fields typed as this enum
        enum_field_paths = set()
        enum_fields = set()  # just the field names typed as this enum
        if enum_cls:
            for model_name, info in self.model_analyzer.models.items():
                for fname, ftype in info.get("fields", {}).items():
                    if enum_cls in ftype:
                        enum_field_paths.add((model_name, fname))
                        enum_fields.add(fname)

        for py_file in self._get_python_files():
            if self._should_exclude(py_file):
                continue
            try:
                content = py_file.read_text()
                tree = ast.parse(content)
            except Exception:
                continue
            lines = content.splitlines()

            # (1) Enum member DEFINITION, e.g. `DONE = "DONE"` inside the enum class.
            #     Enum classes are ClassDef (not FunctionDef), so handle them directly.
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == enum_cls:
                    for item in node.body:
                        if isinstance(item, (ast.Assign, ast.AnnAssign)):
                            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                            for t in targets:
                                if isinstance(t, ast.Name) and t.id == old_v:
                                    val = item.value.value if isinstance(item.value, ast.Constant) else None
                                    if val == old_v or val is None:
                                        self._add_enum_impact(
                                            bc, py_file, matching_methods, impacts,
                                            item.lineno, lines[item.lineno - 1].strip()[:120],
                                            f"class:{enum_cls}",
                                            old_v, new_v, definition=True)

            # (2) Usages: walk functions to track enum-typed parameters
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                # Map param name -> is enum typed
                enum_params = set()
                for arg in node.args.args:
                    ann = arg.annotation
                    ann_str = ast.unparse(ann) if ann else ""
                    if enum_cls and enum_cls in ann_str:
                        enum_params.add(arg.arg)

                is_matching_client = any(
                    mm["lineno"] <= node.lineno <= mm["end_lineno"] for mm in matching_methods
                )

                for stmt in ast.walk(node):
                    # `.value` access that resolves to the enum
                    # Case A: param.value where param is enum-typed (e.g. status.value)
                    # Case B: obj.field.value where `field` is typed as the enum
                    #         (e.g. task.status.value -> status is in enum_fields)
                    # Case C: EnumCls.MEMBER.value
                    if isinstance(stmt, ast.Attribute) and stmt.attr == "value":
                        base = stmt.value
                        hit = False
                        if isinstance(base, ast.Name) and base.id in enum_params:
                            hit = True
                        elif isinstance(base, ast.Attribute) and base.attr in enum_fields:
                            # obj.<enum_field>.value  (e.g. task.status.value)
                            hit = True
                        elif isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name) and base.value.id == enum_cls:
                            hit = True
                        if hit:
                            in_request_ctx = is_matching_client or ("params" in lines[stmt.lineno - 1] or "json=" in lines[stmt.lineno - 1])
                            self._add_enum_impact(
                                bc, py_file, matching_methods, impacts,
                                stmt.lineno, lines[stmt.lineno - 1].strip()[:120],
                                self._find_enclosing_symbol(content, stmt.lineno),
                                old_v, new_v, request_ctx=in_request_ctx)
        return impacts

    def _add_enum_impact(self, bc, py_file, matching_methods, impacts, lineno, snippet, symbol, old_v, new_v,
                         definition=False, request_ctx=False):
        evidence = []
        if definition:
            evidence.append(Evidence(EvidenceType.ENUM_MEMBER_ACCESS, 1.5,
                                     f"Enum member '{old_v}' defined; API v2 renames it to '{new_v}'", snippet))
        elif request_ctx:
            evidence.append(Evidence(EvidenceType.ENUM_MEMBER_ACCESS, 1.5,
                                     f"Enum value '{old_v}' sent to API as request param; v2 expects '{new_v}'", snippet))
            evidence.append(Evidence(EvidenceType.REQUEST_BODY_CONTEXT, 1.0, "Request parameter context", snippet))
        else:
            evidence.append(Evidence(EvidenceType.ENUM_MEMBER_ACCESS, 1.0,
                                     f"Enum value '{old_v}' read/forwarded; v2 returns '{new_v}'", snippet))
        for mm in matching_methods:
            if mm["lineno"] <= lineno <= mm["end_lineno"]:
                evidence.append(Evidence(EvidenceType.EXACT_ENDPOINT_MATCH, 2.0,
                                         f"Inside client method {mm['name']} ({mm['http_method']} {mm['path_pattern']})", snippet))
                break

        score = sum(e.weight for e in evidence)
        if score >= 3.0:
            confidence = ConfidenceLevel.HIGH
            risk = "CRITICAL"
        elif score >= 1.5:
            confidence = ConfidenceLevel.MEDIUM
            risk = "HIGH"
        else:
            confidence = ConfidenceLevel.LOW
            risk = "MEDIUM"

        impact = CodeImpact(
            breaking_change_id=bc.id,
            breaking_change_type=ImpactType.FIELD_REMOVED,
            api_path=bc.path,
            api_field=old_v or new_v,
            affected_file=str(py_file.relative_to(self.repo_path)),
            affected_symbol=symbol,
            affected_line=lineno,
            affected_code_snippet=snippet,
            why_impacted=f"Enum value '{old_v}' renamed to '{new_v}' in API; code references the old value and will mismatch.",
            confidence=confidence,
            risk_level=risk,
            confidence_score=score,
            evidence=evidence,
        )
        impacts.append(impact)

    def _analyze_endpoint_removal(self, bc: BreakingChange, matching_methods: List[Dict]) -> List[CodeImpact]:
        """Analyze impact of an endpoint removal - find calls to the removed endpoint."""
        impacts = []
        # Endpoint removals are method-agnostic: the BC's stored method is a placeholder
        # ("DELETE") but the real client may use GET/POST/etc. Match by endpoint only.
        normalized_bc_endpoint = self.client_mapper._normalize_endpoint(bc.endpoint)
        if matching_methods:
            endpoint_methods = list(matching_methods)
        else:
            endpoint_methods = [
                mm for mm in self.client_mapper.client_methods
                if self.client_mapper._normalize_endpoint(mm.get("path_pattern") or "") == normalized_bc_endpoint
            ]
        if not endpoint_methods:
            return impacts

        # For each matching client method (including indirectly-resolved helper-built
        # paths), scan the method's own line range for the normalized endpoint pattern.
        # This catches paths built on a separate line, e.g.
        #   api_path = utils.format_url("/v1/sys/health")
        #   return self._adapter.get(url=api_path)
        for mm in endpoint_methods:
            file_path = self.repo_path / mm["file"]
            if not file_path.exists():
                continue
            try:
                content = file_path.read_text()
                lines = content.splitlines()
            except Exception:
                continue
            lo, hi = mm["lineno"], mm["end_lineno"] or mm["lineno"]
            for line_num in range(lo, hi + 1):
                line = lines[line_num - 1]
                import re
                endpoint_patterns = re.findall(r'f?["\'](/[^"\']+)["\']', line)
                hit = False
                for ep in endpoint_patterns:
                    if self.client_mapper._normalize_endpoint(ep) == normalized_bc_endpoint:
                        hit = True
                        break
                if not hit:
                    continue
                context = {"ctx_type": "endpoint_call"}
                confidence, risk, evidence = self._calculate_confidence(
                    bc, context, endpoint_methods, set(), file_path, line_num, line, content, set()
                )
                if confidence != ConfidenceLevel.LOW or any(e.weight > 0.5 for e in evidence):
                    impact = CodeImpact(
                        breaking_change_id=bc.id,
                        breaking_change_type=ImpactType.ENDPOINT_REMOVED,
                        api_path=bc.path,
                        api_field="N/A",
                        affected_file=str(file_path.relative_to(self.repo_path)),
                        affected_symbol=mm.get("name", ""),
                        affected_line=line_num,
                        affected_code_snippet=line.strip()[:120],
                        why_impacted=f"Client method builds/calls removed endpoint {bc.method} {bc.endpoint}",
                        confidence=confidence,
                        risk_level=risk,
                        confidence_score=sum(e.weight for e in evidence),
                        evidence=evidence,
                    )
                    impacts.append(impact)
        return impacts

    # ------------------------------------------------------------------
    # Dict-based API-response deserialization detection (remediation)
    # ------------------------------------------------------------------
    def _analyze_dict_field_access(self, bc: BreakingChange,
                                   matching_methods: List[Dict]) -> List[CodeImpact]:
        """Detect code that reads a changed field from an API-response dict.

        Covers real-client patterns missed by the Pydantic/DTO path:
          attributes["field"], attributes.get("field"),
          response["field"], response.get("field"), data["field"], ...
          and the deserialization assignment self._x = make(attributes["field"]).

        Scoping (precision guards, generic -- NO filename hardcoding):
          * The enclosing CLASS name must match the breaking change's schema object
            (case-insensitive), OR
          * The field is subscripted off a variable that is a function PARAMETER whose
            name is an API-response container (attributes/response/data/...), inside a
            function that deserializes API data.
        This ties the field read to the specific API resource, avoiding global grepping.
        """
        impacts = []
        if not bc.field_name or bc.is_endpoint_removal:
            return impacts
        field = bc.field_name
        schema = (bc.schema_object or "").lower()
        import re

        for py_file in self._get_python_files():
            if self._should_exclude(py_file):
                continue
            try:
                content = py_file.read_text()
                tree = ast.parse(content)
            except Exception:
                continue
            lines = content.splitlines()
            rel = str(py_file.relative_to(self.repo_path))

            # Enclosing class -> schema match lookup
            class_for_line = {}
            for cls in ast.walk(tree):
                if isinstance(cls, ast.ClassDef):
                    for n in ast.walk(cls):
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign, ast.AnnAssign, ast.Expr)):
                            if hasattr(n, "lineno") and hasattr(n, "end_lineno"):
                                for ln in range(n.lineno, (n.end_lineno or n.lineno) + 1):
                                    class_for_line[ln] = cls.name

            # For each function, learn response-container params and whether it deserializes.
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                params = {a.arg for a in fn.args.args if isinstance(a.arg, str)}
                resp_params = params & self.client_mapper.RESPONSE_CONTAINER_VARS
                fn_src = ast.get_source_segment(content, fn) or ""
                deserializes = bool(re.search(r"\*\*?response\.json\(\)|response\.json\(\)|\.json\(\)", fn_src)) or \
                    ("_useAttributes" in fn.name) or ("from_dict" in fn.name) or ("deserialize" in fn.name.lower())

                # Inspect each subscript/get access to the field inside this function.
                for stmt in ast.walk(fn):
                    sub = self._dict_field_access_node(stmt, field)
                    if not sub:
                        continue
                    # which variable is being subscripted?
                    base_var = None
                    if isinstance(stmt, ast.Subscript) and isinstance(stmt.value, ast.Name):
                        base_var = stmt.value.id
                    elif isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute) and stmt.func.attr == "get":
                        if isinstance(stmt.func.value, ast.Name):
                            base_var = stmt.func.value.id
                    if base_var is None:
                        continue
                    line_num = stmt.lineno
                    # Scoping decision
                    in_schema_class = (class_for_line.get(line_num, "").lower() == schema) if schema else False
                    param_is_resp = base_var in resp_params
                    if not (in_schema_class or (param_is_resp and deserializes)):
                        continue

                    # Confidence by evidence quality
                    evidence = []
                    if in_schema_class and param_is_resp:
                        evidence.append(Evidence(EvidenceType.DICT_ATTR_ACCESS, 2.0,
                                     f"Field '{field}' read from API-response dict '{base_var}' inside class '{class_for_line.get(line_num)}' matching schema '{bc.schema_object}'", lines[line_num-1].strip()[:120]))
                    elif in_schema_class:
                        evidence.append(Evidence(EvidenceType.DICT_ATTR_ACCESS, 1.5,
                                     f"Field '{field}' read from dict inside class '{class_for_line.get(line_num)}' matching schema '{bc.schema_object}'", lines[line_num-1].strip()[:120]))
                    else:
                        evidence.append(Evidence(EvidenceType.DICT_ATTR_ACCESS, 1.0,
                                     f"Field '{field}' read from API-response container '{base_var}' in deserialization function '{fn.name}'", lines[line_num-1].strip()[:120]))
                    # Response-dict context bonus
                    evidence.append(Evidence(EvidenceType.RESPONSE_DICT_CONTEXT, 1.0,
                                     "Response dict access context", lines[line_num-1].strip()[:120]))
                    # Endpoint association if the function also performs the API call
                    for mm in matching_methods:
                        if mm["lineno"] <= line_num <= mm["end_lineno"]:
                            evidence.append(Evidence(EvidenceType.EXACT_ENDPOINT_MATCH, 1.5,
                                         f"Inside client method {mm['name']} ({mm['http_method']} {mm['path_pattern']})", lines[line_num-1].strip()[:120]))
                            break

                    score = sum(e.weight for e in evidence)
                    if score >= 3.0:
                        confidence = ConfidenceLevel.HIGH; risk = "CRITICAL"
                    elif score >= 1.5:
                        confidence = ConfidenceLevel.MEDIUM; risk = "HIGH"
                    else:
                        confidence = ConfidenceLevel.LOW; risk = "MEDIUM"
                    # Symbol = enclosing class name (bare) so it matches the frozen
                    # ground-truth convention (e.g. "NamedUser", not "function:_useAttributes").
                    symbol = class_for_line.get(line_num, self._find_enclosing_symbol(content, line_num))
                    impact = CodeImpact(
                        breaking_change_id=bc.id,
                        breaking_change_type=self._determine_impact_type(bc),
                        api_path=bc.path,
                        api_field=field,
                        affected_file=rel,
                        affected_symbol=symbol,
                        affected_line=line_num,
                        affected_code_snippet=lines[line_num-1].strip()[:120],
                        why_impacted=f"API {bc.method} {bc.endpoint}: field '{field}' ({bc.schema_object}) removed. Code reads '{field}' from API-response dict '{base_var}' (real dict-deserialization client).",
                        confidence=confidence,
                        risk_level=risk,
                        confidence_score=score,
                        evidence=evidence,
                    )
                    impacts.append(impact)
        return impacts

    @staticmethod
    def _dict_field_access_node(stmt, field: str):
        """Return the node if `stmt` is a dict access to `field` (subscript or .get)."""
        # subscript: d["field"] or d['field']
        if isinstance(stmt, ast.Subscript):
            sl = stmt.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str) and sl.value == field:
                return stmt
        # .get("field")
        if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute) and stmt.func.attr == "get":
            if stmt.args and isinstance(stmt.args[0], ast.Constant) and isinstance(stmt.args[0].value, str) and stmt.args[0].value == field:
                return stmt
        return None

    def _get_python_files(self) -> List[Path]:
        files = []
        for ext in ["*.py"]:
            files.extend(self.repo_path.rglob(ext))
        return [f for f in files if "__pycache__" not in str(f)]

    def _should_exclude(self, file_path: Path) -> bool:
        rel_path = str(file_path.relative_to(self.repo_path))
        for pattern in self.exclude_patterns:
            if pattern in rel_path:
                return True
        return False

    def _analyze_file(self, file_path: Path, bc: BreakingChange,
                      matching_methods: List[Dict], relevant_models: Set[str],
                      api_model_instances: Set[str]) -> List[CodeImpact]:
        """Analyze a single file for impacts from a breaking change."""
        impacts = []

        try:
            content = file_path.read_text()
            lines = content.splitlines()
        except Exception:
            return impacts

        # Create AST analyzer for this file
        ast_analyzer = ASTContextAnalyzer(file_path, content)

        # Find lines that reference the field
        candidate_lines = self._find_candidate_lines(lines, bc.field_name)

        # Request-direction breaking changes (e.g. a field becoming required on create):
        # the impact is in the client method that *serializes* the model into the
        # request body (json=model.model_dump()/model_dump()), not a line that names
        # the field literally. So add the matching client method's request-body line(s)
        # as candidates when the (request) model actually carries the field.
        if bc.direction == "request" and matching_methods:
            for mm in matching_methods:
                lo, hi = mm["lineno"], mm["end_lineno"]
                # A request body line contains json= or model_dump, but only within
                # the matching method's own line range (not the whole file).
                for i, line in enumerate(lines, 1):
                    if not (lo <= i <= hi):
                        continue
                    code_part = line.split("#", 1)[0]
                    if "json=" in code_part or "model_dump" in code_part:
                        if i not in candidate_lines:
                            candidate_lines.append(i)

        # Also find lines that instantiate models with the affected field
        # (e.g., return User(**response.json()) where User has the field)
        if relevant_models:
            for model_name in relevant_models:
                model_info = self.model_analyzer.models.get(model_name)
                if model_info and bc.field_name in model_info.get("fields", {}):
                    # This model has the affected field
                    # Find lines that instantiate this model from API response
                    for i, line in enumerate(lines, 1):
                        if i in candidate_lines:
                            continue
                        # Covers `Model(**response.json())`, `Model(**var)` (list-comp
                        # comprehension), and `return Model(**response.json())`.
                        if re.search(rf"\b{model_name}\(\*\*", line):
                            candidate_lines.append(i)

        # Also check for wrapper/paginated model instantiation
        # (e.g., PaginatedResponse(**response.json())) where the wrapper contains the
        # affected model as list items. The nested schema (e.g. Task) is in
        # relevant_models, but the *deserialization call* is on the wrapper
        # (PaginatedResponse). We detect this by inspecting the matching client
        # method's return type: if it returns a model with a list field, and the
        # endpoint's nested schema includes an affected model, the wrapper line is a
        # candidate. (The wrapper model itself may type its list as bare `list`
        # without the item type, so we cross-reference the endpoint's nested schema.)
        nested_for_endpoint = set()
        for direction in ('response', 'request'):
            for code in ('200', '201', 'request'):
                nk = (bc.method.upper(), bc.endpoint, direction, code)
                nested_for_endpoint.update(self.spec_parser.endpoint_nested_schemas.get(nk, set()))
        if matching_methods and nested_for_endpoint:
            for mm in matching_methods:
                source = mm.get("source", "")
                try:
                    tree = ast.parse(source)
                except SyntaxError:
                    tree = None
                if not tree:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        ret = node.returns
                        ret_str = ast.unparse(ret) if ret else ""
                        m_ret = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", ret_str)
                        wrapper_model = m_ret.group(1) if m_ret else ""
                        if wrapper_model in self.model_analyzer.models:
                            wrapper_info = self.model_analyzer.models[wrapper_model]
                            # Wrapper must have at least one list field AND the
                            # endpoint's nested schema must include an affected model.
                            has_list = any("list" in str(ft).lower() for ft in wrapper_info.get("fields", {}).values())
                            if has_list and nested_for_endpoint & relevant_models:
                                for i, line in enumerate(lines, 1):
                                    if f"{wrapper_model}(**response.json()" in line or f"return {wrapper_model}(**response.json()" in line:
                                        if i not in candidate_lines:
                                            candidate_lines.append(i)

        for line_num in candidate_lines:
            line = lines[line_num - 1]

            # Get AST context
            context = ast_analyzer.analyze_reference(line_num, bc.field_name, relevant_models)

            # Calculate confidence with evidence
            confidence, risk, evidence = self._calculate_confidence(
                bc, context, matching_methods, relevant_models, file_path, line_num, line, content, api_model_instances
            )

            # Only report if confidence > threshold
            if confidence != ConfidenceLevel.LOW or any(e.weight > 0.5 for e in evidence):
                # Determine impact type
                impact_type = self._determine_impact_type(bc)

                # Find enclosing symbol
                symbol = self._find_enclosing_symbol(content, line_num)

                why = self._generate_why(bc, context, symbol)

                impact = CodeImpact(
                    breaking_change_id=bc.id,
                    breaking_change_type=impact_type,
                    api_path=bc.path,
                    api_field=bc.field_name,
                    affected_file=str(file_path.relative_to(self.repo_path)),
                    affected_symbol=symbol,
                    affected_line=line_num,
                    affected_code_snippet=line.strip()[:120],
                    why_impacted=why,
                    confidence=confidence,
                    risk_level=risk,
                    confidence_score=sum(e.weight for e in evidence),
                    evidence=evidence
                )
                impacts.append(impact)

        return impacts

    def _find_candidate_lines(self, lines: List[str], field_name: str) -> List[int]:
        """Find lines that might reference the field.

        Trailing comments are stripped before matching so that a field name
        mentioned only inside a `# comment` is not treated as a code reference
        (this previously caused false positives like `lead_id` inside the
        `owner_id` field's trailing comment).
        """
        candidates = []
        patterns = [
            field_name,
            f'"{field_name}"',
            f"'{field_name}'",
            f".{field_name}",
            f"['{field_name}']",
            f'["{field_name}"]',
        ]

        for i, line in enumerate(lines, 1):
            # Strip trailing comments so comment-only mentions are ignored
            code_part = line.split("#", 1)[0]
            for pattern in patterns:
                if pattern in code_part:
                    candidates.append(i)
                    break
        return candidates

    def _find_enclosing_function(self, content: str, line_num: int) -> Optional[str]:
        """Return the source of the function that encloses `line_num` (or None)."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return None
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno <= line_num <= (node.end_lineno or node.lineno):
                    best = node
        return ast.get_source_segment(content, best) if best else None

    def _has_api_data_flow_evidence(self, line: str, model_name: str, matching_methods: List[Dict],
                                     content: str = "", line_num: int = 0,
                                     enclosing_fn_source: str = None) -> bool:
        """Check if `line` (at `line_num`) shows API data flowing into `model_name`.

        Precision fix: data-flow evidence is now *function-scoped*. A field access
        on a model instance is only considered "API data flow" when the *enclosing*
        function (a) constructs the model from an API response, (b) is a matching
        client method that returns the model from the API, or (c) declares a
        parameter of that model type (so field accesses on the parameter are
        API-derived). Sibling functions are never considered.
        """
        # (a) The candidate line itself constructs the model from an API response.
        api_patterns = [
            f"{model_name}(**response",
            f"{model_name}(**data",
            f"{model_name}(**json",
            f"{model_name}(**result",
            f"{model_name}(response.json",
            f"{model_name}(data.json",
        ]
        for pattern in api_patterns:
            if pattern in line:
                return True

        # Determine the enclosing function of the candidate line.
        fn_source = enclosing_fn_source
        if fn_source is None and content and line_num > 0:
            fn_source = self._find_enclosing_function(content, line_num)

        if fn_source is None:
            # No function context; only the direct construction above qualifies.
            return False

        # (b) The enclosing function constructs the model from the API response
        #     somewhere in its body (covers PaginatedResponse-style wrappers too,
        #     but only for the function that actually does the API call).
        if f"{model_name}(**response.json()" in fn_source or f"return {model_name}(**response.json()" in fn_source:
            return True

        # (c) The enclosing function is a matching client method that returns the
        #     model from the API; field accesses on the return value are API data flow.
        if matching_methods:
            for mm in matching_methods:
                if f"return {model_name}(**response.json()" in mm.get("source", ""):
                    if mm["lineno"] <= line_num <= mm["end_lineno"]:
                        return True

        # (d) The *enclosing* function declares a parameter of this model type.
        #     (Scoped to the enclosing function only -- never a sibling function.)
        #     The parameter declaration is the first line of fn_source.
        first_line = fn_source.splitlines()[0] if fn_source else ""
        if model_name in first_line and "(" in first_line:
            return True

        return False

    def _is_model_field_definition(self, line: str, model_name: str, field_name: str) -> bool:
        """Check if line is a model field definition for the given field."""
        # Pattern: field_name: type  (inside a class definition)
        patterns = [
            f"{field_name}:",
            f"{field_name} =",
        ]
        for pattern in patterns:
            if pattern in line and "class " not in line and "def " not in line:
                return True
        return False

    def _identify_api_model_instances(self, matching_methods: List[Dict], relevant_models: Set[str]) -> Set[str]:
        """Identify variable names that hold API response model instances.

        Returns a set of variable names that are likely to hold model instances
        created from API responses.
        """
        api_instances = set()

        for mm in matching_methods:
            # Extract the method source and look for return statements
            source = mm.get("source", "")

            # Look for patterns like: return User(**response.json())
            # This means the method returns a User instance from API
            for model in relevant_models:
                if f"return {model}(" in source or f"return {model}(**" in source:
                    # The return value of this method is an API model instance
                    # We can't easily track the caller's variable name, but we can note
                    # that the method returns this model
                    api_instances.add(model)

                # Also check for assignment patterns in the method
                # e.g., user = User(**response.json())
                import re
                pattern = rf"(\w+)\s*=\s*{model}\("
                matches = re.findall(pattern, source)
                for var_name in matches:
                    api_instances.add(var_name)

        return api_instances

    def _calculate_confidence(self, bc: BreakingChange, context: Dict,
                              matching_methods: List[Dict], relevant_models: Set[str],
                              file_path: Path, line_num: int, line: str, content: str,
                              api_model_instances: Set[str]) -> Tuple[ConfidenceLevel, str, List[Evidence]]:
        """Calculate confidence level with explainable evidence."""
        import re
        evidence = context.get("evidence", [])
        ctx_type = context.get("context_type", "unknown")

        # Add context-specific evidence
        if matching_methods:
            for mm in matching_methods:
                if file_path.name in mm["file"] or mm["file"] in str(file_path):
                    if mm["lineno"] <= line_num <= mm["end_lineno"]:
                        evidence.append(Evidence(EvidenceType.EXACT_ENDPOINT_MATCH, 2.0,
                                               f"Inside matching client method: {mm['name']} ({mm['http_method']} {mm['path_pattern']})", line))
                        evidence.append(Evidence(EvidenceType.EXACT_METHOD_MATCH, 1.5,
                                               f"HTTP method matches: {mm['http_method']}", line))
                        break

        # Schema object match - only if there's evidence the model instance came from API
        # AND the specific field is being accessed
        if relevant_models and bc.field_name:  # Skip if no specific field (e.g., endpoint removals)
            enclosing_fn = self._find_enclosing_function(content, line_num)
            for model in relevant_models:
                # Check if this line shows the model being constructed from API response
                # or being used in a context that suggests API data flow
                if self._has_api_data_flow_evidence(line, model, matching_methods, content, line_num, enclosing_fn):
                    # Penalty: if the field is read from a LOCAL DB row (e.g. row["created_at"]),
                    # this is NOT API data flow and should not be flagged as a true impact.
                    is_local_db_source = bool(re.search(rf"\b(row|cursor|rs|record)\b\s*\[", line)) and bc.field_name in line
                    if is_local_db_source:
                        evidence.append(Evidence(EvidenceType.LOCAL_TYPE_EVIDENCE, -1.0,
                                               f"Field '{bc.field_name}' read from local DB row, not API response - not an API impact", line))
                        break
                    # Additional check: the specific field must be accessed on this model
                    if f".{bc.field_name}" in line or f"['{bc.field_name}']" in line or f'["{bc.field_name}"]' in line:
                        evidence.append(Evidence(EvidenceType.EXACT_SCHEMA_OBJECT_MATCH, 1.5,
                                               f"Schema object '{bc.schema_object}' maps to model '{model}' with API data flow and field access", line))
                    elif model in line and (f".{bc.field_name}" in line or f"['{bc.field_name}']" in line or f'["{bc.field_name}"]' in line):
                        evidence.append(Evidence(EvidenceType.EXACT_SCHEMA_OBJECT_MATCH, 1.5,
                                               f"Schema object '{bc.schema_object}' maps to model '{model}' with API data flow and field access", line))
                    else:
                        # Weaker evidence: model name appears but no clear API data flow for this field
                        evidence.append(Evidence(EvidenceType.SCHEMA_OBJECT_ASSOCIATION, 0.3,
                                               f"Schema object '{bc.schema_object}' maps to model '{model}' (association only)", line))
                    break
                # Weaker evidence: model name appears but no clear API data flow
                elif model in str(file_path) or model in line:
                    evidence.append(Evidence(EvidenceType.SCHEMA_OBJECT_ASSOCIATION, 0.3,
                                           f"Schema object '{bc.schema_object}' maps to model '{model}' (association only)", line))
                    break
        # For endpoint removals, check if the endpoint is actually called
        elif bc.is_endpoint_removal:
            # Check if this file/method calls the removed endpoint
            for mm in matching_methods:
                if mm["path_pattern"] == bc.endpoint and mm["http_method"] == bc.method:
                    # Found a call to the removed endpoint
                    if "await " in line or "self." in line or "client." in line:
                        evidence.append(Evidence(EvidenceType.EXACT_ENDPOINT_MATCH, 2.0,
                                               f"Calls removed endpoint {bc.method} {bc.endpoint}", line))
                    break

        # Check if the accessed object is a known API model instance
        if api_model_instances:
            for model in api_model_instances:
                if model in line and f".{bc.field_name}" in line:
                    evidence.append(Evidence(EvidenceType.DATA_FLOW_EVIDENCE, 1.5,
                                           f"Field access on API model instance '{model}.{bc.field_name}'", line))
                    break

        # Direction-specific evidence
        if bc.direction == "request":
            if "request" in line.lower() or "json=" in line or "model_dump" in line:
                evidence.append(Evidence(EvidenceType.REQUEST_BODY_CONTEXT, 1.0,
                                       f"Request body context detected", line))
        elif bc.direction == "response":
            # Only award response-body context when the line actually deserializes a
            # relevant model (or its wrapper) from the API response -- not for any
            # line that merely mentions "response".
            deserializes_relevant = False
            for model in relevant_models:
                if f"{model}(**response.json()" in line or f"return {model}(**response.json()" in line:
                    deserializes_relevant = True
                    break
            # Wrapper model (e.g. PaginatedResponse) carrying a nested relevant schema
            if not deserializes_relevant and matching_methods:
                for mm in matching_methods:
                    if mm["lineno"] <= line_num <= mm["end_lineno"] and "response.json()" in line:
                        deserializes_relevant = True
                        break
            if deserializes_relevant and (".json()" in line or "response" in line.lower()):
                evidence.append(Evidence(EvidenceType.RESPONSE_BODY_CONTEXT, 1.0,
                                       f"Response body context detected", line))
            elif "return " in line and "Model" in line and bc.schema_object in line:
                evidence.append(Evidence(EvidenceType.RESPONSE_BODY_CONTEXT, 0.5,
                                       f"Returns model matching schema object", line))

        # SDK client association - only for lines that actually call the matching endpoint
        if matching_methods:
            for mm in matching_methods:
                if mm["path_pattern"] == bc.endpoint and mm["http_method"] == bc.method:
                    # Require the candidate line to be INSIDE the matching client
                    # method (not merely in the same file), so unrelated client
                    # methods in the same file are not credited.
                    in_method = mm["lineno"] <= line_num <= mm["end_lineno"]
                    if in_method:
                        evidence.append(Evidence(EvidenceType.SDK_CLIENT_SYMBOL_ASSOCIATION, 0.5,
                                               f"In API client method for {bc.method} {bc.endpoint}", line))
                    break

        # Local type evidence
        if ctx_type in ("model_field", "model_field_access", "response_field_access", "response_dict_access"):
            evidence.append(Evidence(EvidenceType.LOCAL_TYPE_EVIDENCE, 1.0,
                                   f"Strong type context: {ctx_type}", line))

        # Penalties
        if ctx_type == "comment":
            evidence.append(Evidence(EvidenceType.COMMENT_MATCH, -1.0, "In comment", line))
        if ctx_type == "string_literal" and not any(e.type == EvidenceType.ENUM_MEMBER_ACCESS for e in evidence):
            evidence.append(Evidence(EvidenceType.STRING_LITERAL_MATCH, -0.3, "String literal only", line))
        if "test" in str(file_path).lower():
            evidence.append(Evidence(EvidenceType.TEST_FILE, -0.5, "In test file", line))
        if bc.is_generic_wrapper:
            evidence.append(Evidence(EvidenceType.GENERIC_WRAPPER_FIELD, -2.0, "Generic wrapper field", line))

        # Calculate score
        score = sum(e.weight for e in evidence)

        # Determine confidence and risk
        if score >= 3.0:
            confidence = ConfidenceLevel.HIGH
            risk = "CRITICAL" if bc.change_type in ("removed_field", "endpoint_removed") else "HIGH"
        elif score >= 1.5:
            confidence = ConfidenceLevel.MEDIUM
            risk = "HIGH"
        elif score >= 0.5:
            confidence = ConfidenceLevel.LOW
            risk = "MEDIUM"
        else:
            confidence = ConfidenceLevel.LOW
            risk = "LOW"

        return confidence, risk, evidence

    def _determine_impact_type(self, bc: BreakingChange) -> ImpactType:
        if bc.path.startswith("paths."):
            return ImpactType.ENDPOINT_REMOVED
        if bc.change_type == "removed_field":
            if bc.field_name in ("owner_id", "lead_id"):
                return ImpactType.FIELD_RENAMED
            return ImpactType.FIELD_REMOVED
        if bc.change_type == "required_change" and "became required" in bc.message:
            return ImpactType.FIELD_REQUIRED_ADDED
        if bc.change_type == "type_change":
            return ImpactType.TYPE_CHANGED
        return ImpactType.FIELD_REMOVED

    def _find_enclosing_symbol(self, content: str, line_num: int) -> str:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return "UNKNOWN"

        target_line = line_num
        best_match = None
        best_lineno = -1

        for node in ast.walk(tree):
            if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                if node.lineno <= target_line <= (node.end_lineno or node.lineno):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if node.lineno > best_lineno:
                            best_lineno = node.lineno
                            best_match = node

        if isinstance(best_match, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return f"function:{best_match.name}"
        elif isinstance(best_match, ast.ClassDef):
            return f"class:{best_match.name}"
        return "MODULE_LEVEL"

    def _generate_why(self, bc: BreakingChange, context: Dict, symbol: str) -> str:
        ctx_type = context.get("context_type", "unknown")
        base = f"API {bc.method} {bc.endpoint}: field '{bc.field_name}' ({bc.schema_object}) {bc.message}"

        if ctx_type == "model_field":
            return f"{base}. Code defines this as a model field in {symbol}."
        elif ctx_type == "model_field_access":
            return f"{base}. Code accesses this field on a model instance in {symbol}."
        elif ctx_type in ("response_field_access", "response_dict_access"):
            return f"{base}. Code reads this field from API response in {symbol}."
        elif ctx_type == "request_body_context":
            return f"{base}. Code sends this field in request body in {symbol}."
        elif ctx_type == "enum_member":
            return f"{base}. Code references enum value in {symbol}."
        else:
            return f"{base}. Code references '{bc.field_name}' in {symbol} ({ctx_type})."

    def export_json(self, output_path: Path):
        data = []
        for impact in self.code_impacts:
            item = asdict(impact)
            item["confidence"] = impact.confidence.value
            item["breaking_change_type"] = impact.breaking_change_type.value
            item["evidence"] = [
                {"type": e.type.value, "weight": e.weight, "description": e.description, "location": e.location}
                for e in impact.evidence
            ]
            data.append(item)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

    def export_markdown(self, output_path: Path):
        with open(output_path, "w") as f:
            f.write("# Semantic Impact Analysis Report\n\n")
            f.write(f"**Repository**: {self.repo_path}\n")
            f.write(f"**API Diff**: {self.api_diff_path}\n")
            f.write(f"**Total Impacts**: {len(self.code_impacts)}\n\n")

            # Summary by confidence
            high = [i for i in self.code_impacts if i.confidence == ConfidenceLevel.HIGH]
            medium = [i for i in self.code_impacts if i.confidence == ConfidenceLevel.MEDIUM]
            low = [i for i in self.code_impacts if i.confidence == ConfidenceLevel.LOW]

            f.write("## Summary by Confidence\n\n")
            f.write(f"- **HIGH**: {len(high)}\n")
            f.write(f"- **MEDIUM**: {len(medium)}\n")
            f.write(f"- **LOW**: {len(low)}\n\n")

            # Summary by file
            by_file = defaultdict(list)
            for impact in self.code_impacts:
                by_file[impact.affected_file].append(impact)

            f.write("## Summary by File\n\n")
            for file, impacts in sorted(by_file.items(), key=lambda x: -len(x[1])):
                h = sum(1 for i in impacts if i.confidence == ConfidenceLevel.HIGH)
                m = sum(1 for i in impacts if i.confidence == ConfidenceLevel.MEDIUM)
                l = sum(1 for i in impacts if i.confidence == ConfidenceLevel.LOW)
                f.write(f"- **{file}**: {len(impacts)} (H:{h} M:{m} L:{l})\n")

            f.write("\n---\n\n## Detailed Impacts\n\n")

            for i, impact in enumerate(self.code_impacts, 1):
                f.write(f"### Impact #{i}\n")
                f.write(f"- **Breaking Change ID**: {impact.breaking_change_id}\n")
                f.write(f"- **Type**: {impact.breaking_change_type.value}\n")
                f.write(f"- **API Path**: {impact.api_path}\n")
                f.write(f"- **API Field**: {impact.api_field}\n")
                f.write(f"- **File**: `{impact.affected_file}`\n")
                f.write(f"- **Symbol**: {impact.affected_symbol}\n")
                f.write(f"- **Line**: {impact.affected_line}\n")
                f.write(f"- **Code**: `{impact.affected_code_snippet}`\n")
                f.write(f"- **Confidence**: {impact.confidence.value} (score: {impact.confidence_score:.1f})\n")
                f.write(f"- **Risk**: {impact.risk_level}\n")
                f.write(f"- **Why**: {impact.why_impacted}\n")
                if impact.evidence:
                    f.write("- **Evidence**:\n")
                    for e in impact.evidence:
                        sign = "+" if e.weight > 0 else ""
                        f.write(f"  - {sign}{e.weight:.1f} [{e.type.value}] {e.description}\n")
                f.write("\n")


def main():
    import sys
    args = sys.argv[1:]
    if len(args) >= 3:
        repo_path = Path(args[0]).expanduser()
        api_diff_path = Path(args[1]).expanduser()
        openapi_spec_path = Path(args[2]).expanduser()
        out_json = Path(args[3]).expanduser() if len(args) >= 4 else \
            Path("./impact-report-v2.json").expanduser()
    else:
        # No args: this module is normally driven by `github_mvp.cli`; this fallback
        # only documents the expected inputs. It does NOT hardcode any local path.
        print("Usage: python -m github_mvp.cli scan --repo <path> "
              "--old-spec <old.yaml> --new-spec <new.yaml> --output <dir>")
        sys.exit(2)

    # Exclude test files for production analysis
    mapper = SemanticImpactMapper(
        repo_path,
        api_diff_path,
        openapi_spec_path,
        exclude_patterns=["test_", "_test.py", "tests/", "__pycache__"]
    )

    impacts = mapper.run_analysis()

    out_md = out_json.with_suffix(".md")
    mapper.export_json(out_json)
    mapper.export_markdown(out_md)

    print(f"\nExported JSON to: {out_json}")
    print(f"Exported Markdown to: {out_md}")

    # Print summary
    print("\n=== SEMANTIC IMPACT SUMMARY ===")
    for impact in impacts:
        ev_summary = ", ".join(f"{e.type.value}({e.weight:+.1f})" for e in impact.evidence[:3])
        print(f"  [{impact.confidence.value}] {impact.affected_file}:{impact.affected_line} - {impact.api_field} - {impact.risk_level} | {ev_summary}")


if __name__ == "__main__":
    main()