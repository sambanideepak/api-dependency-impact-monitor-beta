#!/usr/bin/env python3
"""
OpenAPI spec diff -> normalized breaking changes.

Turns an OLD and NEW OpenAPI 3.x spec into the breaking-changes list the
hardened SemanticImpactMapper already consumes (see semantic_impact_mapper.py
APISpecParser.parse), enriched with ``schema_object`` (so direction scoping
works) and ``direction`` (request/response/endpoint/enum).

Purely deterministic. No network, no paid deps (only PyYAML, already present).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


# ----------------------------- spec loading ----------------------------- #

def load_spec(path: Path) -> Dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required for OpenAPI parsing")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ----------------------------- helpers ---------------------------------- #

def _paths(spec: Dict[str, Any]) -> Dict[str, Any]:
    return spec.get("paths", {}) or {}


def _components_schemas(spec: Dict[str, Any]) -> Dict[str, Any]:
    return (spec.get("components", {}) or {}).get("schemas", {}) or {}


def _iter_operations(paths: Dict[str, Any]):
    """Yield (method, endpoint, operation_dict) for every operation."""
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
    for endpoint, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() in http_methods and isinstance(op, dict):
                yield method.upper(), endpoint, op


def _schema_ref_name(ref: Optional[str]) -> Optional[str]:
    """Extract 'Task' from '#/components/schemas/Task' or 'schemas/Task'."""
    if not isinstance(ref, str):
        return None
    return ref.rstrip("/").split("/")[-1]


def _resolve_schema(spec: Dict[str, Any], schema_node: Any) -> Optional[Dict[str, Any]]:
    """Resolve a schema node to its concrete object (following $ref)."""
    if not isinstance(schema_node, dict):
        return None
    if "$ref" in schema_node:
        name = _schema_ref_name(schema_node["$ref"])
        if name:
            return _components_schemas(spec).get(name)
    return schema_node


def _response_schema_object(spec: Dict[str, Any], op: Dict[str, Any]) -> Optional[str]:
    """Best-effort schema object returned by a 200/201 response."""
    responses = op.get("responses", {}) or {}
    for code in ("200", "201", "2XX", "default"):
        resp = responses.get(code)
        if not isinstance(resp, dict):
            continue
        content = resp.get("content", {}) or {}
        for ctype, media in content.items():
            if isinstance(media, dict) and "schema" in media:
                node = _resolve_schema(spec, media["schema"])
                # unwrap array
                if isinstance(node, dict) and node.get("type") == "array":
                    items = node.get("items")
                    if isinstance(items, dict):
                        sub = _resolve_schema(spec, items)
                        if sub is not None:
                            # array of named schema -> schema name inferred later
                            return _schema_ref_name(items.get("$ref")) if items.get("$ref") else None
                if isinstance(media["schema"], dict) and media["schema"].get("$ref"):
                    return _schema_ref_name(media["schema"]["$ref"])
    return None


def _request_schema_object(spec: Dict[str, Any], op: Dict[str, Any]) -> Optional[str]:
    """Best-effort schema object accepted in the request body."""
    body = op.get("requestBody")
    if not isinstance(body, dict):
        return None
    content = body.get("content", {}) or {}
    for ctype, media in content.items():
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            sch = media["schema"]
            if sch.get("$ref"):
                return _schema_ref_name(sch["$ref"])
            # array of refs
            if sch.get("type") == "array" and isinstance(sch.get("items"), dict) and sch["items"].get("$ref"):
                return _schema_ref_name(sch["items"]["$ref"])
    return None


def _schema_fields(spec: Dict[str, Any], schema_name: Optional[str]) -> Dict[str, Any]:
    """Return {field: {type, enum}} for a named schema, following $ref."""
    if not schema_name:
        return {}
    node = _components_schemas(spec).get(schema_name)
    node = _resolve_schema(spec, node)
    if not isinstance(node, dict):
        return {}
    props = node.get("properties", {}) or {}
    out: Dict[str, Any] = {}
    for field, meta in props.items():
        if not isinstance(meta, dict):
            continue
        if "$ref" in meta:
            ref_name = _schema_ref_name(meta["$ref"])
            ref_node = _components_schemas(spec).get(ref_name) if ref_name else None
            ref_node = _resolve_schema(spec, ref_node)
            enum_vals = ref_node.get("enum") if isinstance(ref_node, dict) else None
            out[field] = {"type": (ref_node or {}).get("type", "object"),
                          "ref": ref_name, "enum": enum_vals}
        else:
            out[field] = {"type": meta.get("type"), "enum": meta.get("enum")}
    return out


def _schema_required(spec: Dict[str, Any], schema_name: Optional[str]) -> List[str]:
    node = _components_schemas(spec).get(schema_name) if schema_name else None
    node = _resolve_schema(spec, node)
    if isinstance(node, dict):
        return list(node.get("required", []) or [])
    return []


def _operation_params(op: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize an operation's parameters into a list of {name, in, required}."""
    out: List[Dict[str, Any]] = []
    for p in op.get("parameters", []) or []:
        if not isinstance(p, dict):
            continue
        out.append({
            "name": p.get("name"),
            "in": p.get("in", "query"),
            "required": bool(p.get("required", False)),
        })
    return out


def _was_required(old_params: List[Dict[str, Any]], name: Optional[str]) -> bool:
    for p in old_params:
        if p.get("name") == name and p.get("required"):
            return True
    return False


# ----------------------------- diff core -------------------------------- #

def diff_specs(old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a list of normalized breaking-change dicts."""
    changes: List[Dict[str, Any]] = []
    old_paths = _paths(old_spec)
    new_paths = _paths(new_spec)

    # 1) endpoint removals
    for endpoint, methods in old_paths.items():
        if endpoint not in new_paths:
            changes.append({
                "type": "endpoint_removed",
                "severity": "breaking",
                "path": f"paths.{endpoint}",
                "message": "Endpoint removed",
                "schema_object": "",
                "direction": "endpoint",
            })
        else:
            for method, op in methods.items():
                if not isinstance(op, dict):
                    continue
                new_op = new_paths[endpoint].get(method)
                if new_op is None:
                    changes.append({
                        "type": "endpoint_removed",
                        "severity": "breaking",
                        "path": f"paths.{endpoint}",
                        "message": f"{method.upper()} {endpoint} operation removed",
                        "schema_object": "",
                        "direction": "endpoint",
                    })

    # 2) operation-level schema/field diffs (response & request) + parameters
    for method, endpoint, op in _iter_operations(old_paths):
        new_op = None
        np = new_paths.get(endpoint)
        if isinstance(np, dict):
            new_op = np.get(method.lower())
        if new_op is None:
            continue  # endpoint/op removal already handled

        # 2a) parameter changes (query/path/header) -- breaking if removed or
        #     newly required. These are request-direction breaking changes.
        old_params = _operation_params(op)
        new_params = _operation_params(new_op)
        old_param_names = {p["name"] for p in old_params}
        new_param_names = {p["name"] for p in new_params}
        # removed parameters (a client that sends them will break / be ignored)
        for p in old_params:
            if p["name"] not in new_param_names:
                changes.append({
                    "type": "removed_param",
                    "severity": "breaking",
                    "path": (f"operations.{method} {endpoint}.parameters.{p['name']}"),
                    "message": f"Parameter '{p['name']}' ({p['in']}) removed from {method} {endpoint}",
                    "schema_object": "",
                    "direction": "request",
                    "api_field": p["name"],
                    "param_in": p["in"],
                })
        # newly required parameters
        for p in new_params:
            if p.get("required") and not _was_required(old_params, p["name"]):
                changes.append({
                    "type": "required_param",
                    "severity": "breaking",
                    "path": (f"operations.{method} {endpoint}.parameters.{p['name']}"),
                    "message": f"Parameter '{p['name']}' ({p['in']}) became required on {method} {endpoint}",
                    "schema_object": "",
                    "direction": "request",
                    "api_field": p["name"],
                    "param_in": p["in"],
                })

        # response body schema object
        rso = _response_schema_object(old_spec, op)
        # request body schema object
        qso = _request_schema_object(old_spec, op)

        for direction, schema_name in (("response", rso), ("request", qso)):
            if not schema_name:
                continue
            old_fields = _schema_fields(old_spec, schema_name)
            new_fields = _schema_fields(new_spec, schema_name)
            old_req = set(_schema_required(old_spec, schema_name))
            new_req = set(_schema_required(new_spec, schema_name))

            # removed fields
            for field in old_fields:
                if field not in new_fields:
                    changes.append({
                        "type": "removed_field",
                        "severity": "breaking",
                        "path": (f"operations.{method} {endpoint}.{direction}"
                                 f".schema.properties.{field}"),
                        "message": f"Property '{field}' removed from {direction} schema '{schema_name}'",
                        "schema_object": schema_name,
                        "direction": direction,
                        "api_field": field,
                    })
            # renamed fields (heuristic: a removed field reappears with similar name)
            removed = [f for f in old_fields if f not in new_fields]
            added = [f for f in new_fields if f not in old_fields]
            for rm in removed:
                for ad in added:
                    if _similar(rm, ad):
                        changes.append({
                            "type": "renamed_field",
                            "severity": "breaking",
                            "path": (f"operations.{method} {endpoint}.{direction}"
                                     f".schema.properties.{ad}"),
                            "message": f"Property '{rm}' renamed to '{ad}' in {direction} schema '{schema_name}'",
                            "schema_object": schema_name,
                            "direction": direction,
                            "api_field": ad,
                            "old_field": rm,
                        })
            # required field added
            for field in new_req - old_req:
                if field in new_fields:
                    changes.append({
                        "type": "required_change",
                        "severity": "breaking",
                        "path": (f"operations.{method} {endpoint}.{direction}"
                                 f".schema.required.{field}"),
                        "message": f"Field '{field}' became required in {direction} schema '{schema_name}'",
                        "schema_object": schema_name,
                        "direction": direction,
                        "api_field": field,
                    })
            # type changes (non-enum)
            for field in old_fields:
                if field in new_fields:
                    ot = old_fields[field].get("type")
                    nt = new_fields[field].get("type")
                    oe = old_fields[field].get("enum")
                    ne = new_fields[field].get("enum")
                    if ot != nt and ot is not None and nt is not None:
                        changes.append({
                            "type": "type_change",
                            "severity": "breaking",
                            "path": (f"operations.{method} {endpoint}.{direction}"
                                     f".schema.properties.{field}"),
                            "message": f"Type of '{field}' changed from {ot} to {nt} in {direction} schema '{schema_name}'",
                            "schema_object": schema_name,
                            "direction": direction,
                            "api_field": field,
                            "old_type": ot,
                            "new_type": nt,
                        })
                    # enum value rename/add/remove
                    if oe and ne and set(oe) != set(ne):
                        removed_vals = [v for v in oe if v not in ne]
                        added_vals = [v for v in ne if v not in oe]
                        for idx, ov in enumerate(removed_vals):
                            nv = added_vals[idx] if idx < len(added_vals) else (added_vals[0] if added_vals else "")
                            changes.append({
                                "type": "enum_change",
                                "severity": "breaking",
                                "path": (f"operations.{method} {endpoint}.{direction}"
                                         f".schema.properties.{field}"),
                                "message": f"Enum value '{ov}' of '{field}' changed"
                                           + (f" to '{nv}'" if nv else " (removed)"),
                                "schema_object": schema_name,
                                "direction": "enum",
                                "api_field": field,
                                "old_value": ov if ov is not None else "",
                                "new_value": nv if nv is not None else "",
                            })

    return changes


def _similar(a: str, b: str) -> bool:
    """Cheap rename heuristic: same stem, one is prefix/srefix of the other."""
    if a == b:
        return False
    a, b = a.lower(), b.lower()
    if a.startswith(b) or b.startswith(a):
        return True
    # levenshtein-ish on small strings
    if abs(len(a) - len(b)) <= 3:
        common = sum(1 for x, y in zip(a, b) if x == y)
        return common >= max(len(a), len(b)) - 2
    return False


def diff_spec_files(old_path: Path, new_path: Path) -> List[Dict[str, Any]]:
    return diff_specs(load_spec(old_path), load_spec(new_path))


def write_diff(old_path: Path, new_path: Path, out_path: Path) -> List[Dict[str, Any]]:
    changes = diff_spec_files(old_path, new_path)
    payload = {"breaking_changes": changes}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return changes


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        o = Path(sys.argv[1]).expanduser()
        n = Path(sys.argv[2]).expanduser()
        out = Path(sys.argv[3]).expanduser() if len(sys.argv) >= 4 else Path("artifacts/api-diff.json")
        ch = write_diff(o, n, out)
        print(f"Wrote {len(ch)} breaking changes to {out}")
    else:
        print("usage: spec_diff.py OLD_SPEC NEW_SPEC [OUT_JSON]")
