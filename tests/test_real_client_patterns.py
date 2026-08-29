"""Unit tests for the new real-client coverage (Phases 2-4).

These use small, real-style code snippets (NOT the actual PyGithub/hvac source) to prove
the dict-deserialization and helper-built-endpoint detectors work generically, with no
filename/repo-specific hardcoding.
"""
import sys, ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from semantic_impact_mapper import (  # noqa: E402
    SemanticImpactMapper, ClientMethodMapper, EvidenceType, BreakingChange,
)
from github_mvp.spec_diff import diff_spec_files  # noqa: E402


def _dummy_spec_path():
    import tempfile
    p = Path(tempfile.mkdtemp()) / "spec.yaml"
    p.write_text("openapi: 3.0.0\ninfo:\n  title: dummy\n  version: '1'\npaths: {}\ncomponents: {}\n")
    return p


def _make_mapper(src_dir):
    return SemanticImpactMapper(src_dir, Path("/tmp/empty_diff.json"), _dummy_spec_path())


def _make_bc(schema, field, change_type="removed_field", endpoint="", method="GET",
             direction="response"):
    return BreakingChange(
        id="BC001", path=f"operations.{method} {endpoint}.{direction}.schema.properties.{field}",
        method=method, endpoint=endpoint, field_name=field, schema_object=schema,
        change_type=change_type, message=f"Property '{field}' removed", direction=direction,
    )


def test_dict_deserialization_attributes():
    """PyGithub-style: class User reads attributes['avatar_url']."""
    src = '''
class User:
    def _useAttributes(self, attributes):
        if "avatar_url" in attributes:
            self._avatar_url = self._makeStringAttribute(attributes["avatar_url"])
'''
    import tempfile, os
    d = tempfile.mkdtemp()
    f = Path(d) / "snippet.py"
    f.write_text(src)
    m = _make_mapper(f.parent)
    bc = _make_bc("User", "avatar_url", endpoint="/user")
    imps = m._analyze_dict_field_access(bc, [])
    assert len(imps) == 1, f"expected 1 impact, got {len(imps)}: {imps}"
    imp = imps[0]
    assert imp.affected_file.endswith("snippet.py")
    assert "attributes[\"avatar_url\"]" in imp.affected_code_snippet
    assert imp.confidence.value in ("HIGH", "MEDIUM")
    assert any(e.type == EvidenceType.DICT_ATTR_ACCESS for e in imp.evidence)
    print("PASS test_dict_deserialization_attributes")


def test_dict_deserialization_response_get():
    """response.get('field') inside a class matching schema."""
    src = '''
class Order:
    def from_response(self, response):
        self.id = response.get("order_id")
'''
    import tempfile
    d = tempfile.mkdtemp()
    f = Path(d) / "snippet.py"
    f.write_text(src)
    m = _make_mapper(f.parent)
    bc = _make_bc("Order", "order_id", endpoint="/orders")
    imps = m._analyze_dict_field_access(bc, [])
    assert len(imps) == 1, f"expected 1, got {len(imps)}"
    assert "response.get(\"order_id\")" in imps[0].affected_code_snippet
    print("PASS test_dict_deserialization_response_get")


def test_dict_no_match_different_field():
    """Precision: a User BC for field 'avatar_url' must NOT flag a class that only
    reads a DIFFERENT field (e.g. 'order_id'). Proves detection is field-specific,
    not a blanket grep of every string."""
    src = '''
class Order:
    def _useAttributes(self, attributes):
        if "order_id" in attributes:
            self._order_id = attributes["order_id"]
'''
    import tempfile
    d = tempfile.mkdtemp()
    f = Path(d) / "snippet.py"
    f.write_text(src)
    m = _make_mapper(f.parent)
    bc = _make_bc("User", "avatar_url", endpoint="/user")
    imps = m._analyze_dict_field_access(bc, [])
    assert len(imps) == 0, f"expected 0 (different field), got {len(imps)}"
    print("PASS test_dict_no_match_different_field")


def test_helper_built_endpoint():
    """hvac-style: api_path = utils.format_url('/v1/sys/health') then adapter.get(url=api_path)."""
    src = '''
class SystemBackend:
    def read_health_status(self):
        api_path = utils.format_url("/v1/sys/health")
        return self._adapter.get(url=api_path, raise_exception=False)
'''
    import tempfile
    d = tempfile.mkdtemp()
    f = Path(d) / "snippet.py"
    f.write_text(src)
    cm = ClientMethodMapper(f.parent)
    # find the indirectly-resolved method
    resolved = [mm for mm in cm.client_methods if mm.get("indirect")]
    assert len(resolved) == 1, f"expected 1 indirect method, got {len(resolved)}"
    mm = resolved[0]
    assert mm["http_method"] == "GET"
    assert mm["path_pattern"] == "/v1/sys/health"
    print("PASS test_helper_built_endpoint")


def test_fstring_endpoint():
    src = '''
class Items:
    def get_item(self, item_id):
        path = f"/v1/items/{item_id}"
        return self.client.get(url=path)
'''
    import tempfile
    d = tempfile.mkdtemp()
    f = Path(d) / "snippet.py"
    f.write_text(src)
    cm = ClientMethodMapper(f.parent)
    resolved = [mm for mm in cm.client_methods if mm.get("indirect")]
    assert len(resolved) == 1
    assert resolved[0]["path_pattern"] == "/v1/items/{param}", resolved[0]["path_pattern"]
    print("PASS test_fstring_endpoint")


def test_indirect_requester_name():
    """requestJsonAndCheck('GET', path) where path is built in the same function."""
    src = '''
class Wrapper:
    def fetch(self, item_id):
        path = f"/v1/items/{item_id}"
        return self.requester.requestJsonAndCheck("GET", path)
'''
    import tempfile
    d = tempfile.mkdtemp()
    f = Path(d) / "snippet.py"
    f.write_text(src)
    cm = ClientMethodMapper(f.parent)
    resolved = [mm for mm in cm.client_methods if mm.get("indirect")]
    assert len(resolved) == 1, f"expected 1, got {len(resolved)}"
    assert resolved[0]["http_method"] == "GET"
    assert resolved[0]["path_pattern"] == "/v1/items/{param}", resolved[0]["path_pattern"]
    print("PASS test_indirect_requester_name")


if __name__ == "__main__":
    test_dict_deserialization_attributes()
    test_dict_deserialization_response_get()
    test_dict_no_match_different_field()
    test_helper_built_endpoint()
    test_fstring_endpoint()
    test_indirect_requester_name()
    print("\nALL REAL-CLIENT PATTERN TESTS PASSED")
