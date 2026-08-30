"""Regression coverage for private-name HTTP wrappers used by real Python SDKs."""

from pathlib import Path
import tempfile

# Importing github_mvp applies the package-level compatibility mapping before
# the mapper is used by the production pipeline.
import github_mvp  # noqa: F401,E402
from semantic_impact_mapper import ClientMethodMapper  # noqa: E402


def test_private_get_with_format_built_path_is_resolved():
    src = '''
class Client:
    def get_role_secret_id(self, role_name, secret_id):
        url = '/v1/auth/approle/role/{0}/secret-id/{1}'.format(role_name, secret_id)
        return self._get(url).json()
'''
    root = Path(tempfile.mkdtemp())
    (root / "client.py").write_text(src)

    mapper = ClientMethodMapper(root)
    resolved = [m for m in mapper.client_methods if m.get("indirect")]

    assert len(resolved) == 1, resolved
    assert resolved[0]["http_method"] == "GET"
    assert resolved[0]["path_pattern"] == "/v1/auth/approle/role/{param}/secret-id/{param}"


def test_private_post_wrapper_maps_as_post():
    src = '''
class Client:
    def lookup(self, role_name):
        url = '/v1/auth/approle/role/{0}/secret-id/lookup'.format(role_name)
        return self._post(url, json={'secret_id': 'x'}).json()
'''
    root = Path(tempfile.mkdtemp())
    (root / "client.py").write_text(src)

    mapper = ClientMethodMapper(root)
    resolved = [m for m in mapper.client_methods if m.get("indirect")]

    assert len(resolved) == 1, resolved
    assert resolved[0]["http_method"] == "POST"
    assert resolved[0]["path_pattern"] == "/v1/auth/approle/role/{param}/secret-id/lookup"
