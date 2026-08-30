"""GitHub MVP package: Python-first API dependency impact monitor.

Compatibility note:
The verified mapper recognizes common public requester spellings such as
``client.get(...)``. Mature Python SDKs also commonly wrap these as private
helpers (``self._get(...)``, ``self._post(...)``). Treat those private-name
wrappers as the same deterministic HTTP verbs so real SDK migrations are not
missed. This is static matching only; it performs no network or target-code
execution.
"""

from semantic_impact_mapper import ClientMethodMapper

ClientMethodMapper.METHOD_ATTRS.update(
    {
        "_get": "GET",
        "_post": "POST",
        "_put": "PUT",
        "_patch": "PATCH",
        "_delete": "DELETE",
        "_head": "HEAD",
        "_options": "OPTIONS",
    }
)
