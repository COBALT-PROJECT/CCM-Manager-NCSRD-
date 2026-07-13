import copy
import re
import uuid

import pytest

from services import certificate_service as service


pytestmark = pytest.mark.unit


class FakeInsertResult:
    inserted_id = "inserted-id"


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = [copy.deepcopy(doc) for doc in docs or []]

    def find_one(self, query=None, projection=None):
        for doc in self.find(query or {}, projection):
            return doc
        return None

    def find(self, query=None, projection=None, sort=None):
        matches = [
            self._project(doc, projection)
            for doc in self.docs
            if self._matches(doc, query or {})
        ]
        if sort:
            for key, direction in reversed(sort):
                matches.sort(
                    key=lambda item: self._get_path(item, key),
                    reverse=direction < 0,
                )
        return matches

    def insert_one(self, document):
        self.docs.append(copy.deepcopy(document))
        return FakeInsertResult()

    def _matches(self, doc, query):
        for key, expected in query.items():
            actual = self._get_path(doc, key)
            if isinstance(expected, dict) and "$regex" in expected:
                flags = re.IGNORECASE if "i" in expected.get("$options", "") else 0
                if actual is None or not re.match(expected["$regex"], str(actual), flags):
                    return False
            elif actual != expected:
                return False
        return True

    def _project(self, doc, projection):
        if not projection:
            return copy.deepcopy(doc)
        if any(value for value in projection.values()):
            projected = {}
            for key, enabled in projection.items():
                if key == "_id" or not enabled:
                    continue
                value = self._get_path(doc, key)
                if value is not None:
                    self._set_path(projected, key, value)
            return projected
        projected = copy.deepcopy(doc)
        for key, enabled in projection.items():
            if enabled == 0:
                self._delete_path(projected, key)
        return projected

    def _get_path(self, doc, path):
        current = doc
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _set_path(self, doc, path, value):
        current = doc
        parts = path.split(".")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = copy.deepcopy(value)

    def _delete_path(self, doc, path):
        current = doc
        parts = path.split(".")
        for part in parts[:-1]:
            current = current.get(part, {})
            if not isinstance(current, dict):
                return
        current.pop(parts[-1], None)


def _scheme_doc(scheme_id, name):
    return {
        "uuid": scheme_id,
        "content": {
            "id": scheme_id,
            "name": name,
        },
    }


def _toe_doc(toe_id, scheme_id):
    return {
        "uuid": toe_id,
        "name": "Quantum ToE",
        "linked_scheme_id": scheme_id,
    }


def _patch_certificate_dependencies(monkeypatch, schemes, toes):
    certificates = FakeCollection()
    monkeypatch.setattr(service, "schemes_col", FakeCollection(schemes))
    monkeypatch.setattr(service, "toes_col", FakeCollection(toes))
    monkeypatch.setattr(service, "certificates_col", certificates)
    monkeypatch.setattr(service, "send_to_ledger", lambda *args, **kwargs: "ledger-hash")
    monkeypatch.setattr(service, "_generate_updated_certificate_pdf", lambda certificate: "/tmp/test-certificate.pdf")
    return certificates


def test_certificate_evaluation_resolves_scheme_name_to_uuid(monkeypatch):
    scheme_id = "urn:uuid:4a4f4f3d-2d55-4c48-82d2-0c44b9f43f61"
    scheme_name = "QUANTUM Scheme Reupload Test"
    toe_id = str(uuid.uuid4())
    certificates = _patch_certificate_dependencies(
        monkeypatch,
        [_scheme_doc(scheme_id, scheme_name)],
        [_toe_doc(toe_id, scheme_id)],
    )

    payload, status = service.update_certificate_evaluation_result(
        {
            "toe_id": toe_id,
            "scheme_id": scheme_name,
            "evaluation_type": "Manual",
            "result": "OK",
        }
    )

    assert status == 201
    assert payload["scheme_id"] == scheme_id
    assert payload["certificate"]["certification"]["certification_scheme"] == scheme_id
    assert certificates.docs[0]["certification"]["certification_scheme"] == scheme_id
    assert certificates.docs[0]["last_evaluation"]["scheme_id"] == scheme_id


def test_certificate_evaluation_resolves_scheme_name_alias(monkeypatch):
    scheme_id = "urn:uuid:alias-scheme"
    scheme_name = "Alias Scheme"
    toe_id = str(uuid.uuid4())
    _patch_certificate_dependencies(
        monkeypatch,
        [_scheme_doc(scheme_id, scheme_name)],
        [_toe_doc(toe_id, scheme_id)],
    )

    payload, status = service.update_certificate_evaluation_result(
        {
            "toe_id": toe_id,
            "scheme_name": scheme_name,
            "evaluation_type": "Manual",
            "result": "OK",
        }
    )

    assert status == 201
    assert payload["scheme_id"] == scheme_id


def test_certificate_evaluation_rejects_ambiguous_scheme_name(monkeypatch):
    scheme_name = "Duplicate Scheme"
    toe_id = str(uuid.uuid4())
    _patch_certificate_dependencies(
        monkeypatch,
        [
            _scheme_doc("urn:uuid:scheme-a", scheme_name),
            _scheme_doc("urn:uuid:scheme-b", scheme_name),
        ],
        [_toe_doc(toe_id, "urn:uuid:scheme-a")],
    )

    payload, status = service.update_certificate_evaluation_result(
        {
            "toe_id": toe_id,
            "scheme_id": scheme_name,
            "evaluation_type": "Manual",
            "result": "OK",
        }
    )

    assert status == 409
    assert "Multiple certification schemes" in payload["error"]
    assert {candidate["uuid"] for candidate in payload["candidates"]} == {
        "urn:uuid:scheme-a",
        "urn:uuid:scheme-b",
    }


def test_certificate_evaluation_rejects_unknown_scheme_reference(monkeypatch):
    toe_id = str(uuid.uuid4())
    _patch_certificate_dependencies(monkeypatch, [], [_toe_doc(toe_id, "urn:uuid:scheme-a")])

    payload, status = service.update_certificate_evaluation_result(
        {
            "toe_id": toe_id,
            "scheme_id": "Unknown Scheme",
            "evaluation_type": "Manual",
            "result": "OK",
        }
    )

    assert status == 404
    assert payload["scheme_reference"] == "Unknown Scheme"


def test_certificate_evaluation_keeps_toe_linkage_check_after_name_resolution(monkeypatch):
    toe_id = str(uuid.uuid4())
    _patch_certificate_dependencies(
        monkeypatch,
        [_scheme_doc("urn:uuid:requested-scheme", "Requested Scheme")],
        [_toe_doc(toe_id, "urn:uuid:linked-scheme")],
    )

    payload, status = service.update_certificate_evaluation_result(
        {
            "toe_id": toe_id,
            "certification_scheme_name": "Requested Scheme",
            "evaluation_type": "Manual",
            "result": "OK",
        }
    )

    assert status == 409
    assert payload["linked_scheme_id"] == "urn:uuid:linked-scheme"
    assert payload["requested_scheme_id"] == "urn:uuid:requested-scheme"
