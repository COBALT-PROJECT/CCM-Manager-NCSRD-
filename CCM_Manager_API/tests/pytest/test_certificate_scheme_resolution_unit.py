import copy
import re
import uuid
from datetime import datetime, timezone

import pytest

from services import assessment_service
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

    def replace_one(self, query, document):
        for index, existing in enumerate(self.docs):
            if self._matches(existing, query):
                self.docs[index] = copy.deepcopy(document)
                return

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


def test_certificate_evaluation_creates_then_updates_same_certificate(monkeypatch):
    scheme_id = "urn:uuid:state-transition-scheme"
    toe_id = str(uuid.uuid4())
    certificates = _patch_certificate_dependencies(
        monkeypatch,
        [_scheme_doc(scheme_id, "State Transition Scheme")],
        [_toe_doc(toe_id, scheme_id)],
    )

    base_payload = {
        "toe_id": toe_id,
        "scheme_id": scheme_id,
        "evaluation_type": "Manual",
        "result": "OK",
        "evidence_id": str(uuid.uuid4()),
    }

    created, status = service.update_certificate_evaluation_result(base_payload)
    certificate_id = created["certificate_id"]

    assert status == 201
    assert created["operation"] == "created"
    assert created["decision_status"] == "INITIATE"
    assert len(certificates.docs) == 1

    valid, status = service.update_certificate_evaluation_result(base_payload)

    assert status == 200
    assert valid["operation"] == "updated"
    assert valid["previous_state"] == "INITIATE"
    assert valid["decision_status"] == "VALID"
    assert valid["certificate_id"] == certificate_id
    assert len(certificates.docs) == 1

    suspended, status = service.update_certificate_evaluation_result(
        {**base_payload, "evaluation_type": "DYNAMIC", "result": "NOK"}
    )

    assert status == 200
    assert suspended["previous_state"] == "VALID"
    assert suspended["decision_status"] == "SUSPENDED"
    assert suspended["certificate_id"] == certificate_id
    assert len(certificates.docs) == 1

    restored, status = service.update_certificate_evaluation_result(
        {**base_payload, "evaluation_type": "DYNAMIC", "result": "OK"}
    )

    assert status == 200
    assert restored["previous_state"] == "SUSPENDED"
    assert restored["decision_status"] == "VALID"
    assert restored["certificate_id"] == certificate_id
    assert len(certificates.docs) == 1
    assert len(restored["certificate"]["certification"]["history"]) == 4


def test_assessment_result_stores_without_updating_certificate(monkeypatch):
    scheme_id = "urn:uuid:record-only-scheme"
    toe_id = str(uuid.uuid4())
    assessments = FakeCollection()

    monkeypatch.setattr(assessment_service, "toes_col", FakeCollection([_toe_doc(toe_id, scheme_id)]))
    monkeypatch.setattr(assessment_service, "schemes_col", FakeCollection([_scheme_doc(scheme_id, "Scheme")]))
    monkeypatch.setattr(assessment_service, "collection", assessments)
    monkeypatch.setattr(assessment_service, "send_to_ledger", lambda *args, **kwargs: "assessment-hash")
    monkeypatch.setattr(assessment_service, "ledger_auth_context", lambda: {"service": "ledger"})

    now = datetime.now(timezone.utc).isoformat()
    payload, status = assessment_service.process_assessment_result(
        {
            "id": str(uuid.uuid4()),
            "created_at": now,
            "metric_id": "metric-1",
            "metric_configuration": {},
            "compliant": False,
            "evidence_id": str(uuid.uuid4()),
            "resource_id": "resource-1",
            "resource_types": ["service"],
            "compliance_comment": "Noncompliant",
            "target_of_evaluation_id": toe_id,
            "history_updated_at": now,
            "history": [],
        }
    )

    assert status == 200
    assert payload["status"] == "success"
    assert payload["certificate_update_status"] == "skipped"
    assert payload["certificate_update_endpoint"] == "/certificate-evaluation-result"
    assert len(assessments.docs) == 1


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
