import copy
import json
from pathlib import Path

import pytest

import app as app_module
from services import artifact_service
from services import certification_scheme_service as scheme_service


pytestmark = pytest.mark.unit

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "data" / "eucs"


class FakeInsertResult:
    inserted_id = "fake-id"


class FakeCollection:
    def __init__(self):
        self.docs = []

    def insert_one(self, document):
        self.docs.append(copy.deepcopy(document))
        return FakeInsertResult()

    def insert_many(self, documents):
        for document in documents:
            self.insert_one(document)

    def update_one(self, query, update, upsert=False):
        document = self.find_one(query)
        if document is None:
            if not upsert:
                return
            document = copy.deepcopy(query)
            self.docs.append(document)

        for key, value in update.get("$set", {}).items():
            self._set_nested(document, key, copy.deepcopy(value))

    def delete_many(self, query):
        self.docs = [
            document for document in self.docs
            if not self._matches(document, query)
        ]

    def find(self, query=None, projection=None):
        query = query or {}
        return [
            self._project(document, projection)
            for document in self.docs
            if self._matches(document, query)
        ]

    def find_one(self, query=None, projection=None):
        query = query or {}
        for document in self.docs:
            if self._matches(document, query):
                return self._project(document, projection)
        return None

    def _project(self, document, projection):
        result = document
        if projection and projection.get("_id") == 0:
            result = {key: value for key, value in document.items() if key != "_id"}
        return result

    def _matches(self, document, query):
        for key, expected in query.items():
            if self._get_nested(document, key) != expected:
                return False
        return True

    def _get_nested(self, document, key):
        value = document
        for part in key.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    def _set_nested(self, document, key, value):
        current = document
        parts = key.split(".")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value


def load_json(filename):
    with open(FIXTURE_DIR / filename) as fixture:
        return json.load(fixture)


def bundled_scheme_payload():
    payload = load_json("global_certification_scheme_fully_mapped.json")
    payload["catalog"] = load_json("EUCS_controls_version_1.1_catalog_master.json")["catalog"]
    payload["profile"] = load_json("EUCS_version_1.1_profile_All.json")["profile"]
    return payload


def patch_scheme_collections(monkeypatch):
    collections = {
        "schemes": FakeCollection(),
        "metrics": FakeCollection(),
        "risks": FakeCollection(),
        "threats": FakeCollection(),
        "controls": FakeCollection(),
        "rtc": FakeCollection(),
        "cm": FakeCollection(),
    }

    monkeypatch.setattr(scheme_service, "schemes_col", collections["schemes"])
    monkeypatch.setattr(scheme_service, "metrics_col", collections["metrics"])
    monkeypatch.setattr(scheme_service, "risks_col", collections["risks"])
    monkeypatch.setattr(scheme_service, "threats_col", collections["threats"])
    monkeypatch.setattr(scheme_service, "controls_col", collections["controls"])
    monkeypatch.setattr(scheme_service, "rtc_col", collections["rtc"])
    monkeypatch.setattr(scheme_service, "cm_col", collections["cm"])
    monkeypatch.setattr(scheme_service, "send_to_ledger", lambda endpoint, data: "ledger-hash")
    return collections


def catalog_control_ids():
    catalog = load_json("EUCS_controls_version_1.1_catalog_master.json")["catalog"]
    return set(scheme_service._catalog_control_index(catalog))


def test_fully_mapped_scheme_imports_eucs_relationships(monkeypatch):
    patch_scheme_collections(monkeypatch)

    payload, status_code = scheme_service.upload_certification_scheme(bundled_scheme_payload())

    assert status_code == 200
    assert payload["populated"] == {
        "metrics": 36,
        "risks": 10,
        "threats": 4,
        "controls": 41,
        "control_metric_mappings": 36,
        "risk_threat_control_mappings": 87,
    }

    export, status_code = scheme_service.export_scheme(payload["uuid"])

    assert status_code == 200
    assert export["counts"] == {
        "risks": 10,
        "threats": 4,
        "metrics": 36,
        "controls": 41,
        "rtc_mappings": 87,
        "cm_mappings": 36,
    }
    assert export["scheme"]["catalog"]["uuid"] == "74c8ba1e-5cd4-4ad1-bbfd-d888e2f6c724"
    assert export["scheme"]["profile"]["uuid"] == "74c8ba1e-5cd4-4ad1-bbfd-d888e2f6c724"

    first_control = next(
        control for control in export["controls"]
        if control["control_id"] == "eucs-7.AI-01_req.1"
    )
    assert first_control["title"] == "AI-01.1"
    assert first_control["class"] == "Model Theft"
    assert first_control["prose"]


def test_fully_mapped_scheme_control_references_exist_in_catalog():
    scheme = load_json("global_certification_scheme_fully_mapped.json")["certificationScheme"]
    references = scheme_service._referenced_control_ids(
        scheme["certifiable_standards_mapping"],
        scheme["risk_catalogue"],
        scheme.get("controls", []),
    )

    assert len(references) == 41
    assert set(references).issubset(catalog_control_ids())


def test_upload_oscal_route_merges_profile_and_catalog(monkeypatch):
    fake_collection = FakeCollection()
    monkeypatch.setattr(artifact_service, "collection", fake_collection)

    client = app_module.app.test_client()
    catalog_payload = load_json("EUCS_controls_version_1.1_catalog_master.json")
    profile_payload = load_json("EUCS_version_1.1_profile_All.json")
    doc_uuid = profile_payload["profile"]["uuid"]

    response = client.post("/upload_oscal", json=catalog_payload)
    assert response.status_code == 200

    response = client.post("/upload_oscal", json=profile_payload)
    assert response.status_code == 200

    response = client.post("/upload_oscal", json=profile_payload)
    assert response.status_code == 200
    assert "Duplicate profile" in response.get_json()["message"]

    stored = fake_collection.find_one({"uuid": doc_uuid})
    assert set(stored["content"]) == {"catalog", "profile"}

    response = client.get(f"/oscal_ids/{doc_uuid}")
    assert response.status_code == 200
    control_ids = response.get_json()["control_ids"]
    assert len(control_ids) == 165
    assert set(control_ids).issubset(catalog_control_ids())
