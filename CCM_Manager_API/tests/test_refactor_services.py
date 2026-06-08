#!/usr/bin/env python3
import os
import sys
import unittest
import xml.etree.ElementTree as ET


sys.path.insert(0, os.path.dirname(__file__))

from services import artifact_service, catalogue_service, cbom_workflow, chain_trigger
from utils import is_valid_urn_uuid


class FakeInsertResult:
    inserted_id = "fake-id"


class FakeCollection:
    def __init__(self):
        self.inserted = []
        self.updated = []

    def insert_one(self, document):
        self.inserted.append(document)
        return FakeInsertResult()

    def update_one(self, query, update, upsert=False):
        self.updated.append((query, update, upsert))


class RefactorServiceTests(unittest.TestCase):
    def test_validates_urn_uuid(self):
        self.assertTrue(is_valid_urn_uuid("urn:uuid:00000000-0000-0000-0000-000000000000"))
        self.assertFalse(is_valid_urn_uuid("00000000-0000-0000-0000-000000000000"))
        self.assertFalse(is_valid_urn_uuid("urn:uuid:not-a-uuid"))

    def test_catalogue_bulk_upsert_uses_key_and_timestamp(self):
        collection = FakeCollection()

        payload, status_code = catalogue_service.upsert_documents(
            collection,
            [{"id": "metric-1"}, {"id": "metric-2"}],
            catalogue_service.metric_key,
            "Metric must have an 'id'.",
            "metrics",
            "id",
        )

        self.assertEqual(status_code, 201)
        self.assertEqual(payload["message"], "2 metrics saved successfully.")
        self.assertEqual(len(collection.updated), 2)
        self.assertEqual(collection.updated[0][0], {"id": "metric-1"})
        self.assertIn("timestamp", collection.updated[0][1]["$set"])

    def test_saasbom_upload_assigns_serial_and_inserts(self):
        original_collection = artifact_service.collection
        fake_collection = FakeCollection()
        artifact_service.collection = fake_collection
        try:
            payload, status_code = artifact_service.upload_saasbom({
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "metadata": {"component": {"name": "service"}},
                "services": [{"name": "api", "data": [], "x-trust-boundary": True}],
            })
        finally:
            artifact_service.collection = original_collection

        self.assertEqual(status_code, 200)
        self.assertTrue(payload["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(len(fake_collection.inserted), 1)

    def test_xml_to_dict_preserves_attributes_and_text(self):
        root = ET.fromstring('<bom version="1"><component>api</component></bom>')

        self.assertEqual(
            chain_trigger.xml_to_dict(root),
            {"bom": {"component": "api", "@version": "1"}},
        )

    def test_process_cipher_normalizes_common_names(self):
        self.assertEqual(cbom_workflow.process_cipher("AESGCM(256)"), "AES_GCM_256")
        self.assertEqual(cbom_workflow.process_cipher("CHACHA20/POLY1305(256)"), "CHACHA_256")


if __name__ == "__main__":
    unittest.main()
