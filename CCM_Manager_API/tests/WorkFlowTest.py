import requests
import json
import uuid
from datetime import datetime, timezone
import unittest
import time

# --- CONFIGURATION ---
BASE_URL = "http://localhost:5001"
HEADERS = {"Content-Type": "application/json"}

# Generate unique IDs for this test run to identify data in Mongo/Ledger
TEST_RUN_ID = str(uuid.uuid4())[:8]
SCHEME_ID = f"urn:cobalt:scheme:test:{TEST_RUN_ID}"
TOE_UUID = str(uuid.uuid4())
EVIDENCE_ID = str(uuid.uuid4())

def print_banner(title):
    print(f"\n{'='*100}")
    print(f" {title.center(98)}")
    print(f"{'='*100}")

def log_api_call(step, method, endpoint, payload=None, response=None, status=None):
    print(f"\n[PHASE] {step}")
    print(f"[ACTION] {method} {BASE_URL}{endpoint}")
    if payload:
        print(f"[PAYLOAD SENT]:\n{json.dumps(payload, indent=2)}")
    if response:
        print(f"[STATUS CODE]: {status}")
        print(f"[RESPONSE RECEIVED]:\n{json.dumps(response, indent=2)}")

class TestCobaltDetailedWorkflows(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print_banner(f"COBALT CCM MANAGER INTEGRATION TEST - RUN {TEST_RUN_ID}")
        print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        print(f"Target API: {BASE_URL}")

    def test_end_to_end_lifecycle(self):
        """
        Verbose test covering Workflow 1 (Setup) and Workflow 3 (Continuous Issuance)
        """

        # ==================================================================
        # WORKFLOW 1 (WF1): SETUP & SCHEME REGISTRATION
        # ==================================================================
        print_banner("WORKFLOW 1: SETUP & SPECIFICATION")

        step_1 = "WF1.1 - Register Certification Scheme on Ledger and Database"
        scheme_payload = {
            "certificationScheme": {
                "id": SCHEME_ID,
                "name": f"COBALT Automated Audit Scheme {TEST_RUN_ID}",
                "version": "1.0",
                "description": "Standardized criteria for AI service evaluation.",
                "complianceMetrics": [
                    {"id": "Met-01", "name": "Transport Layer Security", "target_value": "TLS 1.3"}
                ],
                "controls": [{"id": "ISO-27001-A.10.1"}],
                "boundaryConditions": {"environment": "Production-Cloud"},
                "productProfile": {"type": "SaaS", "architecture": "Microservices"}
            }
        }
        
        resp = requests.post(
            f"{BASE_URL}/upload_certification_scheme?sync_drm=false&sync_scheme_import=false",
            json=scheme_payload,
            headers=HEADERS,
        )
        data = resp.json()
        log_api_call(step_1, "POST", "/upload_certification_scheme", scheme_payload, data, resp.status_code)
        
        self.assertEqual(resp.status_code, 200)
        self.assertIn("ledger_hash", data)

        # ------------------------------------------------------------------

        step_2 = "WF1.2 - Register Target of Evaluation (ToE) and Link to Scheme"
        toe_payload = {
            "component": {
                "component-definition": {
                    "uuid": str(uuid.uuid4()), # Document UUID
                    "metadata": {"title": "System Audit Record"},
                    "components": [
                        {
                            "uuid": TOE_UUID,
                            "type": "service",
                            "title": f"SIM.AI Core Engine {TEST_RUN_ID}",
                            "description": "The AI processing unit being certified."
                        }
                    ]
                }
            },
            "certification_scheme_id": SCHEME_ID # The linking mechanism
        }

        resp = requests.post(f"{BASE_URL}/upload_toe_descriptor", json=toe_payload, headers=HEADERS)
        data = resp.json()
        log_api_call(step_2, "POST", "/upload_toe_descriptor", toe_payload, data, resp.status_code)
        
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data.get('linked_scheme'), SCHEME_ID)

        # ==================================================================
        # WORKFLOW 3 (WF3): CONTINUOUS ASSESSMENT & CERTIFICATION
        # ==================================================================
        print_banner("WORKFLOW 3: CONTINUOUS CERTIFICATION LIFECYCLE")

        step_3 = "WF3.1 - Submit COMPLIANT Assessment (Automatic Issuance Trigger)"
        assessment_payload = {
            "id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "metric_id": "Met-01",
            "metric_configuration": {"operator": "==", "target": "TLS 1.3"},
            "compliant": True,
            "evidence_id": EVIDENCE_ID,
            "resource_id": "sim-production-cluster-01",
            "resource_types": ["Service-Endpoint"],
            "compliance_comment": "Automated scan confirms TLS 1.3 is enforced on all ingress points.",
            "target_of_evaluation_id": TOE_UUID,
            "tool_id": "Clouditor-Continuous-Scanner",
            "history_updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "history": [
                {
                    "evidence_id": EVIDENCE_ID, 
                    "evidence_recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                }
            ]
        }

        resp = requests.post(f"{BASE_URL}/assessment-result", json=assessment_payload, headers=HEADERS)
        data = resp.json()
        log_api_call(step_3, "POST", "/assessment-result", assessment_payload, data, resp.status_code)

        self.assertEqual(resp.status_code, 201)
        self.assertIn("certificate", data, "Compliance should have triggered certificate issuance")
        print(f"\n[RESULT] Certificate Generated successfully for ToE: {TOE_UUID}")
        print(f"[CERTIFICATE ID]: {data['certificate']['certification']['certification_id']}")

        # ------------------------------------------------------------------

        step_4 = "WF3.2 - Data Retrieval (Verify ToE and Linked Artifacts)"
        resp = requests.get(f"{BASE_URL}/retrieve_toe/{TOE_UUID}")
        data = resp.json()
        log_api_call(step_4, "GET", f"/retrieve_toe/{TOE_UUID}", None, data, resp.status_code)

        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(len(data.get('linked_documents', [])), 1)

    def tearDown(self):
        print(f"\n{'*'*50}")
        print(f"Step completion verified at {datetime.now(timezone.utc).isoformat()}")
        print(f"{'*'*50}")

if __name__ == '__main__':
    unittest.main(verbosity=2)
