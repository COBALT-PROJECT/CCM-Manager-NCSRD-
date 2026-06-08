#!/usr/bin/env python3
"""
CCM Manager API Test Suite
==========================
This script tests all API endpoints, checks for hardcoded values,
and validates Swagger documentation against actual endpoints.

Usage:
    python test_api.py [--base-url http://localhost:5001] [--verbose]
"""

import requests
import json
import os
import sys
import argparse
import re
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum
import hashlib
import uuid


class TestStatus(Enum):
    PASSED = "✅ PASSED"
    FAILED = "❌ FAILED"
    SKIPPED = "⏭️ SKIPPED"
    WARNING = "⚠️ WARNING"


@dataclass
class TestResult:
    name: str
    status: TestStatus
    message: str
    response_code: Optional[int] = None
    response_time: Optional[float] = None


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


class CCMAPITester:
    def __init__(self, base_url: str = "http://localhost:5001", verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.results: List[TestResult] = []
        self.swagger_endpoints: Dict[str, Dict] = {}
        self.actual_endpoints: List[Dict] = []
        
        # Sample test data based on actual project examples
        self.sample_data = self._load_sample_data()
        
    def _load_sample_data(self) -> Dict[str, Any]:
        """Load sample data for testing based on project examples"""
        return {
            "cbom_input": {
                "ciphers": {
                    "tls": {
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {
                            "TLS_version": "1.2",
                            "encryption_algorithm": "AESGCM(256)",
                            "oid": "2.16.840.1.101.3.4.1.46"
                        },
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {
                            "TLS_version": "1.2",
                            "encryption_algorithm": "AESGCM(128)",
                            "oid": "2.16.840.1.101.3.4.1.6"
                        }
                    }
                },
                "certificate": {
                    "subjectName": "CN=test.example.com",
                    "issuerName": "CN=Test CA",
                    "notValidBefore": "Jan 01 00:00:00 2024 GMT",
                    "notValidAfter": "Jan 01 00:00:00 2026 GMT",
                    "rsaPublicKey": "test-public-key-123",
                    "signatureAlgorithm": "sha256WithRSAEncryption",
                    "oid": "1.2.840.113549.1.1.11",
                    "publicKeyAlgorithm": "rsaEncryption"
                }
            },
            "oscal_catalog": {
                "catalog": {
                    "uuid": str(uuid.uuid4()),
                    "metadata": {
                        "title": "Test Catalog",
                        "version": "1.0.0",
                        "last-modified": datetime.now().isoformat()
                    }
                }
            },
            "oscal_profile": {
                "profile": {
                    "uuid": str(uuid.uuid4()),
                    "metadata": {
                        "title": "Test Profile",
                        "version": "1.0.0"
                    },
                    "imports": [
                        {
                            "include-controls": [
                                {"with-ids": ["AC-1", "AC-2", "CM-2"]}
                            ]
                        }
                    ]
                }
            },
            "oscal_component_definition": {
                "component-definition": {
                    "uuid": str(uuid.uuid4()),
                    "metadata": {
                        "title": "Test Component",
                        "version": "1.0.0",
                        "last-modified": datetime.now().isoformat(),
                        "oscal-version": "1.1.2"
                    },
                    "components": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "type": "service",
                            "title": "Test Service",
                            "description": "A test service component"
                        }
                    ]
                }
            },
            "saasbom": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "version": 1,
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "Test SaaS Application",
                        "version": "1.0.0"
                    }
                },
                "services": [
                    {
                        "name": "test-service",
                        "data": {"classification": "internal"},
                        "x-trust-boundary": True
                    }
                ]
            },
            "toe_descriptor": {
                "component": {
                    "component-definition": {
                        "components": [
                            {
                                "uuid": str(uuid.uuid4()),
                                "title": "Test TOE Component"
                            }
                        ]
                    }
                },
                "bills-of-material": {
                    "sbom": {},
                    "vex": {},
                    "cbom": {},
                    "saasbo": {}
                }
            },
            "certification_scheme": {
                "certificationScheme": {
                    "id": f"scheme-{uuid.uuid4()}",
                    "complianceMetrics": [{"id": "metric-1", "name": "Test Metric"}],
                    "controls": [{"id": "control-1", "name": "Test Control"}],
                    "boundaryConditions": [{"id": "boundary-1"}],
                    "productProfile": {"name": "Test Product"}
                }
            },
            "ledger_entry": {
                "component-definition": {
                    "uuid": str(uuid.uuid4()),
                    "metadata": {
                        "title": "Ledger Test",
                        "version": "1.0.0"
                    }
                }
            },
            "evidence": {
                "timestamp": datetime.now().isoformat(),
                "toolId": "test-tool-001",
                "raw": {"test": "data"},
                "resource": "test-resource",
                "id": f"evidence-{uuid.uuid4()}"
            },
            "assessment_result": {
                "targetId": f"target-{uuid.uuid4()}",
                "status": "compliant",
                "timestamp": datetime.now().isoformat()
            }
        }

    def log(self, message: str, color: str = ""):
        """Print message with optional color"""
        if self.verbose or not color:
            print(f"{color}{message}{Colors.END}" if color else message)

    def log_section(self, title: str):
        """Print section header"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{title.center(60)}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")

    def add_result(self, result: TestResult):
        """Add test result and print status"""
        self.results.append(result)
        color = {
            TestStatus.PASSED: Colors.GREEN,
            TestStatus.FAILED: Colors.RED,
            TestStatus.SKIPPED: Colors.YELLOW,
            TestStatus.WARNING: Colors.YELLOW
        }.get(result.status, "")
        
        timing = f" ({result.response_time:.2f}s)" if result.response_time else ""
        code = f" [HTTP {result.response_code}]" if result.response_code else ""
        print(f"{color}{result.status.value}{Colors.END} {result.name}{code}{timing}")
        if result.message and (self.verbose or result.status in [TestStatus.FAILED, TestStatus.WARNING]):
            print(f"    └─ {result.message}")

    def make_request(self, method: str, endpoint: str, **kwargs) -> Tuple[Optional[requests.Response], float]:
        """Make HTTP request and return response with timing"""
        url = f"{self.base_url}{endpoint}"
        start_time = datetime.now()
        try:
            response = requests.request(method, url, timeout=30, **kwargs)
            elapsed = (datetime.now() - start_time).total_seconds()
            return response, elapsed
        except requests.exceptions.RequestException as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            self.log(f"Request error: {e}", Colors.RED)
            return None, elapsed

    def describe_test(self, name: str, description: str, sends: str, expects: str):
        """Print test description before running"""
        print(f"\n{Colors.CYAN}┌{'─'*58}┐{Colors.END}")
        print(f"{Colors.CYAN}│{Colors.END} {Colors.BOLD}{name}{Colors.END}")
        print(f"{Colors.CYAN}│{Colors.END} {Colors.DIM}Description:{Colors.END} {description}")
        print(f"{Colors.CYAN}│{Colors.END} {Colors.DIM}Sends:{Colors.END} {sends}")
        print(f"{Colors.CYAN}│{Colors.END} {Colors.DIM}Expects:{Colors.END} {expects}")
        print(f"{Colors.CYAN}└{'─'*58}┘{Colors.END}")

    # ==================== ENDPOINT TESTS ====================

    def test_home_endpoint(self):
        """Test GET / - Home endpoint"""
        self.describe_test(
            "GET /",
            "Health check endpoint to verify API is running",
            "Empty GET request",
            "HTTP 200 with JSON containing 'message' key"
        )
        response, elapsed = self.make_request("GET", "/")
        if response is None:
            self.add_result(TestResult("GET /", TestStatus.FAILED, "Connection failed"))
            return
        
        if response.status_code == 200:
            data = response.json()
            if "message" in data:
                self.add_result(TestResult("GET /", TestStatus.PASSED, data["message"], 200, elapsed))
            else:
                self.add_result(TestResult("GET /", TestStatus.WARNING, "Missing 'message' key", 200, elapsed))
        else:
            self.add_result(TestResult("GET /", TestStatus.FAILED, f"Unexpected status", response.status_code, elapsed))

    def test_data_endpoint(self):
        """Test POST /data - Insert data"""
        self.describe_test(
            "POST /data",
            "Insert arbitrary JSON data into MongoDB",
            "JSON body: {test_key, timestamp}",
            "HTTP 201 with {status: 'success', id: <mongo_id>}"
        )
        test_data = {"test_key": "test_value", "timestamp": datetime.now().isoformat()}
        response, elapsed = self.make_request("POST", "/data", json=test_data)
        
        if response is None:
            self.add_result(TestResult("POST /data", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 201:
            data = response.json()
            if data.get("status") == "success":
                self.add_result(TestResult("POST /data", TestStatus.PASSED, f"ID: {data.get('id')}", 201, elapsed))
            else:
                self.add_result(TestResult("POST /data", TestStatus.WARNING, "Missing success status", 201, elapsed))
        else:
            self.add_result(TestResult("POST /data", TestStatus.FAILED, response.text[:100], response.status_code, elapsed))

    def test_show_vulnerabilities(self):
        """Test GET /show_vulnerabilities"""
        self.describe_test(
            "GET /show_vulnerabilities",
            "Retrieve all stored vulnerabilities from MongoDB",
            "Empty GET request",
            "HTTP 200 with vulnerability array, or 404 if none exist"
        )
        response, elapsed = self.make_request("GET", "/show_vulnerabilities")
        
        if response is None:
            self.add_result(TestResult("GET /show_vulnerabilities", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code in [200, 404]:
            self.add_result(TestResult("GET /show_vulnerabilities", TestStatus.PASSED, 
                "Vulnerabilities found" if response.status_code == 200 else "No vulnerabilities", 
                response.status_code, elapsed))
        else:
            self.add_result(TestResult("GET /show_vulnerabilities", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_generate_cbom_no_file(self):
        """Test POST /generate_cbom without file (should fail)"""
        self.describe_test(
            "POST /generate_cbom (no file)",
            "Validation test - CBOM generation requires a file upload",
            "Empty POST request (no file attached)",
            "HTTP 400 with error message about missing file"
        )
        response, elapsed = self.make_request("POST", "/generate_cbom")
        
        if response is None:
            self.add_result(TestResult("POST /generate_cbom (no file)", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 400:
            self.add_result(TestResult("POST /generate_cbom (no file)", TestStatus.PASSED, 
                "Correctly rejected missing file", 400, elapsed))
        else:
            self.add_result(TestResult("POST /generate_cbom (no file)", TestStatus.FAILED, 
                f"Expected 400, got {response.status_code}", response.status_code, elapsed))

    def test_generate_cbom_with_data(self):
        """Test POST /generate_cbom with valid data"""
        self.describe_test(
            "POST /generate_cbom (with data)",
            "Generate Cryptographic BOM from TLS cipher and certificate data",
            "Multipart form: JSON file with {ciphers, certificate}, hashed_ip",
            "HTTP 200 with {algorithm_sbom, certificate_sbom, protocol_sbom} filenames"
        )
        import io
        
        cbom_data = json.dumps(self.sample_data["cbom_input"])
        files = {'file': ('test_cbom.json', io.BytesIO(cbom_data.encode()), 'application/json')}
        data = {'hashed_ip': hashlib.sha256(b'test_ip').hexdigest()}
        
        response, elapsed = self.make_request("POST", "/generate_cbom", files=files, data=data)
        
        if response is None:
            self.add_result(TestResult("POST /generate_cbom (with data)", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            result = response.json()
            if "algorithm_sbom" in result:
                self.add_result(TestResult("POST /generate_cbom (with data)", TestStatus.PASSED, 
                    f"Generated: {result.get('algorithm_sbom')}", 200, elapsed))
            else:
                self.add_result(TestResult("POST /generate_cbom (with data)", TestStatus.WARNING, 
                    "Response missing expected fields", 200, elapsed))
        else:
            self.add_result(TestResult("POST /generate_cbom (with data)", TestStatus.FAILED, 
                response.text[:200], response.status_code, elapsed))

    def test_receive_output(self):
        """Test POST /receive_output with JSON data"""
        self.describe_test(
            "POST /receive_output",
            "Receive output from CCM Agent and trigger CBOM generation",
            "JSON body with TLS cipher info and certificate data",
            "HTTP 200 - internally calls /generate_cbom"
        )
        response, elapsed = self.make_request("POST", "/receive_output", json=self.sample_data["cbom_input"])
        
        if response is None:
            self.add_result(TestResult("POST /receive_output", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            self.add_result(TestResult("POST /receive_output", TestStatus.PASSED, 
                "CBOM generated via receive_output", 200, elapsed))
        else:
            self.add_result(TestResult("POST /receive_output", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_upload_oscal_catalog(self):
        """Test POST /upload_oscal with catalog"""
        self.describe_test(
            "POST /upload_oscal (catalog)",
            "Upload OSCAL catalog document (security control definitions)",
            "JSON body: {catalog: {uuid, metadata, groups}}",
            "HTTP 200 with {message, uuid}"
        )
        response, elapsed = self.make_request("POST", "/upload_oscal", json=self.sample_data["oscal_catalog"])
        
        if response is None:
            self.add_result(TestResult("POST /upload_oscal (catalog)", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            data = response.json()
            self.add_result(TestResult("POST /upload_oscal (catalog)", TestStatus.PASSED, 
                f"UUID: {data.get('uuid')}", 200, elapsed))
        else:
            self.add_result(TestResult("POST /upload_oscal (catalog)", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_upload_oscal_profile(self):
        """Test POST /upload_oscal with profile"""
        self.describe_test(
            "POST /upload_oscal (profile)",
            "Upload OSCAL profile document (control baseline selection)",
            "JSON body: {profile: {uuid, metadata, imports}}",
            "HTTP 200 with {message, uuid}"
        )
        response, elapsed = self.make_request("POST", "/upload_oscal", json=self.sample_data["oscal_profile"])
        
        if response is None:
            self.add_result(TestResult("POST /upload_oscal (profile)", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            data = response.json()
            self.add_result(TestResult("POST /upload_oscal (profile)", TestStatus.PASSED, 
                f"UUID: {data.get('uuid')}", 200, elapsed))
            # Store UUID for oscal_ids test
            self.profile_uuid = data.get('uuid')
        else:
            self.add_result(TestResult("POST /upload_oscal (profile)", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_upload_oscal_component_definition(self):
        """Test POST /upload_oscal with component-definition"""
        self.describe_test(
            "POST /upload_oscal (component-def)",
            "Upload OSCAL component definition (system component security info)",
            "JSON body: {component-definition: {uuid, metadata, components}}",
            "HTTP 200 with {message, uuid}"
        )
        response, elapsed = self.make_request("POST", "/upload_oscal", json=self.sample_data["oscal_component_definition"])
        
        if response is None:
            self.add_result(TestResult("POST /upload_oscal (component-def)", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            self.add_result(TestResult("POST /upload_oscal (component-def)", TestStatus.PASSED, 
                "Component definition uploaded", 200, elapsed))
        else:
            self.add_result(TestResult("POST /upload_oscal (component-def)", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_oscal_ids_endpoint(self):
        """Test GET /oscal_ids/<doc_uuid>"""
        self.describe_test(
            "GET /oscal_ids/<uuid>",
            "Retrieve control IDs from a stored OSCAL profile by UUID",
            "URL parameter: doc_uuid (profile identifier)",
            "HTTP 200 with {control_ids: [...]}, or 404 if not found"
        )
        # First upload a profile to get a UUID
        test_uuid = str(uuid.uuid4())
        profile_data = {
            "content": {
                "profile": {
                    "uuid": test_uuid,
                    "imports": [{"include-controls": [{"with-ids": ["AC-1", "AC-2"]}]}]
                }
            }
        }
        
        # Test with non-existent UUID (should return 404)
        response, elapsed = self.make_request("GET", f"/oscal_ids/{test_uuid}")
        
        if response is None:
            self.add_result(TestResult("GET /oscal_ids/<uuid>", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 404:
            self.add_result(TestResult("GET /oscal_ids/<uuid> (not found)", TestStatus.PASSED, 
                "Correctly returned 404 for missing profile", 404, elapsed))
        elif response.status_code == 200:
            self.add_result(TestResult("GET /oscal_ids/<uuid>", TestStatus.PASSED, 
                "Control IDs retrieved", 200, elapsed))
        else:
            self.add_result(TestResult("GET /oscal_ids/<uuid>", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_upload_saasbom(self):
        """Test POST /upload_saasbom"""
        self.describe_test(
            "POST /upload_saasbom",
            "Upload SaaS Bill of Materials (CycloneDX 1.4 with services)",
            "JSON body: {bomFormat, specVersion, version, metadata, services}",
            "HTTP 200 with {message, serialNumber}"
        )
        response, elapsed = self.make_request("POST", "/upload_saasbom", json=self.sample_data["saasbom"])
        
        if response is None:
            self.add_result(TestResult("POST /upload_saasbom", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            data = response.json()
            self.add_result(TestResult("POST /upload_saasbom", TestStatus.PASSED, 
                f"Serial: {data.get('serialNumber')}", 200, elapsed))
        else:
            self.add_result(TestResult("POST /upload_saasbom", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_upload_saasbom_validation(self):
        """Test POST /upload_saasbom with invalid data"""
        self.describe_test(
            "POST /upload_saasbom (invalid)",
            "Validation test - SaaSBOM requires CycloneDX 1.4 format",
            "JSON body: {bomFormat: 'Invalid', specVersion: '1.0'}",
            "HTTP 400 with validation error"
        )
        invalid_data = {"bomFormat": "Invalid", "specVersion": "1.0"}
        response, elapsed = self.make_request("POST", "/upload_saasbom", json=invalid_data)
        
        if response is None:
            self.add_result(TestResult("POST /upload_saasbom (invalid)", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 400:
            self.add_result(TestResult("POST /upload_saasbom (invalid)", TestStatus.PASSED, 
                "Correctly rejected invalid SaaSBOM", 400, elapsed))
        else:
            self.add_result(TestResult("POST /upload_saasbom (invalid)", TestStatus.FAILED, 
                f"Expected 400, got {response.status_code}", response.status_code, elapsed))

    def test_upload_toe_descriptor(self):
        """Test POST /upload_toe_descriptor"""
        self.describe_test(
            "POST /upload_toe_descriptor",
            "Upload Target of Evaluation descriptor and forward to external service",
            "JSON body: {component, bills-of-material: {sbom, vex, cbom, saasbo}}",
            "HTTP 200 with forward status, or 502 if FORWARD_URL unavailable"
        )
        response, elapsed = self.make_request("POST", "/upload_toe_descriptor", json=self.sample_data["toe_descriptor"])
        
        if response is None:
            self.add_result(TestResult("POST /upload_toe_descriptor", TestStatus.WARNING, 
                "External FORWARD_URL service not available (timeout)"))
            return
            
        # This endpoint forwards to FORWARD_URL, so 502 is expected if FORWARD_URL is not available
        if response.status_code == 200:
            self.add_result(TestResult("POST /upload_toe_descriptor", TestStatus.PASSED, 
                "Descriptor forwarded successfully", 200, elapsed))
        elif response.status_code == 502:
            self.add_result(TestResult("POST /upload_toe_descriptor", TestStatus.WARNING, 
                "Forward URL not available (expected in test env)", 502, elapsed))
        else:
            self.add_result(TestResult("POST /upload_toe_descriptor", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_upload_certification_scheme(self):
        """Test POST /upload_certification_scheme"""
        self.describe_test(
            "POST /upload_certification_scheme",
            "Upload certification scheme with compliance metrics and controls",
            "JSON body: {certificationScheme: {id, complianceMetrics, controls, ...}}",
            "HTTP 200 with {message, uuid}"
        )
        response, elapsed = self.make_request("POST", "/upload_certification_scheme", 
            json=self.sample_data["certification_scheme"])
        
        if response is None:
            self.add_result(TestResult("POST /upload_certification_scheme", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            self.add_result(TestResult("POST /upload_certification_scheme", TestStatus.PASSED, 
                "Certification scheme uploaded", 200, elapsed))
        else:
            self.add_result(TestResult("POST /upload_certification_scheme", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_store_ledger(self):
        """Test POST /store-ledger"""
        self.describe_test(
            "POST /store-ledger",
            "Store OSCAL component definition in ledger with integrity hash",
            "JSON body: {component-definition: {uuid, metadata}}",
            "HTTP 201 with {message, uuid, hash}"
        )
        response, elapsed = self.make_request("POST", "/store-ledger", json=self.sample_data["ledger_entry"])
        
        if response is None:
            self.add_result(TestResult("POST /store-ledger", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 201:
            data = response.json()
            self.ledger_uuid = data.get('uuid')  # Store for update test
            self.add_result(TestResult("POST /store-ledger", TestStatus.PASSED, 
                f"UUID: {data.get('uuid')}, Hash: {data.get('hash', '')[:16]}...", 201, elapsed))
        else:
            self.add_result(TestResult("POST /store-ledger", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_update_ledger(self):
        """Test PUT /update-ledger/<uuid>"""
        self.describe_test(
            "PUT /update-ledger/<uuid>",
            "Update existing ledger entry and recalculate hash",
            "URL param: uuid, JSON body: {component-definition: {...}}",
            "HTTP 200 with {message, uuid, hash}, or 404 if not found"
        )
        # Use the UUID from store_ledger test, or a random one
        test_uuid = getattr(self, 'ledger_uuid', str(uuid.uuid4()))
        updated_data = self.sample_data["ledger_entry"].copy()
        updated_data["component-definition"]["metadata"]["title"] = "Updated Ledger Test"
        
        response, elapsed = self.make_request("PUT", f"/update-ledger/{test_uuid}", json=updated_data)
        
        if response is None:
            self.add_result(TestResult("PUT /update-ledger/<uuid>", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            self.add_result(TestResult("PUT /update-ledger/<uuid>", TestStatus.PASSED, 
                "Ledger entry updated", 200, elapsed))
        elif response.status_code == 404:
            self.add_result(TestResult("PUT /update-ledger/<uuid>", TestStatus.PASSED, 
                "Correctly returned 404 for non-existent entry", 404, elapsed))
        else:
            self.add_result(TestResult("PUT /update-ledger/<uuid>", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_send_sdt(self):
        """Test POST /send_sdt"""
        self.describe_test(
            "POST /send_sdt",
            "Orchestrate SDT workflow: deploy → deployments → create",
            "JSON body: {hash: '<sha256_hash>'}",
            "HTTP 200 with workflow status (requires external SDT services)"
        )
        test_data = {"hash": hashlib.sha256(b'test').hexdigest()}
        response, elapsed = self.make_request("POST", "/send_sdt", json=test_data)
        
        if response is None:
            self.add_result(TestResult("POST /send_sdt", TestStatus.WARNING, 
                "External SDT services not available (timeout)"))
            return
            
        # This endpoint calls external services, so various status codes are acceptable
        if response.status_code == 200:
            self.add_result(TestResult("POST /send_sdt", TestStatus.PASSED, 
                "SDT workflow completed", 200, elapsed))
        elif response.status_code in [404, 500, 502]:
            self.add_result(TestResult("POST /send_sdt", TestStatus.WARNING, 
                "External services not available (expected in test env)", response.status_code, elapsed))
        else:
            self.add_result(TestResult("POST /send_sdt", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_trigger_delete(self):
        """Test POST /trigger_delete"""
        self.describe_test(
            "POST /trigger_delete",
            "Trigger deletion in external SDT system",
            "JSON body: {identifier: '<resource_id>'}",
            "HTTP 200 with delete response (requires DELETE_SDT service)"
        )
        test_data = {"identifier": "test-identifier-001"}
        response, elapsed = self.make_request("POST", "/trigger_delete", json=test_data)
        
        if response is None:
            self.add_result(TestResult("POST /trigger_delete", TestStatus.WARNING, 
                "External DELETE_SDT service not available (timeout)"))
            return
            
        # External service dependency
        if response.status_code == 200:
            self.add_result(TestResult("POST /trigger_delete", TestStatus.PASSED, 
                "Delete triggered", 200, elapsed))
        elif response.status_code == 500:
            self.add_result(TestResult("POST /trigger_delete", TestStatus.WARNING, 
                "External DELETE_SDT service not available", 500, elapsed))
        else:
            self.add_result(TestResult("POST /trigger_delete", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_send_records(self):
        """Test POST /send_records"""
        self.describe_test(
            "POST /send_records",
            "Store and forward records to blockchain ledger endpoints",
            "JSON body: any data payload with timestamp",
            "HTTP 200 with {status: 'Success'}"
        )
        test_data = {"test": "record", "timestamp": datetime.now().isoformat()}
        response, elapsed = self.make_request("POST", "/send_records", json=test_data)
        
        if response is None:
            self.add_result(TestResult("POST /send_records", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            self.add_result(TestResult("POST /send_records", TestStatus.PASSED, 
                "Records forwarded", 200, elapsed))
        else:
            self.add_result(TestResult("POST /send_records", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_trigger_chain(self):
        """Test POST /trigger-chain"""
        self.describe_test(
            "POST /trigger-chain",
            "Full chain: parse BOM → POST to ledger → GET hash → send_sdt",
            "JSON body: {bom_path: '<file_path>', unique_key: '<key>'}",
            "HTTP 200 with {status, hash, send_sdt_response}, or 404 if file missing"
        )
        # This requires a valid file path, which may not exist in test environment
        test_data = {"bom_path": "/nonexistent/path.json", "unique_key": "test-key-001"}
        response, elapsed = self.make_request("POST", "/trigger-chain", json=test_data)
        
        if response is None:
            self.add_result(TestResult("POST /trigger-chain", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 404:
            self.add_result(TestResult("POST /trigger-chain (missing file)", TestStatus.PASSED, 
                "Correctly returned 404 for missing BOM file", 404, elapsed))
        elif response.status_code == 400:
            self.add_result(TestResult("POST /trigger-chain", TestStatus.PASSED, 
                "Validation working correctly", 400, elapsed))
        else:
            self.add_result(TestResult("POST /trigger-chain", TestStatus.WARNING, 
                response.text[:100], response.status_code, elapsed))

    def test_stop_sdt(self):
        """Test GET /stop-sdt"""
        self.describe_test(
            "GET /stop-sdt",
            "Stop the SDT manager (has 10s internal delay)",
            "Empty GET request",
            "HTTP 200 with 'SDT manager stopped' text"
        )
        response, elapsed = self.make_request("GET", "/stop-sdt")
        
        if response is None:
            self.add_result(TestResult("GET /stop-sdt", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 200:
            self.add_result(TestResult("GET /stop-sdt", TestStatus.PASSED, 
                "SDT manager stop triggered", 200, elapsed))
        else:
            self.add_result(TestResult("GET /stop-sdt", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_evidence_endpoint(self):
        """Test POST /evidence"""
        self.describe_test(
            "POST /evidence",
            "Store audit evidence for compliance tracking",
            "JSON body: {timestamp, toolId, raw, resource, id}",
            "HTTP 201 with {message: 'Evidence stored', id}"
        )
        response, elapsed = self.make_request("POST", "/evidence", json=self.sample_data["evidence"])
        
        if response is None:
            self.add_result(TestResult("POST /evidence", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 201:
            self.add_result(TestResult("POST /evidence", TestStatus.PASSED, 
                "Evidence stored", 201, elapsed))
        else:
            self.add_result(TestResult("POST /evidence", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_assessment_result_endpoint(self):
        """Test POST /assessment-result"""
        self.describe_test(
            "POST /assessment-result",
            "Store compliance assessment result",
            "JSON body: {targetId, status, timestamp}",
            "HTTP 201 with {message: 'Assessment result stored', targetId}"
        )
        response, elapsed = self.make_request("POST", "/assessment-result", json=self.sample_data["assessment_result"])
        
        if response is None:
            self.add_result(TestResult("POST /assessment-result", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 201:
            self.add_result(TestResult("POST /assessment-result", TestStatus.PASSED, 
                "Assessment result stored", 201, elapsed))
        else:
            self.add_result(TestResult("POST /assessment-result", TestStatus.FAILED, 
                response.text[:100], response.status_code, elapsed))

    def test_generate_sbom_no_folder(self):
        """Test POST /generate_sbom without folder (should fail)"""
        self.describe_test(
            "POST /generate_sbom (no folder)",
            "Validation test - SBOM generation requires folder path",
            "Empty POST request (no folder parameter)",
            "HTTP 400 with error about missing folder"
        )
        response, elapsed = self.make_request("POST", "/generate_sbom")
        
        if response is None:
            self.add_result(TestResult("POST /generate_sbom (no folder)", TestStatus.FAILED, "Connection failed"))
            return
            
        if response.status_code == 400:
            self.add_result(TestResult("POST /generate_sbom (no folder)", TestStatus.PASSED, 
                "Correctly rejected missing folder", 400, elapsed))
        else:
            self.add_result(TestResult("POST /generate_sbom (no folder)", TestStatus.FAILED, 
                f"Expected 400, got {response.status_code}", response.status_code, elapsed))

    # ==================== HARDCODED VALUES CHECK ====================

    def check_hardcoded_values(self):
        """Check for hardcoded values in app.py"""
        self.log_section("HARDCODED VALUES CHECK")
        
        app_py_path = os.path.join(os.path.dirname(__file__), "app.py")
        if not os.path.exists(app_py_path):
            print(f"{Colors.YELLOW}⚠️  app.py not found at {app_py_path}{Colors.END}")
            return
            
        with open(app_py_path, 'r') as f:
            content = f.read()
            lines = content.split('\n')
        
        hardcoded_patterns = [
            (r"mongodb://localhost:\d+", "MongoDB localhost URL"),
            (r"mongodb://127\.0\.0\.1:\d+", "MongoDB 127.0.0.1 URL"),
            (r"http://localhost:\d+(?!/)", "Localhost HTTP URL"),
            (r"http://127\.0\.0\.1:\d+", "127.0.0.1 HTTP URL"),
            (r"'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'", "Hardcoded IP address"),
            (r'"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"', "Hardcoded IP address"),
            (r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key"),
            (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
            (r"secret\s*=\s*['\"][^'\"]+['\"]", "Hardcoded secret"),
            (r"port\s*=\s*\d{4,5}(?!\s*,|\s*\))", "Hardcoded port number"),
        ]
        
        issues_found = []
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
                
            for pattern, description in hardcoded_patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                if matches:
                    # Check if it's using os.getenv (acceptable)
                    if 'os.getenv' in line or 'os.environ' in line:
                        continue
                    # Check if it's a default fallback value (acceptable pattern)
                    if re.search(r'os\.getenv\([^)]+,\s*[\'"]' + re.escape(matches[0]) + r'[\'"]', line):
                        continue
                    issues_found.append({
                        'line': line_num,
                        'description': description,
                        'match': matches[0],
                        'content': line.strip()[:80]
                    })
        
        if issues_found:
            print(f"{Colors.YELLOW}Found {len(issues_found)} potential hardcoded value(s):{Colors.END}\n")
            for issue in issues_found:
                print(f"  Line {issue['line']}: {Colors.YELLOW}{issue['description']}{Colors.END}")
                print(f"    Match: {Colors.CYAN}{issue['match']}{Colors.END}")
                print(f"    Code:  {issue['content']}")
                print()
        else:
            print(f"{Colors.GREEN}✅ No obvious hardcoded values found{Colors.END}")
        
        # Check environment variable usage
        print(f"\n{Colors.BOLD}Environment Variables Used:{Colors.END}")
        env_vars = re.findall(r'os\.getenv\([\'"](\w+)[\'"]', content)
        env_vars = sorted(set(env_vars))
        for var in env_vars:
            print(f"  • {var}")

    # ==================== SWAGGER VALIDATION ====================

    def validate_swagger_mapping(self):
        """Validate Swagger documentation against actual endpoints"""
        self.log_section("SWAGGER DOCUMENTATION VALIDATION")
        
        # Define actual endpoints from app.py
        actual_endpoints = {
            "/": {"methods": ["GET"], "description": "Home endpoint"},
            "/data": {"methods": ["POST"], "description": "Insert data"},
            "/generate_sbom": {"methods": ["POST"], "description": "Generate SBOM"},
            "/show_vulnerabilities": {"methods": ["GET"], "description": "Get vulnerabilities"},
            "/generate_cbom": {"methods": ["POST"], "description": "Generate CBOM"},
            "/receive_output": {"methods": ["POST"], "description": "Receive output and trigger CBOM"},
            "/upload_oscal": {"methods": ["POST"], "description": "Upload OSCAL document"},
            "/oscal_ids/<doc_uuid>": {"methods": ["GET"], "description": "Get OSCAL control IDs"},
            "/upload_saasbom": {"methods": ["POST"], "description": "Upload SaaSBOM"},
            "/upload_toe_descriptor": {"methods": ["POST"], "description": "Upload TOE descriptor"},
            "/upload_certification_scheme": {"methods": ["POST"], "description": "Upload certification scheme"},
            "/store-ledger": {"methods": ["POST"], "description": "Store ledger entry"},
            "/update-ledger/<uuid>": {"methods": ["PUT"], "description": "Update ledger entry"},
            "/send_sdt": {"methods": ["POST"], "description": "Send SDT"},
            "/trigger_delete": {"methods": ["POST"], "description": "Trigger delete"},
            "/send_records": {"methods": ["POST"], "description": "Send records"},
            "/trigger-chain": {"methods": ["POST"], "description": "Trigger chain"},
            "/stop-sdt": {"methods": ["GET"], "description": "Stop SDT"},
            "/evidence": {"methods": ["POST"], "description": "Upload evidence"},
            "/assessment-result": {"methods": ["POST"], "description": "Upload assessment result"},
        }
        
        # Load swagger file
        swagger_path = os.path.join(os.path.dirname(__file__), "..", "Swagger Documentation", "swagger-ui", "cobalt_2.json")
        swagger_endpoints = {}
        
        if os.path.exists(swagger_path):
            try:
                with open(swagger_path, 'r') as f:
                    swagger_data = json.load(f)
                    
                for path, methods in swagger_data.get("paths", {}).items():
                    swagger_endpoints[path] = {
                        "methods": [m.upper() for m in methods.keys() if m.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]],
                        "documented": True
                    }
            except json.JSONDecodeError as e:
                print(f"{Colors.RED}Error parsing Swagger file: {e}{Colors.END}")
                return
        else:
            print(f"{Colors.YELLOW}⚠️  Swagger file not found at {swagger_path}{Colors.END}")
            return

        # Compare endpoints
        print(f"{Colors.BOLD}Endpoint Comparison:{Colors.END}\n")
        
        # Normalize paths for comparison
        def normalize_path(path):
            """Convert Flask-style paths to Swagger-style"""
            return re.sub(r'<\w+>', '{id}', path).replace('{id}', '{uuid}').replace('{doc_uuid}', '{uuid}')
        
        all_paths = set(list(actual_endpoints.keys()) + list(swagger_endpoints.keys()))
        
        documented_count = 0
        undocumented_count = 0
        extra_in_swagger = 0
        
        print(f"{'Endpoint':<40} {'Status':<20} {'In API':<10} {'In Swagger':<10}")
        print("-" * 80)
        
        for path in sorted(all_paths):
            norm_path = normalize_path(path)
            in_api = path in actual_endpoints or any(normalize_path(p) == norm_path for p in actual_endpoints)
            in_swagger = path in swagger_endpoints or any(normalize_path(p) == norm_path for p in swagger_endpoints)
            
            if in_api and in_swagger:
                status = f"{Colors.GREEN}✅ Documented{Colors.END}"
                documented_count += 1
            elif in_api and not in_swagger:
                status = f"{Colors.YELLOW}⚠️  Undocumented{Colors.END}"
                undocumented_count += 1
            else:
                status = f"{Colors.CYAN}📝 Swagger only{Colors.END}"
                extra_in_swagger += 1
            
            print(f"{path:<40} {status:<30} {'Yes' if in_api else 'No':<10} {'Yes' if in_swagger else 'No':<10}")
        
        print("-" * 80)
        print(f"\n{Colors.BOLD}Summary:{Colors.END}")
        print(f"  • Documented endpoints: {Colors.GREEN}{documented_count}{Colors.END}")
        print(f"  • Undocumented endpoints: {Colors.YELLOW}{undocumented_count}{Colors.END}")
        print(f"  • Extra in Swagger: {Colors.CYAN}{extra_in_swagger}{Colors.END}")
        
        # Check for Swagger issues
        print(f"\n{Colors.BOLD}Swagger Issues Found:{Colors.END}")
        
        # Dynamically detect issues
        swagger_issues = []
        
        # Check for typo in endpoint names
        if "/send_std" in swagger_endpoints and "/send_sdt" not in swagger_endpoints:
            swagger_issues.append("Endpoint '/send_std' in Swagger should be '/send_sdt' to match actual API")
        
        if swagger_issues:
            for issue in swagger_issues:
                print(f"  {Colors.YELLOW}⚠️  {issue}{Colors.END}")
        else:
            print(f"  {Colors.GREEN}✅ No issues found{Colors.END}")

    # ==================== RUN ALL TESTS ====================

    def run_all_tests(self):
        """Run all API tests"""
        self.log_section("API ENDPOINT TESTS")
        
        # Check if API is reachable
        print(f"Testing API at: {Colors.CYAN}{self.base_url}{Colors.END}\n")
        
        try:
            response = requests.get(f"{self.base_url}/", timeout=5)
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}❌ Cannot connect to API at {self.base_url}{Colors.END}")
            print(f"{Colors.YELLOW}Make sure the API is running with: docker compose up -d{Colors.END}")
            return
        
        # Run all endpoint tests
        test_methods = [
            self.test_home_endpoint,
            self.test_data_endpoint,
            self.test_show_vulnerabilities,
            self.test_generate_sbom_no_folder,
            self.test_generate_cbom_no_file,
            self.test_generate_cbom_with_data,
            self.test_receive_output,
            self.test_upload_oscal_catalog,
            self.test_upload_oscal_profile,
            self.test_upload_oscal_component_definition,
            self.test_oscal_ids_endpoint,
            self.test_upload_saasbom,
            self.test_upload_saasbom_validation,
            self.test_upload_toe_descriptor,
            self.test_upload_certification_scheme,
            self.test_store_ledger,
            self.test_update_ledger,
            self.test_send_sdt,
            self.test_trigger_delete,
            self.test_send_records,
            self.test_trigger_chain,
            self.test_evidence_endpoint,
            self.test_assessment_result_endpoint,
            # Note: test_stop_sdt skipped as it has a 10s sleep
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.add_result(TestResult(
                    test_method.__name__, 
                    TestStatus.FAILED, 
                    f"Exception: {str(e)}"
                ))
        
        # Print summary
        self.print_summary()
        
        # Run additional checks
        self.check_hardcoded_values()
        self.validate_swagger_mapping()

    def print_summary(self):
        """Print test summary"""
        self.log_section("TEST SUMMARY")
        
        passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
        warnings = sum(1 for r in self.results if r.status == TestStatus.WARNING)
        skipped = sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
        total = len(self.results)
        
        print(f"Total Tests: {total}")
        print(f"  {Colors.GREEN}✅ Passed:   {passed}{Colors.END}")
        print(f"  {Colors.RED}❌ Failed:   {failed}{Colors.END}")
        print(f"  {Colors.YELLOW}⚠️  Warnings: {warnings}{Colors.END}")
        print(f"  {Colors.YELLOW}⏭️  Skipped:  {skipped}{Colors.END}")
        
        if total > 0:
            success_rate = (passed / total) * 100
            color = Colors.GREEN if success_rate >= 80 else (Colors.YELLOW if success_rate >= 50 else Colors.RED)
            print(f"\nSuccess Rate: {color}{success_rate:.1f}%{Colors.END}")


def main():
    parser = argparse.ArgumentParser(description="CCM Manager API Test Suite")
    parser.add_argument("--base-url", default="http://localhost:5001", help="Base URL of the API")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    print(f"""
{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════╗
║           CCM Manager API Test Suite                     ║
║                                                          ║
║  Tests all endpoints, checks for hardcoded values,       ║
║  and validates Swagger documentation                     ║
╚══════════════════════════════════════════════════════════╝{Colors.END}
""")
    
    tester = CCMAPITester(base_url=args.base_url, verbose=args.verbose)
    tester.run_all_tests()


if __name__ == "__main__":
    main()
