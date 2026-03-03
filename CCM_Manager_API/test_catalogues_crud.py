import requests
import json
import uuid

BASE_URL = "http://localhost:5001"
HEADERS = {"Content-Type": "application/json"}

def print_result(success, message):
    if success:
        print(f"✅ SUCCESS: {message}")
    else:
        print(f"❌ FAILED: {message}")

def test_endpoint_pair(entity_name, list_endpoint, single_endpoint_prefix, test_payload, id_code):
    print(f"\n--- Testing {entity_name} Endpoints ---")
    
    # 1. POST (Create)
    print(f"Testing POST /{list_endpoint}...")
    post_url = f"{BASE_URL}/{list_endpoint}"
    try:
        response = requests.post(post_url, headers=HEADERS, json=test_payload)
        status = response.status_code
        if status in [200, 201]:
            print_result(True, f"Created {entity_name} successfully.")
        else:
            print_result(False, f"POST returned {status} - {response.text}")
            return
    except Exception as e:
        print_result(False, f"POST exception: {e}")
        return

    # 2. GET (All)
    print(f"Testing GET /{list_endpoint}...")
    try:
        response = requests.get(post_url)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                print_result(True, f"Retrieved list of {len(data)} {entity_name}.")
            else:
                print_result(False, "GET returned empty list or non-list.")
        else:
            print_result(False, f"GET returned {response.status_code}")
    except Exception as e:
        print_result(False, f"GET exception: {e}")

    # 3. GET (Single)
    target_id = test_payload.get(id_code)
    print(f"Testing GET /{list_endpoint}/{target_id}...")
    single_url = f"{BASE_URL}/{list_endpoint}/{target_id}"
    try:
        response = requests.get(single_url)
        if response.status_code == 200:
            item = response.json()
            if item.get(id_code) == target_id:
                print_result(True, f"Retrieved specific {entity_name} matching ID '{target_id}'.")
            else:
                print_result(False, f"Retrieved item ID doesn't match expected '{target_id}'")
        else:
            print_result(False, f"GET single returned {response.status_code}")
    except Exception as e:
        print_result(False, f"GET single exception: {e}")

if __name__ == "__main__":
    print("Starting Comprehensive API Tests...")

    # Unique IDs for test items to avoid collision with existing data
    test_run_id = str(uuid.uuid4())[:8]

    # Metrics
    metric_id = f"TEST_METRIC_{test_run_id}"
    metric_payload = {
        "id": metric_id,
        "name": "Test Metric Initialization",
        "description": "A dummy metric created by the test script.",
        "version": "1.0",
        "target_values": {"target_value": "100", "target_value_scale": "Integer"}
    }
    test_endpoint_pair("Metrics", "metrics", "metrics", metric_payload, "id")

    # Risks
    risk_id = f"TEST_RISK_{test_run_id}"
    risk_payload = {
        "risk_id": risk_id,
        "risk_name": "Test Risk Case",
        "risk_category": "Test Operational",
        "risk_details": "Simulated risk testing payload."
    }
    test_endpoint_pair("Risks", "risks", "risks", risk_payload, "risk_id")

    # Threats
    threat_id = f"TEST_THREAT_{test_run_id}"
    threat_payload = {
        "threat_id": threat_id,
        "name": "Test Threat Execution",
        "associated_risk_id": risk_id
    }
    test_endpoint_pair("Threats", "threats", "threats", threat_payload, "threat_id")

    # Controls
    control_id = f"TEST_CONTROL_{test_run_id}"
    control_payload = {
        "control_id": control_id,
        "metric_id": metric_id,
        "standard": "Test Standard",
        "description": "Automated control testing description."
    }
    test_endpoint_pair("Controls", "controls", "controls", control_payload, "control_id")

    print("\n--- Testing Complete ---")
