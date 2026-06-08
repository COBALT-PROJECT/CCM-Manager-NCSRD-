import requests
import pymongo
import uuid

# 1. Test GET /sdts
print("--- Testing GET /sdts ---")
try:
    resp = requests.get("http://localhost:5001/sdts", timeout=5)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}\n")
except Exception as e:
    print(f"Failed to call /sdts: {e}\n")

# 2. Test PUT /certificates/<cert_uuid>/withdraw
print("--- Testing PUT /certificates/withdraw ---")
try:
    client = pymongo.MongoClient("mongodb://mongo:27017/")
    db = client.mydatabase
    cert_uuid = str(uuid.uuid4())
    dummy_cert = {
        "certification": {
            "certification_id": cert_uuid,
            "certification_decision": {
                "decision_status": "Granted"
            },
            "history": []
        }
    }
    db.certificates.insert_one(dummy_cert)
    print(f"Inserted dummy certificate with UUID: {cert_uuid}")
    
    # Call the API
    put_resp = requests.put(f"http://localhost:5001/certificates/{cert_uuid}/withdraw", timeout=5)
    print(f"API API Status Code: {put_resp.status_code}")
    print(f"API Response: {put_resp.text}")
    
    # Read back from DB
    updated_cert = db.certificates.find_one({"certification.certification_id": cert_uuid})
    status = updated_cert["certification"]["certification_decision"]["decision_status"]
    history = updated_cert["certification"]["history"]
    print(f"Verified from DB - Status: {status}")
    print(f"Verified from DB - History: {history}\n")
except Exception as e:
    print(f"Failed to test withdraw: {e}\n")
