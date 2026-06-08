#!/usr/bin/env python3
"""
Test script: upload the updated AI_Certification_Scheme 1.json
and verify that all collections are populated correctly.
"""
import json
import requests

BASE_URL = "http://localhost:5001"
SCHEME_FILE = "/home/localadmin/CCM-Manager-NCSRD-/AI Use Case/Certification Scheme/AI_Certification_Scheme 1.json"

def test():
    # Load the scheme JSON
    with open(SCHEME_FILE) as f:
        scheme_data = json.load(f)

    # Wrap it in the API format (certificationScheme wrapper)
    payload = {
        "certificationScheme": {
            "id": "AI_CLOUD_UC_v2",
            "compliance_metrics": scheme_data.get("compliance_metrics", []),
            "certifiable_standards_mapping": scheme_data.get("certifiable_standards_mapping", []),
            "boundary_conditions": scheme_data.get("boundary_conditions", {}),
            "risk_catalogue": scheme_data.get("risk_catalogue", []),
            "productProfile": scheme_data.get("productProfile", {}),
        },
        "profile": scheme_data.get("profile", {}),
        "catalog": scheme_data.get("catalog", {}),
        "controls": scheme_data.get("controls", []),
    }

    print(f"=== Uploading scheme with {len(payload['certificationScheme']['compliance_metrics'])} metrics, "
          f"{len(payload['certificationScheme']['risk_catalogue'])} risks, "
          f"{len(payload.get('controls', []))} controls ===\n")

    # Upload
    resp = requests.post(f"{BASE_URL}/upload_certification_scheme", json=payload, timeout=30)
    print(f"POST /upload_certification_scheme -> {resp.status_code}")
    result = resp.json()
    print(json.dumps(result, indent=2))
    
    if resp.status_code != 200:
        print("❌ Upload failed!")
        return

    scheme_id = result["uuid"]

    # Check entity collections
    print(f"\n=== Verifying collections for scheme '{scheme_id}' ===\n")

    for endpoint, label in [
        ("/metrics", "Metrics"),
        ("/risks", "Risks"),
        ("/threats", "Threats"),
        ("/controls", "Controls"),
    ]:
        r = requests.get(f"{BASE_URL}{endpoint}")
        data = r.json()
        count = len(data) if isinstance(data, list) else "error"
        print(f"  {label}: {count}")

    # Check mapping collections
    for endpoint, label in [
        (f"/schemes/{scheme_id}/mappings/cm", "C↔M Mappings"),
        (f"/schemes/{scheme_id}/mappings/rtc", "R↔T↔C Mappings"),
    ]:
        r = requests.get(f"{BASE_URL}{endpoint}")
        data = r.json()
        print(f"  {label}: {data.get('count', 'error')}")

    # Check export
    print(f"\n=== Export endpoint ===\n")
    r = requests.get(f"{BASE_URL}/schemes/{scheme_id}/export")
    export = r.json()
    if "counts" in export:
        print(json.dumps(export["counts"], indent=2))
    else:
        print(f"Export error: {export}")

    # Re-upload to verify no duplicates
    print(f"\n=== Re-uploading to verify no duplicates ===\n")
    resp2 = requests.post(f"{BASE_URL}/upload_certification_scheme", json=payload, timeout=30)
    result2 = resp2.json()
    print(f"POST /upload_certification_scheme -> {resp2.status_code}")
    print(f"Populated: {json.dumps(result2.get('populated', {}), indent=2)}")

    # Verify counts haven't doubled
    r2 = requests.get(f"{BASE_URL}/schemes/{scheme_id}/mappings/cm")
    cm_count = r2.json().get("count", 0)
    r3 = requests.get(f"{BASE_URL}/schemes/{scheme_id}/mappings/rtc")
    rtc_count = r3.json().get("count", 0)
    print(f"\n  C↔M after re-upload: {cm_count} (should be same as first upload)")
    print(f"  R↔T↔C after re-upload: {rtc_count} (should be same as first upload)")

    print("\n✅ Done!")

if __name__ == "__main__":
    test()
