#!/usr/bin/env python3
"""
CAB Workflow Test
==================
Simulates a Certification Authority Body (CAB) adding new entities
and mappings through the API, as described in the COBALT emails:

- CAB can add new risks, threats, controls, metrics
- CAB can define explicit R↔T↔C mappings
- CAB can define explicit C↔M mappings
- UCO proposes amendments (new risks/threats); CAB validates
- All additions must appear in the export
- No duplicates on re-add
"""
import json
import sys
import requests

BASE_URL = "http://localhost:5001"
SCHEME_ID = "AI_CLOUD_UC_v2"

PASS = "✅ PASS"
FAIL = "❌ FAIL"

results = []

def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((name, status, detail))
    print(f"  {status} {name}" + (f" — {detail}" if detail else ""))
    return condition


def main():
    print("=" * 70)
    print("CAB WORKFLOW TEST")
    print("Simulating Certification Authority operations")
    print("=" * 70)

    # ── Baseline: get current counts ─────────────────────────────────
    print("\n📋 Getting baseline counts...")
    r = requests.get(f"{BASE_URL}/schemes/{SCHEME_ID}/export")
    if r.status_code != 200:
        print(f"  {FAIL} Cannot fetch export. Upload the scheme first.")
        return 1
    baseline = r.json().get("counts", {})
    print(f"  Risks: {baseline['risks']}, Threats: {baseline['threats']}, "
          f"Metrics: {baseline['metrics']}, Controls: {baseline['controls']}")
    print(f"  R↔T↔C: {baseline['rtc_mappings']}, C↔M: {baseline['cm_mappings']}")

    # ── STEP 1: CAB adds a new risk ──────────────────────────────────
    print(f"\n{'─'*70}")
    print("STEP 1: CAB adds a new risk")
    print(f"{'─'*70}")

    new_risk = {
        "risk_id": "#CABTest_Risk_SupplyChain",
        "risk_name": "Supply Chain Compromise",
        "risk_details": "Risk of compromised AI model supply chain components",
        "risk_category": "Operational",
        "associated_framework": "COBALT AI Framework",
        "mapped_threats": [
            {"threat_id": "#CABTest_Threat_MaliciousLib", "name": "Malicious Library Injection"},
            {"threat_id": "#CABTest_Threat_DataTampering", "name": "Training Data Tampering"}
        ],
        "mapped_metrics": [
            {"metric_id": "RestrictLibraryLoading_AIModelClassification_43", "impact": "High"}
        ],
        "scheme_id": SCHEME_ID
    }

    r = requests.post(f"{BASE_URL}/risks", json=new_risk)
    check("POST /risks → new risk created",
          r.status_code == 201,
          f"Status: {r.status_code}, {r.json().get('message', r.text)}")

    # Verify it's retrievable
    r = requests.get(f"{BASE_URL}/risks/{new_risk['risk_id']}")
    check("GET /risks/<id> → risk retrievable",
          r.status_code == 200 and r.json().get("risk_id") == new_risk["risk_id"])

    # ── STEP 2: CAB adds new threats ─────────────────────────────────
    print(f"\n{'─'*70}")
    print("STEP 2: CAB adds new threats")
    print(f"{'─'*70}")

    new_threats = [
        {
            "threat_id": "#CABTest_Threat_MaliciousLib",
            "name": "Malicious Library Injection",
            "associated_risk_id": "#CABTest_Risk_SupplyChain",
            "scheme_id": SCHEME_ID
        },
        {
            "threat_id": "#CABTest_Threat_DataTampering",
            "name": "Training Data Tampering",
            "associated_risk_id": "#CABTest_Risk_SupplyChain",
            "scheme_id": SCHEME_ID
        }
    ]

    r = requests.post(f"{BASE_URL}/threats", json=new_threats)
    check("POST /threats → 2 threats created (bulk)",
          r.status_code == 201,
          r.json().get("message", r.text))

    # Verify each
    for t in new_threats:
        r = requests.get(f"{BASE_URL}/threats/{t['threat_id']}")
        check(f"GET /threats/{t['threat_id'][:30]}... → retrievable",
              r.status_code == 200)

    # ── STEP 3: CAB adds a new metric ────────────────────────────────
    print(f"\n{'─'*70}")
    print("STEP 3: CAB adds a new metric")
    print(f"{'─'*70}")

    new_metric = {
        "id": "CABTest_SupplyChainVerification_1.0",
        "name": "Supply Chain Verification Check",
        "description": "Verifies integrity of AI model supply chain artifacts",
        "version": "1.0",
        "information_need": "Supply chain component integrity",
        "implementation_evidence": "Signed artifact verification logs",
        "frequency": 24,
        "data_source_type": "CI/CD pipeline",
        "reporting_format": "JSON",
        "target_values": {
            "target_value_scale": "binary",
            "target_value": "true"
        },
        "associated_control": {
            "associated_control_framework": "COBALT",
            "associated_control_category": "Supply Chain Security",
            "associated_control_requirement": "#ORControl_SupplyChain"
        },
        "scheme_id": SCHEME_ID
    }

    r = requests.post(f"{BASE_URL}/metrics", json=new_metric)
    check("POST /metrics → new metric created",
          r.status_code == 201,
          r.json().get("message", r.text))

    r = requests.get(f"{BASE_URL}/metrics/{new_metric['id']}")
    check("GET /metrics/<id> → metric retrievable",
          r.status_code == 200)

    # ── STEP 4: CAB adds a new control ───────────────────────────────
    print(f"\n{'─'*70}")
    print("STEP 4: CAB adds a new control")
    print(f"{'─'*70}")

    new_control = {
        "control_id": "Supply Chain Security",
        "name": "Supply Chain Security",
        "description": "Verifies integrity of AI model supply chain",
        "metric_id": "CABTest_SupplyChainVerification_1.0",
        "standard": "COBALT",
        "oscal_id": "cobalt-OR.ORControl_SupplyChain_baseline_req.1",
        "scheme_id": SCHEME_ID
    }

    r = requests.post(f"{BASE_URL}/controls", json=new_control)
    check("POST /controls → new control created",
          r.status_code == 201,
          r.json().get("message", r.text))

    # ── STEP 5: CAB adds explicit R↔T↔C mappings ────────────────────
    print(f"\n{'─'*70}")
    print("STEP 5: CAB adds explicit R↔T↔C mappings for the new risk")
    print(f"{'─'*70}")

    # First get existing mappings
    r = requests.get(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/rtc")
    existing_rtc = r.json().get("mappings", [])
    existing_count = len(existing_rtc)

    # Add the new risk's triplets to existing ones
    new_rtc = [
        {
            "risk_id": "#CABTest_Risk_SupplyChain",
            "threat_id": "#CABTest_Threat_MaliciousLib",
            "control_id": "#ORControl_SupplyChain"
        },
        {
            "risk_id": "#CABTest_Risk_SupplyChain",
            "threat_id": "#CABTest_Threat_DataTampering",
            "control_id": "#ORControl_SupplyChain"
        },
    ]

    # POST replaces ALL, so append to existing
    combined_rtc = []
    for m in existing_rtc:
        combined_rtc.append({
            "risk_id": m["risk_id"],
            "threat_id": m["threat_id"],
            "control_id": m["control_id"],
        })
    combined_rtc.extend(new_rtc)

    r = requests.post(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/rtc", json=combined_rtc)
    check("POST /schemes/<id>/mappings/rtc → updated",
          r.status_code == 201,
          r.json().get("message", r.text))

    # Verify count increased
    r = requests.get(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/rtc")
    new_count = r.json().get("count", 0)
    check("R↔T↔C count increased by 2",
          new_count == existing_count + 2,
          f"Was {existing_count}, now {new_count}")

    # ── STEP 6: CAB adds explicit C↔M mapping ───────────────────────
    print(f"\n{'─'*70}")
    print("STEP 6: CAB adds C↔M mapping for the new metric")
    print(f"{'─'*70}")

    r = requests.get(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/cm")
    existing_cm = r.json().get("mappings", [])
    existing_cm_count = len(existing_cm)

    new_cm_entry = {
        "control_id": "#ORControl_SupplyChain",
        "metric_id": "CABTest_SupplyChainVerification_1.0"
    }

    combined_cm = []
    for m in existing_cm:
        combined_cm.append({
            "control_id": m["control_id"],
            "metric_id": m["metric_id"],
        })
    combined_cm.append(new_cm_entry)

    r = requests.post(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/cm", json=combined_cm)
    check("POST /schemes/<id>/mappings/cm → updated",
          r.status_code == 201,
          r.json().get("message", r.text))

    r = requests.get(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/cm")
    new_cm_count = r.json().get("count", 0)
    check("C↔M count increased by 1",
          new_cm_count == existing_cm_count + 1,
          f"Was {existing_cm_count}, now {new_cm_count}")

    # ── STEP 7: Verify everything appears in export ──────────────────
    print(f"\n{'─'*70}")
    print("STEP 7: Verify new entities appear in export")
    print(f"{'─'*70}")

    r = requests.get(f"{BASE_URL}/schemes/{SCHEME_ID}/export")
    export = r.json()

    # Check new R↔T↔C
    rtc_triplets = export.get("risk_threat_control_mappings", [])
    new_triplets = [t for t in rtc_triplets if t.get("risk_id") == "#CABTest_Risk_SupplyChain"]
    check("New risk's R↔T↔C triplets in export",
          len(new_triplets) == 2,
          f"Found {len(new_triplets)} (expected 2)")

    # Check new C↔M
    cm_mappings = export.get("control_metric_mappings", [])
    new_cm = [m for m in cm_mappings if m.get("metric_id") == "CABTest_SupplyChainVerification_1.0"]
    check("New metric's C↔M mapping in export",
          len(new_cm) == 1,
          f"Found {len(new_cm)} (expected 1)")

    print(f"\n  Updated export counts:")
    for k, v in export.get("counts", {}).items():
        delta = v - baseline.get(k, 0)
        arrow = f" (+{delta})" if delta > 0 else ""
        print(f"    {k}: {v}{arrow}")

    # ── STEP 8: Re-add same entities — no duplicates ─────────────────
    print(f"\n{'─'*70}")
    print("STEP 8: Re-add same risk (upsert) — no duplicates")
    print(f"{'─'*70}")

    r = requests.post(f"{BASE_URL}/risks", json=new_risk)
    check("POST /risks with same risk_id → upsert (not duplicate)",
          r.status_code == 201)

    # Count risks with this ID
    r = requests.get(f"{BASE_URL}/risks")
    all_risks = r.json()
    matching = [r for r in all_risks if r.get("risk_id") == "#CABTest_Risk_SupplyChain"]
    check("Only 1 copy of the risk exists",
          len(matching) == 1,
          f"Found {len(matching)}")

    # ── STEP 9: DRM sync endpoint responds correctly ─────────────────
    print(f"\n{'─'*70}")
    print("STEP 9: DRM sync endpoint (should fail gracefully — no DRM_BASE_URL)")
    print(f"{'─'*70}")

    r = requests.post(f"{BASE_URL}/schemes/{SCHEME_ID}/sync-drm")
    check("POST /sync-drm → 503 (DRM not configured)",
          r.status_code == 503,
          r.json().get("error", r.text))

    # ── CLEANUP: Remove test entities ────────────────────────────────
    print(f"\n{'─'*70}")
    print("CLEANUP: Removing test entities...")
    print(f"{'─'*70}")

    # Remove test mappings (restore original)
    orig_rtc = [t for t in combined_rtc if not t.get("risk_id", "").startswith("#CABTest")]
    r = requests.post(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/rtc", json=orig_rtc)
    print(f"  R↔T↔C restored to {len(orig_rtc)} (removed {len(combined_rtc) - len(orig_rtc)} test entries)")

    orig_cm = [m for m in combined_cm if not m.get("metric_id", "").startswith("CABTest")]
    r = requests.post(f"{BASE_URL}/schemes/{SCHEME_ID}/mappings/cm", json=orig_cm)
    print(f"  C↔M restored to {len(orig_cm)} (removed {len(combined_cm) - len(orig_cm)} test entries)")

    # Note: individual entity cleanup would need DELETE endpoints (not implemented)
    print(f"  ⚠️  Test risk/threat/metric/control left in DB (no DELETE endpoints yet)")

    # ── SUMMARY ──────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    passed = sum(1 for _, s, _ in results if s == PASS)
    failed = sum(1 for _, s, _ in results if s == FAIL)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'='*70}")

    if failed:
        print("\nFailed checks:")
        for name, status, detail in results:
            if status == FAIL:
                print(f"  {FAIL} {name}: {detail}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
