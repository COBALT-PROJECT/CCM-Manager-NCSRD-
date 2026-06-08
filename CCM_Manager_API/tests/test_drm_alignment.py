#!/usr/bin/env python3
"""
DRM Alignment Validation Test
===============================
Based on the COBALT consortium email thread (Anjan/Natael/Alvaro, April 2026):

1. The DRM expects EXPLICIT R↔T↔C triplets — not derived combinations
2. Every metric must map to exactly one control (C↔M)
3. No orphan entities — all IDs in mappings must reference real entities
4. The export JSON must be self-contained for DRM ingestion
5. Re-upload must not create duplicates
6. R↔T↔C count must be ≤ |threats| × |controls| (not a full cartesian product)
"""
import json
import sys
import requests
from collections import defaultdict

BASE_URL = "http://localhost:5001"
SCHEME_ID = "AI_CLOUD_UC_v2"

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"

results = []

def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((name, status, detail))
    print(f"  {status} {name}" + (f" — {detail}" if detail else ""))
    return condition

def warn(name, detail=""):
    results.append((name, WARN, detail))
    print(f"  {WARN} {name}" + (f" — {detail}" if detail else ""))


def main():
    print("=" * 70)
    print("DRM ALIGNMENT VALIDATION")
    print("Based on COBALT consortium requirements (April 2026 emails)")
    print("=" * 70)

    # ── Fetch the export ─────────────────────────────────────────────
    print(f"\nFetching export for scheme '{SCHEME_ID}'...")
    r = requests.get(f"{BASE_URL}/schemes/{SCHEME_ID}/export")
    if r.status_code != 200:
        print(f"  {FAIL} Could not fetch export: {r.status_code} {r.text}")
        sys.exit(1)

    export = r.json()
    scheme   = export.get("scheme", {})
    risks    = export.get("risks", [])
    threats  = export.get("threats", [])
    metrics  = export.get("metrics", [])
    controls = export.get("controls", [])
    rtc      = export.get("risk_threat_control_mappings", [])
    cm       = export.get("control_metric_mappings", [])
    counts   = export.get("counts", {})

    print(f"  Scheme ID: {SCHEME_ID}")
    print(f"  Risks: {len(risks)}, Threats: {len(threats)}, Metrics: {len(metrics)}, Controls: {len(controls)}")
    print(f"  R↔T↔C mappings: {len(rtc)}, C↔M mappings: {len(cm)}")

    # ── TEST 1: Export structure has all required sections ────────────
    print(f"\n{'─'*70}")
    print("TEST 1: Export structure — DRM requires all these sections")
    print(f"{'─'*70}")
    required_keys = ["scheme", "risks", "threats", "metrics", "controls",
                     "risk_threat_control_mappings", "control_metric_mappings"]
    for key in required_keys:
        check(f"Export has '{key}'", key in export)

    # ── TEST 2: Entity ID uniqueness ─────────────────────────────────
    print(f"\n{'─'*70}")
    print("TEST 2: Entity ID uniqueness — no duplicate IDs")
    print(f"{'─'*70}")

    risk_ids   = [r.get("risk_id") for r in risks]
    threat_ids = [t.get("threat_id") for t in threats]
    metric_ids = [m.get("id") for m in metrics]

    check("Risk IDs unique",   len(risk_ids)   == len(set(risk_ids)),   f"{len(risk_ids)} total, {len(set(risk_ids))} unique")
    check("Threat IDs unique", len(threat_ids) == len(set(threat_ids)), f"{len(threat_ids)} total, {len(set(threat_ids))} unique")
    check("Metric IDs unique", len(metric_ids) == len(set(metric_ids)), f"{len(metric_ids)} total, {len(set(metric_ids))} unique")

    # ── TEST 3: Every metric has an associated_control ───────────────
    print(f"\n{'─'*70}")
    print("TEST 3: Every metric → control link (from email: 'C↔M is required')")
    print(f"{'─'*70}")

    metrics_without_control = []
    for m in metrics:
        ac = m.get("associated_control", {})
        if not ac.get("associated_control_requirement"):
            metrics_without_control.append(m.get("id"))

    check("All metrics have associated_control",
          len(metrics_without_control) == 0,
          f"{len(metrics_without_control)} missing" if metrics_without_control else f"all {len(metrics)} covered")

    if metrics_without_control:
        for mid in metrics_without_control[:5]:
            print(f"    → Missing control: {mid}")

    # ── TEST 4: C↔M mapping completeness ─────────────────────────────
    print(f"\n{'─'*70}")
    print("TEST 4: C↔M mapping collection matches compliance_metrics")
    print(f"{'─'*70}")

    cm_metric_ids = {m.get("metric_id") for m in cm}
    scheme_metric_ids = {m.get("id") for m in metrics}

    check("C↔M count matches metrics count",
          len(cm) == len(metrics),
          f"C↔M: {len(cm)}, Metrics: {len(metrics)}")

    missing_cm = scheme_metric_ids - cm_metric_ids
    check("Every metric has a C↔M mapping",
          len(missing_cm) == 0,
          f"{len(missing_cm)} missing" if missing_cm else "all covered")

    # Unique controls in C↔M
    cm_control_ids = {m.get("control_id") for m in cm}
    print(f"  ℹ️  Unique controls in C↔M: {len(cm_control_ids)}")

    # ── TEST 5: R↔T↔C referential integrity ──────────────────────────
    print(f"\n{'─'*70}")
    print("TEST 5: R↔T↔C referential integrity — all IDs must exist")
    print(f"{'─'*70}")

    risk_id_set   = set(risk_ids)
    threat_id_set = set(threat_ids)

    rtc_risk_ids    = {t.get("risk_id") for t in rtc}
    rtc_threat_ids  = {t.get("threat_id") for t in rtc}
    rtc_control_ids = {t.get("control_id") for t in rtc}

    orphan_risks = rtc_risk_ids - risk_id_set
    check("All R↔T↔C risk_ids exist in risks collection",
          len(orphan_risks) == 0,
          f"{len(orphan_risks)} orphans: {list(orphan_risks)[:3]}" if orphan_risks else "all valid")

    orphan_threats = rtc_threat_ids - threat_id_set
    check("All R↔T↔C threat_ids exist in threats collection",
          len(orphan_threats) == 0,
          f"{len(orphan_threats)} orphans: {list(orphan_threats)[:3]}" if orphan_threats else "all valid")

    orphan_controls = rtc_control_ids - cm_control_ids
    check("All R↔T↔C control_ids exist in C↔M mappings",
          len(orphan_controls) == 0,
          f"{len(orphan_controls)} orphans: {list(orphan_controls)[:3]}" if orphan_controls else "all valid")

    # ── TEST 6: R↔T↔C is NOT a full cartesian product ────────────────
    print(f"\n{'─'*70}")
    print("TEST 6: R↔T↔C is targeted, NOT a cartesian product")
    print("  (Natael's concern: DRM was creating all possible combinations)")
    print(f"{'─'*70}")

    max_possible = len(risk_id_set) * len(threat_id_set) * len(cm_control_ids)
    actual = len(rtc)
    ratio = (actual / max_possible * 100) if max_possible > 0 else 0

    check("R↔T↔C count < full cartesian product",
          actual < max_possible,
          f"Actual: {actual}, Max possible: {max_possible} ({ratio:.1f}%)")

    if ratio > 50:
        warn("R↔T↔C ratio is high",
             f"{ratio:.1f}% — may indicate too many derived combinations")

    # ── TEST 7: Every risk with threats has R↔T↔C entries ────────────
    print(f"\n{'─'*70}")
    print("TEST 7: Risks with threats should have R↔T↔C entries")
    print(f"{'─'*70}")

    risks_with_threats = [r for r in risks if r.get("mapped_threats")]
    risks_with_rtc = set(t.get("risk_id") for t in rtc)

    missing_rtc_risks = []
    for r in risks_with_threats:
        rid = r.get("risk_id")
        if rid not in risks_with_rtc:
            missing_rtc_risks.append(rid)

    check("All risks with threats have R↔T↔C entries",
          len(missing_rtc_risks) == 0,
          f"{len(missing_rtc_risks)} missing" if missing_rtc_risks else
          f"all {len(risks_with_threats)} covered")

    if missing_rtc_risks:
        for rid in missing_rtc_risks[:5]:
            print(f"    → Missing: {rid}")

    # ── TEST 8: Risks WITHOUT threats should NOT have R↔T↔C entries ──
    print(f"\n{'─'*70}")
    print("TEST 8: Risks without threats → no R↔T↔C (cannot form triplet)")
    print(f"{'─'*70}")

    risks_no_threats = [r.get("risk_id") for r in risks if not r.get("mapped_threats")]
    spurious = [rid for rid in risks_no_threats if rid in risks_with_rtc]

    check("No R↔T↔C for risks without threats",
          len(spurious) == 0,
          f"{len(spurious)} spurious" if spurious else
          f"{len(risks_no_threats)} threat-less risks correctly excluded")

    # ── TEST 9: No duplicate R↔T↔C triplets ──────────────────────────
    print(f"\n{'─'*70}")
    print("TEST 9: No duplicate R↔T↔C triplets")
    print(f"{'─'*70}")

    triplet_set = set()
    duplicates = 0
    for t in rtc:
        key = (t.get("risk_id"), t.get("threat_id"), t.get("control_id"))
        if key in triplet_set:
            duplicates += 1
        triplet_set.add(key)

    check("No duplicate R↔T↔C triplets",
          duplicates == 0,
          f"{duplicates} duplicates found" if duplicates else f"{len(rtc)} all unique")

    # ── TEST 10: mapped_risks reverse link ────────────────────────────
    print(f"\n{'─'*70}")
    print("TEST 10: Metrics with mapped_risks (new field in updated scheme)")
    print(f"{'─'*70}")

    metrics_with_mapped_risks = [m for m in metrics if m.get("mapped_risks")]
    print(f"  ℹ️  {len(metrics_with_mapped_risks)}/{len(metrics)} metrics have mapped_risks")

    # Check that mapped_risks reference valid risk_ids
    all_mapped_risk_refs = set()
    for m in metrics_with_mapped_risks:
        for rid in m.get("mapped_risks", []):
            all_mapped_risk_refs.add(rid)

    invalid_refs = all_mapped_risk_refs - risk_id_set
    check("All mapped_risks reference valid risk_ids",
          len(invalid_refs) == 0,
          f"{len(invalid_refs)} invalid: {list(invalid_refs)[:3]}" if invalid_refs else
          f"all {len(all_mapped_risk_refs)} references valid")

    # ── TEST 11: R↔T↔C breakdown per risk ────────────────────────────
    print(f"\n{'─'*70}")
    print("TEST 11: R↔T↔C distribution (should NOT be uniform = not cartesian)")
    print(f"{'─'*70}")

    rtc_per_risk = defaultdict(int)
    for t in rtc:
        rtc_per_risk[t.get("risk_id")] += 1

    for rid, count in sorted(rtc_per_risk.items(), key=lambda x: -x[1])[:10]:
        risk_name = next((r.get("risk_name", "?") for r in risks if r.get("risk_id") == rid), "?")
        n_threats = len([t for t in rtc if t.get("risk_id") == rid and t.get("threat_id")])
        unique_threats = len(set(t.get("threat_id") for t in rtc if t.get("risk_id") == rid))
        unique_controls = len(set(t.get("control_id") for t in rtc if t.get("risk_id") == rid))
        print(f"  {rid[:45]:45} → {count:3} triplets ({unique_threats}T × {unique_controls}C)")

    # ── SUMMARY ──────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    passed = sum(1 for _, s, _ in results if s == PASS)
    failed = sum(1 for _, s, _ in results if s == FAIL)
    warned = sum(1 for _, s, _ in results if s == WARN)
    print(f"RESULTS: {passed} passed, {failed} failed, {warned} warnings")
    print(f"{'='*70}")

    if failed:
        print("\nFailed checks:")
        for name, status, detail in results:
            if status == FAIL:
                print(f"  {FAIL} {name}: {detail}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
