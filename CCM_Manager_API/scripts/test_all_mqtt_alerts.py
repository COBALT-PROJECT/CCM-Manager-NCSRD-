#!/usr/bin/env python3
"""Test every MQTT failure-alert scenario through CCM's alert service.

The script does not call CCM's HTTP API and does not need an authentication
token. It imports the same ``publish_failure`` function used by CCM itself, so
configuration, payload sanitisation, topic selection, and MQTT publication all
follow the production CCM code path.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from uuid import uuid4


API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from services.mqtt_alert_service import publish_failure


ALERT_CASES = [
    {
        "name": "certification-scheme-ledger",
        "operation": "Publish certification scheme to blockchain",
        "message": "Blockchain ledger request failed",
        "details": {
            "service": "ledger",
            "endpoint": "/v1/certification-authority/certification-scheme",
            "exception_type": "ConnectTimeout",
            "error": "Synthetic test: blockchain ledger connection timed out",
            "scheme_id": "mqtt-test-scheme",
        },
    },
    {
        "name": "assessment-ledger",
        "operation": "Publish assessment result to blockchain",
        "message": "Blockchain ledger request failed",
        "details": {
            "service": "ledger",
            "endpoint": "/v1/manufacturer/ass-results",
            "exception_type": "ConnectionError",
            "error": "Synthetic test: blockchain ledger connection refused",
            "assessment_id": "mqtt-test-assessment",
            "toe_id": "mqtt-test-toe",
            "scheme_id": "mqtt-test-scheme",
        },
    },
    {
        "name": "certificate-ledger",
        "operation": "Publish certificate to blockchain",
        "message": "Blockchain ledger request failed",
        "details": {
            "service": "ledger",
            "endpoint": "/v1/certification-authority/certificate",
            "exception_type": "HTTPError",
            "error": "Synthetic test: blockchain ledger returned HTTP 500",
            "certificate_id": "mqtt-test-certificate",
            "toe_id": "mqtt-test-toe",
            "scheme_id": "mqtt-test-scheme",
            "certificate_operation": "created",
        },
    },
    {
        "name": "generic-ledger",
        "operation": "Send data to blockchain ledger",
        "message": "Blockchain ledger request failed",
        "details": {
            "service": "ledger",
            "endpoint": "/v1/test",
            "exception_type": "ConnectionError",
            "error": "Synthetic test: ledger unavailable",
        },
    },
    {
        "name": "toe-sbom-ledger",
        "operation": "Publish SBOM to blockchain",
        "message": "Blockchain ledger request failed",
        "details": {
            "service": "ledger",
            "endpoint": "/v1/manufacturer/sbom",
            "exception_type": "ConnectTimeout",
            "error": "Synthetic test: SBOM publication timed out",
            "toe_id": "mqtt-test-toe",
            "sbom_source": "bills-of-material.sbom",
        },
    },
    {
        "name": "toe-sbom-hash-missing",
        "operation": "Publish SBOM to blockchain",
        "message": "Blockchain response did not include an SBOM hash",
        "details": {
            "service": "ledger",
            "endpoint": "/v1/manufacturer/sbom",
            "toe_id": "mqtt-test-toe",
            "sbom_source": "bills-of-material.sbom",
        },
    },
    {
        "name": "bom-blockchain-publish",
        "operation": "Publish BOM to blockchain",
        "message": "Blockchain rejected or could not receive the BOM",
        "details": {
            "service": "ledger",
            "unique_key": "mqtt-test-bom-key",
            "exception_type": "HTTPError",
            "error": "Synthetic test: blockchain rejected the BOM",
        },
    },
    {
        "name": "bom-blockchain-hash",
        "operation": "Retrieve BOM hash from blockchain",
        "message": "Failed to retrieve the blockchain hash",
        "details": {
            "service": "ledger",
            "unique_key": "mqtt-test-bom-key",
            "exception_type": "ReadTimeout",
            "error": "Synthetic test: hash lookup timed out",
        },
    },
    {
        "name": "blockchain-bom-sdtm",
        "operation": "Send blockchain BOM to SDTM",
        "message": "Failed to pass the blockchain hash to SDTM",
        "details": {
            "service": "sdt",
            "unique_key": "mqtt-test-bom-key",
            "hash": "MQTT-TEST-HASH",
            "exception_type": "ConnectionError",
            "error": "Synthetic test: SDTM unavailable",
        },
    },
    {
        "name": "scheme-import-request",
        "operation": "Import certification scheme to orchestrator",
        "message": "Scheme import request failed",
        "details": {
            "service": "scheme_import",
            "scheme_id": "mqtt-test-scheme",
            "payload_mode": "scheme_content",
            "correlation_id": "mqtt-test-correlation",
            "exception_type": "ConnectTimeout",
            "error": "Synthetic test: scheme import timed out",
        },
    },
    {
        "name": "scheme-import-rejected",
        "operation": "Import certification scheme to orchestrator",
        "message": "Scheme import service rejected the certification scheme",
        "details": {
            "service": "scheme_import",
            "scheme_id": "mqtt-test-scheme",
            "payload_mode": "scheme_content",
            "correlation_id": "mqtt-test-correlation",
            "status_code": 500,
            "response": {"error": "Synthetic test: import rejected"},
        },
    },
    {
        "name": "drm-configuration",
        "operation": "Synchronize certification scheme to DRM",
        "message": "DRM synchronization is enabled but DRM_BASE_URL is not configured",
        "details": {
            "service": "drm",
            "scheme_id": "mqtt-test-scheme",
        },
    },
    {
        "name": "drm-rejected",
        "operation": "Synchronize certification scheme to DRM",
        "message": "DRM rejected part of the certification scheme synchronization",
        "details": {
            "service": "drm",
            "scheme_id": "mqtt-test-scheme",
            "path": "/controls",
            "status_code": 500,
            "response": {"error": "Synthetic test: DRM rejected the control"},
            "created_before_failure": {"metrics": 2, "controls": 0},
        },
    },
    {
        "name": "drm-unexpected",
        "operation": "Synchronize certification scheme to DRM",
        "message": "Unexpected DRM synchronization failure",
        "details": {
            "service": "drm",
            "scheme_id": "mqtt-test-scheme",
            "exception_type": "RuntimeError",
            "error": "Synthetic test: unexpected DRM failure",
            "created_before_failure": {"metrics": 2, "controls": 1},
        },
    },
    {
        "name": "toe-orchestrator-rejected",
        "operation": "Forward ToE to orchestrator",
        "message": "Orchestrator rejected the ToE descriptor",
        "details": {
            "service": "orchestrator",
            "toe_id": "mqtt-test-toe",
            "scheme_id": "mqtt-test-scheme",
            "status_code": 500,
        },
    },
    {
        "name": "toe-orchestrator-request",
        "operation": "Forward ToE to orchestrator",
        "message": "Failed to forward the ToE descriptor",
        "details": {
            "service": "orchestrator",
            "toe_id": "mqtt-test-toe",
            "scheme_id": "mqtt-test-scheme",
            "exception_type": "ConnectionError",
            "error": "Synthetic test: orchestrator connection refused",
        },
    },
    {
        "name": "toe-sdtm-sync",
        "operation": "Synchronize ToE to SDTM",
        "message": "Unexpected failure while synchronizing the ToE to SDTM",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "scheme_id": "mqtt-test-scheme",
            "exception_type": "RuntimeError",
            "error": "Synthetic test: ToE synchronization failed",
        },
    },
    {
        "name": "toe-handoff-schedule",
        "operation": "Schedule ToE ID handoff",
        "message": "Failed to schedule the ToE ID handoff workflow",
        "details": {
            "service": "toe_connector",
            "toe_id": "mqtt-test-toe",
            "exception_type": "DatabaseError",
            "error": "Synthetic test: workflow job could not be scheduled",
        },
    },
    {
        "name": "toe-handoff-retry",
        "operation": "Handoff ToE ID to connector",
        "message": "ToE connector handoff failed and was scheduled for retry",
        "details": {
            "service": "toe_connector",
            "toe_id": "mqtt-test-toe",
            "phase": "health",
            "status_code": 503,
            "attempt": 1,
            "next_run_at": "2026-09-16T16:00:30+00:00",
            "error": "Synthetic test: connector health check returned HTTP 503",
        },
    },
    {
        "name": "sdt-id-sync-retry",
        "operation": "Synchronize SDT IDs",
        "message": "SDT ID synchronization failed and was scheduled for retry",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "status_code": 502,
            "attempt": 1,
            "next_run_at": "2026-09-16T16:00:30+00:00",
            "error": "Synthetic test: SDT ID synchronization returned HTTP 502",
        },
    },
    {
        "name": "toe-worker-unexpected",
        "operation": "Process ToE background workflow",
        "message": "Unexpected ToE workflow worker failure; the job will retry after its lease expires",
        "details": {
            "service": "toe_workflow_worker",
            "toe_id": "mqtt-test-toe",
            "worker_id": "mqtt-test-worker",
            "exception_type": "RuntimeError",
            "error": "Synthetic test: unexpected worker failure",
        },
    },
    {
        "name": "sdt-deploy-configuration",
        "operation": "Deploy SDT instance",
        "message": "SDTM digital twin endpoint is not configured",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "hash": "MQTT-TEST-HASH",
        },
    },
    {
        "name": "sdt-deploy-request",
        "operation": "Deploy SDT instance",
        "message": "Failed to deploy SDT instance",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "hash": "MQTT-TEST-HASH",
            "exception_type": "ConnectTimeout",
            "error": "Synthetic test: SDTM deployment timed out",
        },
    },
    {
        "name": "sdt-adapt-configuration",
        "operation": "Adapt BOM in SDTM",
        "message": "SDTM adapt endpoint is not configured",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "hash": "MQTT-TEST-HASH",
        },
    },
    {
        "name": "sdt-adapt-request",
        "operation": "Adapt BOM in SDTM",
        "message": "SDTM adapt request failed",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "hash": "MQTT-TEST-HASH",
            "payload_type": "BOMS",
            "exception_type": "HTTPError",
            "error": "Synthetic test: SDTM adapt returned HTTP 500",
        },
    },
    {
        "name": "sdt-list-deployments",
        "operation": "List SDTM deployments",
        "message": "Failed to list SDTM deployments after deployment",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "twin_id": "mqtt-test-twin",
            "exception_type": "ReadTimeout",
            "error": "Synthetic test: deployments request timed out",
        },
    },
    {
        "name": "sdt-retrieve-instance",
        "operation": "Retrieve deployed SDT instance",
        "message": "Failed to retrieve the deployed SDT instance",
        "details": {
            "service": "sdt",
            "toe_id": "mqtt-test-toe",
            "twin_id": "mqtt-test-twin",
            "exception_type": "HTTPError",
            "error": "Synthetic test: deployed SDT returned HTTP 500",
        },
    },
    {
        "name": "sdt-auth-status",
        "operation": "Retrieve SDTM authentication status",
        "message": "Failed to retrieve authentication status for an SDT instance",
        "details": {
            "service": "sdt",
            "twin_id": "mqtt-test-twin",
            "exception_type": "ConnectionError",
            "error": "Synthetic test: authentication status unavailable",
        },
    },
    {
        "name": "sdt-delete",
        "operation": "Delete SDT instance",
        "message": "SDTM rejected the delete request",
        "details": {
            "service": "sdt",
            "twin_id": "mqtt-test-twin",
            "status_code": 500,
            "response": {"error": "Synthetic test: delete rejected"},
        },
    },
    {
        "name": "artifact-forward-rejected",
        "operation": "Forward artifact record",
        "message": "Artifact destination rejected the forwarded record",
        "details": {
            "service": "artifact_forwarder",
            "destination": "http://mqtt-test-destination.invalid/artifacts",
            "status_code": 500,
        },
    },
    {
        "name": "artifact-forward-request",
        "operation": "Forward artifact record",
        "message": "Failed to forward an artifact record",
        "details": {
            "service": "artifact_forwarder",
            "destination": "http://mqtt-test-destination.invalid/artifacts",
            "exception_type": "ConnectionError",
            "error": "Synthetic test: artifact destination unavailable",
        },
    },
    {
        "name": "certificate-pdf",
        "operation": "Generate certificate PDF",
        "message": "Failed to regenerate the certificate PDF",
        "details": {
            "certificate_id": "mqtt-test-certificate",
            "toe_id": "mqtt-test-toe",
            "scheme_id": "mqtt-test-scheme",
            "exception_type": "OSError",
            "error": "Synthetic test: certificate PDF could not be written",
        },
    },
    {
        "name": "catalogue-initialization",
        "operation": "Initialize CCM catalogue",
        "message": "Failed to initialize a configured catalogue",
        "details": {
            "catalogue_path": "/app/data/mqtt-test-catalogue.json",
            "exception_type": "FileNotFoundError",
            "error": "Synthetic test: catalogue file was not found",
        },
    },
    {
        "name": "generic-http-500",
        "operation": "POST /mqtt-test-endpoint",
        "message": "Synthetic test: CCM endpoint returned HTTP 500",
        "details": {
            "request_id": "mqtt-test-request",
            "method": "POST",
            "path": "/mqtt-test-endpoint",
            "status_code": 500,
        },
    },
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run every MQTT failure-alert scenario through CCM."
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish the synthetic alerts through CCM. Without this flag, only list them.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the alert catalogue without publishing.",
    )
    parser.add_argument(
        "--filter",
        default="",
        help="Run only cases whose name, operation, or message contains this text.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Seconds to wait between published alerts (default: 0.2).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    needle = args.filter.casefold().strip()
    cases = [
        case
        for case in ALERT_CASES
        if not needle
        or needle
        in " ".join(
            (case["name"], case["operation"], case["message"])
        ).casefold()
    ]

    if not cases:
        print("No MQTT alert cases matched the filter.", file=sys.stderr)
        return 2

    if not args.publish or args.list:
        for index, case in enumerate(cases, start=1):
            print(
                f"{index:02d}. {case['name']}: {case['operation']} — "
                f"{case['message']}"
            )
        print(f"\n{len(cases)} alert case(s)")
        if not args.publish:
            return 0

    delay_seconds = min(max(args.delay, 0.0), 2.0)
    run_id = f"mqtt-alert-test-{uuid4()}"
    results = []

    for index, case in enumerate(cases, start=1):
        event_id = f"failure-test-{run_id}-{index:02d}"
        details = {
            **case["details"],
            "synthetic_test": True,
            "test_run_id": run_id,
            "test_case": case["name"],
            "sequence": index,
            "total": len(cases),
        }
        result = publish_failure(
            operation=case["operation"],
            message=case["message"],
            details=details,
            event_id=event_id,
        )
        result = {
            "name": case["name"],
            "operation": case["operation"],
            **result,
        }
        results.append(result)
        print(
            f"[{index:02d}/{len(cases):02d}] {case['name']}: "
            f"{result.get('status', 'unknown')}"
        )
        if result.get("error"):
            print(f"  error: {result['error']}")
        if index < len(cases) and delay_seconds:
            time.sleep(delay_seconds)

    published = sum(result.get("status") == "published" for result in results)
    summary = {
        "test_run_id": run_id,
        "requested": len(cases),
        "published": published,
        "failed": len(cases) - published,
        "synthetic_test": True,
        "results": results,
    }
    print("\n" + json.dumps(summary, indent=2, ensure_ascii=False))

    if published != len(cases):
        if any(result.get("status") == "disabled" for result in results):
            print(
                "\nMQTT alerts are disabled. Set MQTT_ALERTS_ENABLED=true "
                "in CCM's environment and run the command again.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
