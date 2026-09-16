#!/usr/bin/env python3
"""Ask a running CCM instance to test every MQTT failure-alert scenario.

The script never connects to MQTT itself. It calls CCM's guarded internal test
endpoint, and the running CCM process publishes the synthetic failure alerts.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests


API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))


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
        help="Ask CCM to publish the synthetic alerts. Without this flag, list them through CCM.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the alert catalogue through CCM without publishing.",
    )
    parser.add_argument(
        "--filter",
        default="",
        help="Run only cases whose name, operation, or message contains this text.",
    )
    parser.add_argument(
        "--ccm-url",
        default=os.getenv("CCM_API_BASE_URL", "http://localhost:5001"),
        help="Base URL of the running CCM API.",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("CCM_MQTT_TEST_TOKEN", ""),
        help="Token configured as CCM_MQTT_TEST_TOKEN on the CCM server.",
    )
    parser.add_argument(
        "--bearer-token",
        default=os.getenv("CCM_API_BEARER_TOKEN", ""),
        help="Optional bearer token when CCM inbound authentication is enabled.",
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
    if not args.token:
        print(
            "CCM MQTT test token is required. Pass --token or set "
            "CCM_MQTT_TEST_TOKEN.",
            file=sys.stderr,
        )
        return 2

    endpoint = f"{args.ccm_url.rstrip('/')}/internal/test/mqtt-alerts"
    headers = {
        "Accept": "application/json",
        "X-CCM-MQTT-Test-Token": args.token,
    }
    if args.bearer_token:
        headers["Authorization"] = f"Bearer {args.bearer_token}"

    try:
        if args.publish:
            response = requests.post(
                endpoint,
                headers=headers,
                json={
                    "confirm": "PUBLISH_SYNTHETIC_FAILURE_ALERTS",
                    "filter": args.filter,
                    "delay": args.delay,
                },
                timeout=max(30, 15 + (len(ALERT_CASES) * max(args.delay, 0))),
            )
        else:
            response = requests.get(
                endpoint,
                headers=headers,
                params={"filter": args.filter} if args.filter else None,
                timeout=15,
            )
    except requests.RequestException as exc:
        print(f"Failed to call CCM MQTT test endpoint: {exc}", file=sys.stderr)
        return 1

    try:
        response_body = response.json()
    except ValueError:
        response_body = {"raw_response": response.text}

    if not args.publish or args.list:
        for index, case in enumerate(response_body.get("alerts", []), start=1):
            print(
                f"{index:02d}. {case['name']}: {case['operation']} — "
                f"{case['message']}"
            )
        if response_body.get("alerts"):
            print(f"\n{response_body.get('count', 0)} alert case(s)")
        else:
            print(json.dumps(response_body, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(response_body, indent=2, ensure_ascii=False))

    if not response.ok:
        print(f"CCM returned HTTP {response.status_code}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
