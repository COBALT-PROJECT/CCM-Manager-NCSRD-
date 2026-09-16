# CCM Manager MQTT Failure Alerts

## Overview

CCM Manager publishes an MQTT alert whenever an operational failure occurs while processing data or communicating with another COBALT component.

Alerts are published only for failures. CCM Manager does not publish MQTT messages for successful operations, recovery events, intentionally disabled integrations, or expected client errors.

## MQTT connection

| Setting | Default value |
|---|---|
| Broker | `10.163.1.161` |
| Port | `1883` |
| Topic | `components/CCM-Manager/reports` |
| Protocol | MQTT v3.1.1 |
| QoS | `1` |
| Retain | `false` |

MQTT alerts are disabled by default in development and test environments. Enable them in the deployed CCM Manager with:

```env
MQTT_ALERTS_ENABLED=true
MQTT_BROKER_HOST=10.163.1.161
MQTT_BROKER_PORT=1883
MQTT_COMPONENT_ID=CCM-Manager
MQTT_ALERT_TOPIC=components/CCM-Manager/reports
MQTT_QOS=1
MQTT_RETAIN=false
MQTT_KEEPALIVE_SECONDS=10
MQTT_DETAILS_MAX_CHARS=4000
```

Authenticated or TLS-enabled brokers can additionally use:

```env
MQTT_USERNAME=
MQTT_PASSWORD=
MQTT_TLS_ENABLED=false
```

## Common alert format

Every failure alert follows this structure:

```json
{
  "event_id": "failure-<unique-uuid>",
  "state": "failed",
  "severity": "critical",
  "component": "<component that failed>",
  "operation": "<failed operation>",
  "message": "<failure explanation>",
  "occurred_at": "<ISO-8601 UTC timestamp>",
  "details": {
    "request_id": "<request UUID, when available>",
    "method": "<HTTP method, when available>",
    "path": "<CCM endpoint, when available>",
    "service": "<affected component>",
    "status_code": "<HTTP status, when available>",
    "error": "<technical error, when available>"
  }
}
```

The top-level `component` identifies the component that failed. It is taken
from `details.service` when the failure concerns another component, such as
`ledger`, `sdt`, or `orchestrator`. Internal CCM failures use `CCM-Manager`.
The `details` object changes according to the failed operation. Authentication
credentials, bearer tokens, passwords, client secrets, and API keys are
redacted. Large downstream responses are truncated.

## Blockchain and ledger alerts

| Operation | Message | Main details |
|---|---|---|
| `Publish certification scheme to blockchain` | `Blockchain ledger request failed` | Scheme ID, ledger endpoint, exception type and error |
| `Publish assessment result to blockchain` | `Blockchain ledger request failed` | Assessment ID, ToE ID, scheme ID and error |
| `Publish certificate to blockchain` | `Blockchain ledger request failed` | Certificate ID, ToE ID, scheme ID and certificate operation |
| `Send data to blockchain ledger` | `Blockchain ledger request failed` | Ledger endpoint, exception type and error |
| `Publish BOM to blockchain` | `Blockchain rejected or could not receive the BOM` | Unique key, exception type and error |
| `Retrieve BOM hash from blockchain` | `Failed to retrieve the blockchain hash` | Unique key, exception type and error |
| `Send blockchain BOM to SDTM` | `Failed to pass the blockchain hash to SDTM` | Unique key, hash and error |

### Example: certification scheme blockchain failure

```json
{
  "event_id": "failure-8ed223c3-a716-4782-a32b-35d20234e92d",
  "state": "failed",
  "severity": "critical",
  "component": "ledger",
  "operation": "Publish certification scheme to blockchain",
  "message": "Blockchain ledger request failed",
  "occurred_at": "2026-09-16T14:42:18.521934+00:00",
  "details": {
    "request_id": "8cab7a36-f271-47ce-8892-12ed392c66ab",
    "method": "POST",
    "path": "/upload_certification_scheme",
    "service": "ledger",
    "endpoint": "/v1/certification-authority/certification-scheme",
    "exception_type": "ConnectTimeout",
    "error": "Connection to the blockchain ledger timed out",
    "scheme_id": "EUCS-2026"
  }
}
```

### Example: assessment blockchain failure

```json
{
  "event_id": "failure-2de35293-c2f7-437d-8f60-1d4b36965243",
  "state": "failed",
  "severity": "critical",
  "component": "ledger",
  "operation": "Publish assessment result to blockchain",
  "message": "Blockchain ledger request failed",
  "occurred_at": "2026-09-16T15:10:42.391204+00:00",
  "details": {
    "request_id": "req-c63ab0fd",
    "method": "POST",
    "path": "/assessment-result",
    "service": "ledger",
    "endpoint": "/v1/manufacturer/ass-results",
    "exception_type": "ConnectionError",
    "error": "Connection refused",
    "assessment_id": "assessment-1007",
    "toe_id": "toe-42",
    "scheme_id": "EUCS-2026"
  }
}
```

## Certification scheme integration alerts

| Operation | Message | Main details |
|---|---|---|
| `Import certification scheme to orchestrator` | `Scheme import request failed` | Scheme ID, payload mode, correlation ID and exception |
| `Import certification scheme to orchestrator` | `Scheme import service rejected the certification scheme` | Scheme ID, HTTP status and response |
| `Synchronize certification scheme to DRM` | `DRM synchronization is enabled but DRM_BASE_URL is not configured` | Scheme ID |
| `Synchronize certification scheme to DRM` | `DRM rejected part of the certification scheme synchronization` | DRM path, HTTP status and partial progress |
| `Synchronize certification scheme to DRM` | `Unexpected DRM synchronization failure` | Scheme ID, exception and partial progress |

### Example: DRM synchronization failure

```json
{
  "event_id": "failure-c8a41483-d594-4d68-87cd-d8bb0257c202",
  "state": "failed",
  "severity": "critical",
  "component": "drm",
  "operation": "Synchronize certification scheme to DRM",
  "message": "DRM rejected part of the certification scheme synchronization",
  "occurred_at": "2026-09-16T15:13:08.101934+00:00",
  "details": {
    "request_id": "req-e7c6fcf1",
    "method": "POST",
    "path": "/upload_certification_scheme",
    "service": "drm",
    "scheme_id": "EUCS-2026",
    "drm_path": "/controls",
    "status_code": 500,
    "response": {
      "error": "Database unavailable"
    },
    "created_before_failure": {
      "metrics": 12,
      "controls": 3
    }
  }
}
```

## Target of Evaluation and orchestrator alerts

| Operation | Message | Main details |
|---|---|---|
| `Forward ToE to orchestrator` | `Orchestrator rejected the ToE descriptor` | ToE ID, scheme ID and HTTP status |
| `Forward ToE to orchestrator` | `Failed to forward the ToE descriptor` | ToE ID, scheme ID and exception |
| `Synchronize ToE to SDTM` | `Unexpected failure while synchronizing the ToE to SDTM` | ToE ID, scheme ID and exception |
| `Schedule ToE ID handoff` | `Failed to schedule the ToE ID handoff workflow` | ToE ID and exception |
| `Handoff ToE ID to connector` | `ToE connector handoff failed and was scheduled for retry` | Phase, attempt, next retry, HTTP status and error |
| `Synchronize SDT IDs` | `SDT ID synchronization failed and was scheduled for retry` | ToE ID, attempt, next retry, HTTP status and error |
| `Process ToE background workflow` | `Unexpected ToE workflow worker failure; the job will retry after its lease expires` | ToE ID, worker ID and exception |

### Example: ToE connector handoff failure

```json
{
  "event_id": "failure-9ca0e280-2531-421d-9454-55d87b3121ce",
  "state": "failed",
  "severity": "critical",
  "component": "toe_connector",
  "operation": "Handoff ToE ID to connector",
  "message": "ToE connector handoff failed and was scheduled for retry",
  "occurred_at": "2026-09-16T15:17:31.754983+00:00",
  "details": {
    "service": "toe_connector",
    "toe_id": "toe-42",
    "phase": "health",
    "status_code": 503,
    "attempt": 1,
    "next_run_at": "2026-09-16T15:18:01.754983",
    "error": "Health check returned HTTP 503"
  }
}
```

Repeating background-worker failures are deduplicated. One alert is sent at the beginning of a failure episode. After the operation succeeds, a later failure can generate a new alert.

## SDTM alerts

| Operation | Message | Main details |
|---|---|---|
| `Deploy SDT instance` | `SDTM digital twin endpoint is not configured` | ToE ID and hash |
| `Deploy SDT instance` | `Failed to deploy SDT instance` | ToE ID, hash and exception |
| `Adapt BOM in SDTM` | `SDTM adapt endpoint is not configured` | ToE ID and hash |
| `Adapt BOM in SDTM` | `SDTM adapt request failed` | ToE ID, hash, payload type and exception |
| `List SDTM deployments` | `Failed to list SDTM deployments after deployment` | ToE ID, twin ID and exception |
| `Retrieve deployed SDT instance` | `Failed to retrieve the deployed SDT instance` | ToE ID, twin ID and exception |
| `Retrieve SDTM authentication status` | `Failed to retrieve authentication status for an SDT instance` | Twin ID and exception |
| `Delete SDT instance` | `SDTM rejected the delete request` | Twin ID, HTTP status and response |

### Example: SDT deployment failure

```json
{
  "event_id": "failure-c85eb597-976b-41bd-87d6-3f087beb8f50",
  "state": "failed",
  "severity": "critical",
  "component": "sdt",
  "operation": "Deploy SDT instance",
  "message": "Failed to deploy SDT instance",
  "occurred_at": "2026-09-16T15:20:59.019308+00:00",
  "details": {
    "request_id": "req-e19053d8",
    "method": "POST",
    "path": "/upload_toe_descriptor",
    "service": "sdt",
    "toe_id": "toe-42",
    "hash": "37B49A...",
    "exception_type": "ConnectTimeout",
    "error": "The SDTM connection timed out"
  }
}
```

## Artifact, certificate and startup alerts

| Operation | Message | Main details |
|---|---|---|
| `Forward artifact record` | `Artifact destination rejected the forwarded record` | Destination and HTTP status |
| `Forward artifact record` | `Failed to forward an artifact record` | Destination and exception |
| `Generate certificate PDF` | `Failed to regenerate the certificate PDF` | Certificate ID, ToE ID, scheme ID and exception |
| `Initialize CCM catalogue` | `Failed to initialize a configured catalogue` | Catalogue path and exception |

## Generic internal CCM failures

Any HTTP 5xx response that has not already produced a more specific alert generates a generic endpoint alert.

```json
{
  "event_id": "failure-d3960464-c004-42ec-a6dd-874da1d94555",
  "state": "failed",
  "severity": "critical",
  "component": "CCM-Manager",
  "operation": "POST /generate_sbom",
  "message": "Failed to generate SBOM",
  "occurred_at": "2026-09-16T15:24:17.495613+00:00",
  "details": {
    "request_id": "req-d16e56ad",
    "method": "POST",
    "path": "/generate_sbom",
    "status_code": 500
  }
}
```

This fallback covers unexpected database failures, file-processing failures, and uncaught endpoint errors.

## Events that do not produce alerts

CCM Manager does not send MQTT messages for:

- Successful operations.
- HTTP 2xx and 3xx responses without an internal downstream failure.
- Invalid client input such as HTTP 400 responses.
- Missing resources represented by HTTP 404 responses.
- Business-state conflicts represented by HTTP 409 responses.
- Invalid or missing caller authentication.
- Integrations intentionally disabled or skipped.
- Successful retry or recovery events.
- Every repeated attempt in an already-reported background failure episode.

## Failure isolation

MQTT publication is best-effort. If the MQTT broker is unavailable:

- CCM Manager logs the MQTT publication failure.
- The MQTT failure does not replace the original error.
- The original API response and workflow behavior remain unchanged.
- The alert publisher does not recursively attempt to report its own failure.

## Testing every alert through CCM Manager

The test utility imports the same alert service used by CCM. It uses CCM's MQTT
configuration and production payload builder without calling the protected HTTP
API, so it does not require a bearer token or separate test token. It does not
invoke the real ledger, DRM, SDTM, orchestrator, or database failure paths.

Ensure MQTT alerts are enabled in the environment where the script runs:

```env
MQTT_ALERTS_ENABLED=true
```

From the `CCM_Manager_API` directory, list the available cases without
publishing:

```bash
python3 scripts/test_all_mqtt_alerts.py --list
```

Publish all synthetic alerts through CCM:

```bash
python3 scripts/test_all_mqtt_alerts.py --publish
```

Test only matching cases:

```bash
python3 scripts/test_all_mqtt_alerts.py --filter sdt --publish
```

Each test alert includes `synthetic_test`, `test_run_id`, `test_case`,
`sequence`, and `total` fields in `details`, plus the top-level `component`
field.
