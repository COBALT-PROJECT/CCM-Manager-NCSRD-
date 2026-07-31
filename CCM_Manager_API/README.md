# CCM-Manager
Common Certification Model Manager Module for WP2 of COBALT

## Incoming Authentication

Incoming bearer-token authentication is available but disabled by default so local deployments keep working until explicitly protected.

To require callers to authenticate through the COBALT Authentication Manager, configure:

- `CCM_INBOUND_AUTH_ENABLED=true`
- `CCM_INBOUND_ISSUER`, defaults to `AM_BASE_URL`
- `CCM_INBOUND_JWKS_URL`, defaults to `<CCM_INBOUND_ISSUER>/oauth/jwks`
- `CCM_INBOUND_USERINFO_URL`, defaults to `<CCM_INBOUND_ISSUER>/oauth/userinfo?schema=openid`
- `CCM_INBOUND_AUDIENCE`, optional JWT audience, for component tokens usually `components`
- `CCM_INBOUND_REQUIRED_SCOPE`, optional required scope, for current AM component tokens usually `profile`
- `CCM_INBOUND_REQUIRE_TYPE`, optional token subject type, for component-only access use `component`
- `CCM_INBOUND_ALLOWED_CLIENT_IDS`, optional comma/space separated allowlist
- `CCM_INBOUND_VERIFY_TLS`, defaults to `AM_VERIFY_TLS`

Public endpoints remain available without a bearer token: `/`, `/auth/status`, `/apidocs/`, `/apispec_1.json`, and Swagger static assets.

Protected calls must send:

```bash
curl -sS "http://localhost:5001/certification_schemes" \
  -H "Authorization: Bearer <access_token>" \
  -H "Accept: application/json" | jq
```

See `docs/CCM_MANAGER_PARTNER_INTEGRATION.md` for partner-facing instructions and example flows.

## HTTP Request And Response Logging

Flask logs incoming requests and outgoing responses with a generated or forwarded request ID, status code, duration, selected headers, and redacted/truncated body previews. These logs are visible through `docker logs`.

Useful `.env` settings:

```env
CCM_LOG_LEVEL=INFO
CCM_HTTP_LOGGING_ENABLED=true
CCM_HTTP_LOG_HEADERS_ENABLED=true
CCM_HTTP_LOG_BODY_ENABLED=true
CCM_HTTP_LOG_MAX_BODY_CHARS=4000
```

Sensitive headers and payload fields such as `Authorization`, tokens, passwords, and client secrets are redacted before logging.

## Startup Catalogue Seeding

When the Flask app starts, CCM seeds the global catalogue collections from the bundled EUCS and Quantum data files.

Default EUCS sources:

- `data/eucs/global_certification_scheme_fully_mapped.json`
- `data/eucs/EUCS_controls_version_1.1_catalog_master.json`

Default Quantum sources:

- `data/Quantum/global_certification_scheme_quantum_fully_mapped.json`
- `data/Quantum/Quantum_controls_version_1.0_catalog_master.json`

Optional path overrides:

- `AI_CATALOGUE_PATH`
- `EUCS_CONTROLS_CATALOGUE_PATH`
- `QUANTUM_CATALOGUE_PATH`
- `QUANTUM_CONTROLS_CATALOGUE_PATH`

The startup loader upserts catalogue records so EUCS and Quantum metrics, risks, threats, and controls can coexist in MongoDB.
If old seed data should be removed, clear the affected collections once before restarting the app.

## DRM Sync

`POST /upload_certification_scheme` now uploads the certification scheme into CCM, sends it to the scheme import service, and automatically syncs it to DRM.
The response includes `scheme_import_status`, `scheme_import_status_code`, `scheme_import_response`, `drm_sync_status`, `drm_sync_status_code`, and `drm_sync_response` so you can see whether each external component accepted it.

By default the scheme import service is `http://10.163.1.127:8080/scheme/import`.
You can override it with:

- `SCHEME_IMPORT_URL`, full URL override
- `SCHEME_IMPORT_BASE_URL`, base URL used with `/scheme/import`
- `SCHEME_IMPORT_TIMEOUT`, defaults to `10`
- `SCHEME_IMPORT_PAYLOAD_MODE`, defaults to `scheme_content`; use `uploaded`, `wrapper`, or `auto` if the receiver expects a different JSON shape

To upload only into CCM without calling DRM or the scheme import service:

```bash
curl -X POST "http://localhost:5001/upload_certification_scheme?sync_drm=false&sync_scheme_import=false" \
  -H "Content-Type: application/json" \
  -d @fullCertScheme.json
```

`POST /schemes/<scheme_id>/sync-drm` sends a CCM certification scheme to the DRM API using the corrected CCM-to-DRM flow:
metrics and controls, C-M links, scheme, risks and threats, then R-T-C links.
This manual route is still available if you need to retry a DRM sync for an already uploaded scheme.

Configure the DRM target with:

- `DRM_BASE_URL`, for example `http://10.163.1.249`
- `DRM_API_PREFIX`, defaults to `/eu/cobalt`
- `DRM_BEARER_TOKEN`, optional static bearer token for the DRM API
- `DRM_CREATOR_EMAIL`, defaults to `ccm@cobalt.eu`
- `DRM_SCHEME_ADMIN_EMAIL`, optional override for `/schemes` `scheme_admin_email`

## SDT Sync

`POST /upload_toe_descriptor` now registers the ToE and, by default, starts the SDTM flow for it.
CCM uses the uploaded ToE component UUID as the SDTM `toeid`, deploys a digital twin, and sends the
ToE BOM to SDTM adapt. It prefers an explicit `bom_path`/`sdt_bom_path` if one is provided; otherwise
it sends the inline `bills-of-material.sbom` from the ToE JSON.

Example ToE upload with automatic SDTM deploy/adapt:

```bash
curl -X POST "http://localhost:5001/upload_toe_descriptor" \
  -H "Content-Type: application/json" \
  -d @Toe.json
```

To register the ToE without touching SDTM:

```bash
curl -X POST "http://localhost:5001/upload_toe_descriptor?deploy_sdt=false" \
  -H "Content-Type: application/json" \
  -d @Toe.json
```

`POST /send_sdt` keeps the CCM-side workflow stable while supporting the SDTM lifecycle API.
The CCM route accepts a JSON body with `hash`, `bom_path`, or `bom_content`, deploys an SDT instance through
`POST /api/SDTM/digital-twin`, sends the SBOM to `POST /api/SDTM/adapt`, lists deployments,
and retrieves the created twin when the SDTM response includes an identifier.

The CCM SDTM routes are:

- `POST /send_sdt` deploys one SDT instance and returns the SDTM lifecycle response.
- `GET /sdts` lists current SDT deployments via `GET /api/SDTM/deployments`.
- `GET /sdts/<twin_id>` retrieves one SDT instance via `GET /api/SDTM/digital-twin/<twin_id>`.
- `POST /trigger_delete` deletes one SDT instance via `DELETE /api/SDTM/digital-twin/<twin_id>`.

For SDTM you can configure either a single base URL or explicit endpoint overrides:

- `SDTM_BASE_URL`, for example `http://sdtm.cobalt.local:8008`
- `SDTM_DIGITAL_TWIN_URL`, defaults to `<SDTM_BASE_URL>/api/SDTM/digital-twin`
- `SDTM_DEPLOYMENTS_URL`, defaults to `<SDTM_BASE_URL>/api/SDTM/deployments`
- `SDTM_AUTH_STATUS_URL`, defaults to `<SDTM_BASE_URL>/api/SDTM/auth`
- `SDTM_ADAPT_URL`, defaults to `<SDTM_BASE_URL>/api/SDTM/adapt`
- `SDTM_PAYLOAD_TYPE`, defaults to `BOMS`
- `SDTM_TOE_ID`, defaults to `00000000-0000-0000-0000-000000000000`
- `SDT_AUTH_DISABLED`, defaults to `true` for SDTM/SDT calls so CCM calls SDTM without IAM/bearer auth
- `SDT_BEARER_TOKEN`, optional static bearer token if you set `SDT_AUTH_DISABLED=false`

If `SDTM_BASE_URL` is not set, CCM can derive it from legacy `DEPLOY_SDT`,
`DEPLOYMENTS_SDT`, `CREATE_SDT`, or `DELETE_SDT` URLs and still call the new SDTM paths.

### ToE ID handoff and periodic ID sync

CCM starts a restart-safe background workflow after an attempted Digital Twin deployment by default:

1. Poll `GET http://ai-target-of-evaluation.cobalt.local:30005/health`.
2. Only after the health endpoint returns exactly `200`, send the uploaded ToE UUID to
   `POST /api/IDSconnector/TOE/id`.
3. After the ToE ID is accepted, periodically call the SDTM
   `GET /api/SDT/sync/ids` endpoint with the real ToE UUID.

A failed SDTM response does not prevent the handoff from being scheduled because SDTM can return
an error after the Digital Twin was created. An intentional `deploy_sdt=false` request or a
pre-deployment skip caused by missing BOM data does not schedule the workflow.

The worker persists its state in MongoDB collection `toe_workflow_jobs`, uses a lease to avoid
duplicate processing, and does not make an otherwise successful ToE upload fail.

Configure it with:

```env
TOE_ID_HANDOFF_ENABLED=true
TOE_CONNECTOR_BASE_URL=http://ai-target-of-evaluation.cobalt.local:30005
TOE_CONNECTOR_HEALTH_URL=http://ai-target-of-evaluation.cobalt.local:30005/health
TOE_CONNECTOR_ID_URL=http://ai-target-of-evaluation.cobalt.local:30005/api/IDSconnector/TOE/id
TOE_CONNECTOR_ID_FIELD=toe_id
TOE_CONNECTOR_TIMEOUT_SECONDS=15
TOE_CONNECTOR_RETRY_SECONDS=30
TOE_CONNECTOR_RETRY_MAX_SECONDS=30
TOE_CONNECTOR_AUTH_DISABLED=false
TOE_CONNECTOR_AUTH_ROLE=openid profile

SDT_ID_SYNC_ENABLED=true
SDT_ID_SYNC_URL=http://sdtm.cobalt.local:30008/api/SDT/sync/ids
SDT_ID_SYNC_INTERVAL_SECONDS=300
SDT_ID_SYNC_CATEGORY=AI
SDT_ID_SYNC_DATA_PATH=all
SDT_ID_SYNC_TIMEOUT_SECONDS=15

TOE_WORKFLOW_POLL_SECONDS=5
TOE_WORKFLOW_LEASE_SECONDS=90
TOE_WORKFLOW_RESPONSE_MAX_CHARS=4000
```

The connector health check is public. The ToE ID handoff uses CCM's IAM client credentials,
refreshes expired access tokens, and retries every 30 seconds until the connector accepts the ID.
Set `TOE_CONNECTOR_AUTH_DISABLED=true` only when the ToE ID endpoint is intentionally public.
The existing default `SDT_AUTH_DISABLED=true` keeps SDTM calls unauthenticated; set it to `false`
and configure its corresponding auth role or bearer token when SDTM requires IAM authentication.

The worker runs as the Compose service `toe-workflow-worker`. Inspect it with:

```bash
sudo docker compose up -d --build --force-recreate flask-app toe-workflow-worker
sudo docker compose logs -f toe-workflow-worker
```

To disable the feature immediately without deleting ToEs or workflow state:

```env
TOE_ID_HANDOFF_ENABLED=false
SDT_ID_SYNC_ENABLED=false
```

Then recreate Flask and stop the worker:

```bash
sudo docker compose up -d --force-recreate flask-app
sudo docker compose stop toe-workflow-worker
```

## Certificate State Updates

`POST /certificate-evaluation-result` creates the initial certificate for a ToE and certification scheme.
The first request must be `evaluation_type` `Manual` with result `OK`; CCM creates the certificate with state `INITIATE`, uploads it to the DLT, and stores the certificate hash.
The `scheme_id` value can be either the CCM scheme UUID or the exact human-readable scheme name. You can also send `scheme_name` or `certification_scheme_name`.
The `evidence_id` field is optional for this endpoint; if omitted, CCM stores `N/A` as the evidence reference.

`POST /certificates/evaluation-result` is available as an alias for the same certificate creation workflow.

```bash
curl -X POST "http://localhost:5001/certificate-evaluation-result" \
  -H "Content-Type: application/json" \
  -d '{
    "toe_id": "3e671687-395b-41f5-a30f-a58921a69b79",
    "scheme_id": "AI_CLOUD_COMPLEX_DRM_DEMO_v1",
    "evaluation_type": "Manual",
    "result": "OK"
  }'
```

After the certificate exists, `POST /assessment-result` updates its certificate state.
The assessment result remains stored as an assessment result; CCM derives `OK` from `compliant: true` and `NOK` from `compliant: false`, reuploads the updated certificate to the DLT, and stores the new certificate hash.
By default assessment results are treated as `DYNAMIC`; include `evaluation_type: "Manual"` in the assessment payload if the result should follow the manual transition.

For an existing active certificate, assessment `OK` moves `SUSPENDED` to `VALID`, keeps `VALID` as `VALID`, and moves `INITIATE` to `VALID` for `DYNAMIC`.
Assessment `NOK` moves `INITIATE` or `VALID` to `SUSPENDED`, and keeps `SUSPENDED` as `SUSPENDED`.

The generated certificate PDF can be downloaded by another component, such as the UI, through the certificate ID:

```bash
curl -L -o certificate.pdf "http://localhost:5001/certificates/<CERTIFICATE_ID>/pdf"
```

If the PDF file needs to be rebuilt from the latest certificate document, add `?regenerate=true`.
Set `PDF_OUTPUT_DIR` to a mounted folder such as `/app/tmp` so PDFs remain downloadable after container restarts.

## OSCAL Catalog And Profile Queries

Uploaded certification schemes keep their OSCAL catalog and profile under the scheme content.
You can query each section directly by certification scheme ID:

```bash
curl -sS "http://localhost:5001/certification_scheme/<SCHEME_ID>/catalog" | jq
curl -sS "http://localhost:5001/certification_scheme/<SCHEME_ID>/profile" | jq
```

You can also query the catalog/profile through a generated certificate ID. CCM resolves the certificate's linked certification scheme and returns the matching section:

```bash
curl -sS "http://localhost:5001/certificates/<CERTIFICATE_ID>/catalog" | jq
curl -sS "http://localhost:5001/certificates/<CERTIFICATE_ID>/profile" | jq
```

## VM Deployment

The Docker Compose stack uses Percona Server for MongoDB with encryption at rest enabled. Before starting the stack on a VM, create the local Mongo encryption key file in `CCM_Manager_API`.

Recommended:

```bash
cd CCM_Manager_API
chmod +x initialize_encryption.sh
./initialize_encryption.sh
```

Manual fallback:

```bash
cd CCM_Manager_API
openssl rand -base64 32 > mongo_keyfile
sudo chown 1001:1001 mongo_keyfile
sudo chmod 400 mongo_keyfile
```

The key file must exist before `docker compose up`, because `docker-compose.yml` mounts it as:

```yaml
./mongo_keyfile:/etc/mongo_keyfile:ro
```

Start or rebuild the CCM stack:

```bash
docker compose up -d --build
docker compose ps
```

Check logs:

```bash
docker compose logs -f mongo
docker compose logs -f flask-app
```

If the Percona Mongo container keeps restarting, first check the key file:

```bash
ls -l mongo_keyfile
sudo chown 1001:1001 mongo_keyfile
sudo chmod 400 mongo_keyfile
docker compose restart mongo flask-app
```

Do not commit or copy `mongo_keyfile` between deployments. Each VM should generate its own key before first startup. If the `mongo-data` volume already contains encrypted data, keep the same key file for that VM; replacing it will prevent Mongo from reading the existing encrypted volume.

## Structure

See docs/structure.md for a quick map of module connections and folder roles.
