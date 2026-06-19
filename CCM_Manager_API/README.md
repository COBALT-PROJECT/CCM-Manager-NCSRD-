# CCM-Manager
Common Certification Model Manager Module for WP2 of COBALT

## DRM Sync

`POST /schemes/<scheme_id>/sync-drm` sends a CCM certification scheme to the DRM API using the corrected CCM-to-DRM flow:
metrics and controls, C-M links, scheme, risks and threats, then R-T-C links.

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

## Structure

See docs/structure.md for a quick map of module connections and folder roles.
