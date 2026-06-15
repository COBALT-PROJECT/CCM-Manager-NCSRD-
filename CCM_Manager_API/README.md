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

## Structure

See docs/structure.md for a quick map of module connections and folder roles.
