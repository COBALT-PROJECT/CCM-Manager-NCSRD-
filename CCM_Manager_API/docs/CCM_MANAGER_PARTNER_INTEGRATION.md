# CCM Manager Partner Integration Guide

This guide explains how partner components can authenticate to CCM Manager and call the main CCM APIs.

## Base URLs

Replace the host with the deployed CCM Manager address:

```text
http://<ccm-host>:5001
```

Example:

```text
http://10.163.1.204:5001
```

Swagger UI:

```text
http://<ccm-host>:5001/apidocs/
```

## Authentication

When inbound authentication is enabled, CCM Manager expects every protected request to include an Authentication Manager bearer token:

```http
Authorization: Bearer <access_token>
```

Public endpoints:

```text
GET /
GET /auth/status
GET /apidocs/
GET /apispec_1.json
GET /flasgger_static/*
```

All other endpoints require a bearer token when `CCM_INBOUND_AUTH_ENABLED=true`.

## Get A Component Token

Use the COBALT Authentication Manager OAuth token endpoint with `client_credentials`.

```bash
AM_BASE_URL="http://iam.cobalt.local:3100"
AM_CLIENT_ID="<partner-client-id>"
AM_CLIENT_SECRET="<partner-client-secret>"
AM_SCOPE="profile"

TOKEN_RESPONSE=$(curl -sS -u "$AM_CLIENT_ID:$AM_CLIENT_SECRET" \
  -H "Accept: application/json" \
  -d "grant_type=client_credentials" \
  --data-urlencode "scope=$AM_SCOPE" \
  "$AM_BASE_URL/oauth/token")

echo "$TOKEN_RESPONSE" | jq

TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
```

Validate the token with Authentication Manager:

```bash
curl -i "$AM_BASE_URL/oauth/userinfo?schema=openid" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json"
```

Expected result: `HTTP/1.1 200 OK`.

## Call CCM With A Token

```bash
CCM_BASE_URL="http://<ccm-host>:5001"

curl -sS "$CCM_BASE_URL/certification_schemes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | jq
```

In Swagger UI, click `Authorize` and enter:

```text
Bearer <access_token>
```

## Certification Scheme Upload

Upload a certification scheme and allow CCM to perform its configured integrations, such as DRM sync and scheme import:

```bash
curl -sS -X POST "$CCM_BASE_URL/upload_certification_scheme" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @certification_scheme.json | jq
```

For a local CCM-only test that skips external integrations:

```bash
curl -sS -X POST "$CCM_BASE_URL/upload_certification_scheme?sync_drm=false&sync_scheme_import=false" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @certification_scheme.json | jq
```

Useful follow-up calls:

```bash
SCHEME_ID="<scheme-id>"

curl -sS "$CCM_BASE_URL/certification_scheme/$SCHEME_ID" \
  -H "Authorization: Bearer $TOKEN" | jq

curl -sS "$CCM_BASE_URL/certification_scheme/$SCHEME_ID/catalog" \
  -H "Authorization: Bearer $TOKEN" | jq

curl -sS "$CCM_BASE_URL/certification_scheme/$SCHEME_ID/profile" \
  -H "Authorization: Bearer $TOKEN" | jq

curl -sS "$CCM_BASE_URL/schemes/$SCHEME_ID/export" \
  -H "Authorization: Bearer $TOKEN" | jq
```

## ToE Upload

Upload a Target of Evaluation and link it to a certification scheme:

```bash
SCHEME_ID="<scheme-id>"

curl -sS -X POST "$CCM_BASE_URL/upload_toe_descriptor?scheme_id=$SCHEME_ID&deploy_sdt=false" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @toe.json | jq
```

## Initial Certificate Creation

Create the initial certificate from a manual OK evaluation:

```bash
TOE_ID="<toe-id>"
SCHEME_ID="<scheme-id>"

curl -sS -X POST "$CCM_BASE_URL/certificate-evaluation-result" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"toe_id\": \"$TOE_ID\",
    \"scheme_id\": \"$SCHEME_ID\",
    \"evaluation_type\": \"Manual\",
    \"result\": \"OK\",
    \"evidence_id\": \"manual-evidence-001\"
  }" | jq
```

## Assessment Result State Updates

Use `/assessment-result` to update an existing certificate state.

`compliant=false` moves active certificates to `SUSPENDED`.

`compliant=true` moves `SUSPENDED` certificates back to `VALID`, and can also move an `INITIATE` dynamic assessment to `VALID`.

```bash
curl -sS -X POST "$CCM_BASE_URL/assessment-result" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @assessment_result.json | jq
```

The assessment result must satisfy the CCM assessment schema. Required fields include:

```text
id
created_at
metric_id
metric_configuration
evidence_id
resource_id
resource_types
compliance_comment
target_of_evaluation_id
history_updated_at
history
```

## Certificates

List certificates:

```bash
curl -sS "$CCM_BASE_URL/certificates" \
  -H "Authorization: Bearer $TOKEN" | jq
```

Download a certificate PDF:

```bash
CERT_ID="<certificate-id>"

curl -L "$CCM_BASE_URL/certificates/$CERT_ID/pdf?regenerate=true" \
  -H "Authorization: Bearer $TOKEN" \
  -o "certificate-$CERT_ID.pdf"
```

Withdraw a certificate:

```bash
curl -sS -X PUT "$CCM_BASE_URL/certificates/$CERT_ID/withdraw" \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Common Errors

Missing bearer token:

```json
{
  "error": "Authentication required"
}
```

Invalid or expired token:

```json
{
  "error": "Invalid bearer token"
}
```

To debug the AM token:

```bash
curl -i "$AM_BASE_URL/oauth/userinfo?schema=openid" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json"
```

To check CCM auth configuration:

```bash
curl -sS "$CCM_BASE_URL/auth/status" | jq
```

## CCM Deployment Settings

Example inbound-auth configuration for CCM:

```env
CCM_INBOUND_AUTH_ENABLED=true
CCM_INBOUND_ISSUER=http://iam.cobalt.local:3100
CCM_INBOUND_OPENID_CONFIG_URL=http://iam.cobalt.local:3100/.well-known/openid-configuration
CCM_INBOUND_JWKS_URL=http://iam.cobalt.local:3100/oauth/jwks
CCM_INBOUND_USERINFO_URL=http://iam.cobalt.local:3100/oauth/userinfo?schema=openid
CCM_INBOUND_AUDIENCE=components
CCM_INBOUND_REQUIRED_SCOPE=profile
CCM_INBOUND_REQUIRE_TYPE=component
CCM_INBOUND_ALLOWED_CLIENT_IDS=
CCM_INBOUND_VERIFY_TLS=false
```

Use `CCM_INBOUND_ALLOWED_CLIENT_IDS` when CCM should only accept specific component clients:

```env
CCM_INBOUND_ALLOWED_CLIENT_IDS=orchestrator-component,ui-component,assessment-component
```
