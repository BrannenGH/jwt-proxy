# jwt-proxy

A minimal reverse proxy that validates OIDC/JWT bearer tokens (via JWKS) before
forwarding requests to an upstream MCP server. Implements the
`oauth-protected-resource` and `oauth-authorization-server` metadata endpoints
so MCP clients can discover the auth flow.

## Configuration

| Env var | Required | Description |
| --- | --- | --- |
| `OIDC_ISSUER_URL` | yes | Base URL of the OIDC issuer (e.g. Keycloak realm). |
| `MCP_UPSTREAM_URL` | yes | Base URL of the upstream MCP server to proxy to. |
| `OIDC_JWKS_URL` | no | Overrides the JWKS endpoint (default: `{OIDC_ISSUER_URL}/protocol/openid-connect/certs`). |
| `OIDC_METADATA_URL` | no | Overrides where the `.well-known/openid-configuration` discovery document is fetched from (default: `{OIDC_ISSUER_URL}/.well-known/openid-configuration`). Useful for pointing at an internal address to avoid NAT hairpinning when `OIDC_ISSUER_URL` is a public hostname; `iss` claim validation still uses `OIDC_ISSUER_URL`. |
| `MCP_UPSTREAM_MCP_PATH` | no | Upstream path for MCP requests (default: `/mcp`). |
| `MCP_PUBLIC_URL` | no | Public base URL to advertise in metadata (default: inferred from request). |
| `MCP_RESOURCE_URL` | no | Public resource URL to advertise (default: `{MCP_PUBLIC_URL}{MCP_UPSTREAM_MCP_PATH}`). |
| `MCP_UPSTREAM_AUTH_TOKEN` | no | If set, sent upstream as `Authorization: Bearer {token}` instead of stripping the client's Authorization header. |
| `JWT_AUDIENCE` | no | Expected `aud` claim; if unset, audience is not verified. |
| `JWT_REQUIRED_AZP` | no | Expected `azp` claim; if unset, not checked. |
| `JWT_ALGORITHMS` | no | Comma-separated list of accepted signing algorithms (default: `RS256`). |
| `JWT_PROXY_HOST` | no | Listen host (default: `0.0.0.0`). |
| `JWT_PROXY_PORT` | no | Listen port (default: `8080`). |

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
OIDC_ISSUER_URL=https://issuer.example.com/realms/myrealm \
MCP_UPSTREAM_URL=http://localhost:9000 \
.venv/bin/python jwt_proxy.py
```

## Run with Docker

```bash
docker build -t jwt-proxy .
docker run -p 8080:8080 \
  -e OIDC_ISSUER_URL=https://issuer.example.com/realms/myrealm \
  -e MCP_UPSTREAM_URL=http://upstream:9000 \
  jwt-proxy
```

Health check available at `GET /healthz`.

## Container image

There exists a container image as well:

```bash
docker pull ghcr.io/brannengh/jwt-proxy:latest
```
