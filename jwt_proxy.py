#!/usr/bin/env python3
import asyncio
import contextlib
import logging
import os
import time
from collections.abc import Mapping
from typing import Any

import jwt
from aiohttp import (
    ClientConnectionError,
    ClientError,
    ClientPayloadError,
    ClientSession,
    ClientTimeout,
    web,
)
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("jwt_proxy")


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


ISSUER_URL = required_env("OIDC_ISSUER_URL").rstrip("/")
JWKS_URL = os.environ.get("OIDC_JWKS_URL", f"{ISSUER_URL}/protocol/openid-connect/certs")
# Lets the discovery-document fetch target an internal address (e.g. to avoid NAT
# hairpinning back through the public issuer hostname) while ISSUER_URL, used for
# `iss` claim validation, stays the externally-visible issuer.
METADATA_URL = os.environ.get("OIDC_METADATA_URL", f"{ISSUER_URL}/.well-known/openid-configuration")
UPSTREAM_URL = required_env("MCP_UPSTREAM_URL").rstrip("/")
UPSTREAM_MCP_PATH = os.environ.get("MCP_UPSTREAM_MCP_PATH", "/mcp").strip() or "/mcp"
PUBLIC_URL = os.environ.get("MCP_PUBLIC_URL", "").strip().rstrip("/")
RESOURCE_URL = os.environ.get("MCP_RESOURCE_URL", "").strip().rstrip("/")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "").strip() or None
JWT_REQUIRED_AZP = os.environ.get("JWT_REQUIRED_AZP", "").strip() or None
JWT_ALGORITHMS = [
    algorithm.strip()
    for algorithm in os.environ.get("JWT_ALGORITHMS", "RS256").split(",")
    if algorithm.strip()
]
OIDC_JWKS_TIMEOUT = float(os.environ.get("OIDC_JWKS_TIMEOUT", "5"))

jwks_client = PyJWKClient(JWKS_URL, timeout=OIDC_JWKS_TIMEOUT)


def filter_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
    }


def unauthorized(message: str) -> web.Response:
    return web.json_response(
        {"error": "unauthorized", "message": message},
        status=401,
        headers={"WWW-Authenticate": 'Bearer realm="mcp"'},
    )


async def validate_bearer_token(request: web.Request) -> dict[str, Any]:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise web.HTTPUnauthorized(
            text='{"error":"unauthorized","message":"missing bearer token"}',
            content_type="application/json",
            headers={"WWW-Authenticate": 'Bearer realm="mcp"'},
        )

    signing_key = await asyncio.get_running_loop().run_in_executor(
        None, jwks_client.get_signing_key_from_jwt, token
    )
    options = {"verify_aud": JWT_AUDIENCE is not None}
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=JWT_ALGORITHMS,
        audience=JWT_AUDIENCE,
        issuer=ISSUER_URL,
        options=options,
    )

    if JWT_REQUIRED_AZP and claims.get("azp") != JWT_REQUIRED_AZP:
        raise web.HTTPForbidden(
            text='{"error":"forbidden","message":"invalid authorized party"}',
            content_type="application/json",
        )

    return claims


async def health(_: web.Request) -> web.Response:
    return web.json_response({"ok": True, "time": int(time.time())})


def first_header_value(request: web.Request, name: str) -> str | None:
    value = request.headers.get(name)
    if not value:
        return None
    return value.split(",", 1)[0].strip()


def origin_url(request: web.Request) -> str:
    forwarded_proto = first_header_value(request, "X-Forwarded-Proto")
    forwarded_host = first_header_value(request, "X-Forwarded-Host")
    proto = forwarded_proto or request.scheme
    host = forwarded_host or request.headers.get("Host", "")
    return f"{proto}://{host}"


def public_origin_url(request: web.Request) -> str:
    return PUBLIC_URL or origin_url(request)


def resource_url(request: web.Request) -> str:
    return RESOURCE_URL or f"{public_origin_url(request)}{UPSTREAM_MCP_PATH}"


def metadata_url(request: web.Request) -> str:
    return f"{public_origin_url(request)}/.well-known/oauth-protected-resource/mcp"


def unauthorized_headers(request: web.Request) -> dict[str, str]:
    return {"WWW-Authenticate": f'Bearer resource_metadata="{metadata_url(request)}"'}


def include_value(values: Any, value: str) -> list[Any]:
    if not isinstance(values, list):
        return [value]
    if value in values:
        return values
    return [*values, value]


async def protected_resource_metadata(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "resource": resource_url(request),
            "authorization_servers": [ISSUER_URL],
            "bearer_methods_supported": ["header"],
            "resource_documentation": resource_url(request),
        }
    )


async def authorization_server_metadata(request: web.Request) -> web.Response:
    try:
        async with request.app["client"].get(
            METADATA_URL, timeout=ClientTimeout(total=OIDC_JWKS_TIMEOUT + 5)
        ) as response:
            if response.status < 200 or response.status >= 300:
                return web.json_response(
                    {"error": "authorization_server_metadata_failed", "status": response.status},
                    status=502,
                )
            metadata = await response.json()
    except (ClientError, TimeoutError, asyncio.TimeoutError) as error:
        logger.warning("authorization server metadata fetch failed: %s", error)
        return web.json_response(
            {
                "error": "auth_server_unavailable",
                "message": "could not reach or query the identity provider",
            },
            status=503,
        )

    metadata["token_endpoint_auth_methods_supported"] = include_value(
        metadata.get("token_endpoint_auth_methods_supported"),
        "none",
    )
    metadata["protected_resources"] = include_value(
        metadata.get("protected_resources"),
        resource_url(request),
    )
    return web.json_response(metadata)


async def proxy(request: web.Request) -> web.StreamResponse:
    try:
        claims = await validate_bearer_token(request)
    except web.HTTPException as error:
        if error.status == 401:
            error.headers.update(unauthorized_headers(request))
        raise
    except PyJWKClientError as error:
        # Raised when the JWKS endpoint can't be reached/parsed, not when the
        # token itself is bad. PyJWKClientError subclasses PyJWTError, so this
        # must be caught ahead of the generic PyJWTError branch below or every
        # transient JWKS hiccup gets misreported to the client as 401.
        logger.warning("JWKS fetch failed: %s", error)
        return web.json_response(
            {
                "error": "auth_server_unavailable",
                "message": "could not reach or query the identity provider",
            },
            status=503,
        )
    except jwt.PyJWTError as error:
        response = unauthorized(str(error))
        response.headers.update(unauthorized_headers(request))
        return response
    except Exception:
        logger.exception("token validation failed (JWKS/network error)")
        return web.json_response(
            {
                "error": "auth_server_unavailable",
                "message": "could not reach or query the identity provider",
            },
            status=503,
        )

    rel_url = request.rel_url
    if request.path == "/":
        rel_url = rel_url.with_path(UPSTREAM_MCP_PATH)
    target_url = f"{UPSTREAM_URL}{rel_url}"
    headers = filter_headers(request.headers)
    headers.pop("Authorization", None)
    headers["X-Authenticated-Subject"] = str(claims.get("sub", ""))
    if claims.get("preferred_username"):
        headers["X-Authenticated-User"] = str(claims["preferred_username"])

    body = request.content.iter_chunked(64 * 1024)
    response: web.StreamResponse | None = None
    try:
        async with request.app["client"].request(
            request.method,
            target_url,
            headers=headers,
            data=body,
            allow_redirects=False,
        ) as upstream:
            response = web.StreamResponse(
                status=upstream.status,
                reason=upstream.reason,
                headers=filter_headers(upstream.headers),
            )
            await response.prepare(request)
            async for chunk in upstream.content.iter_chunked(64 * 1024):
                await response.write(chunk)
            await response.write_eof()
            return response
    except (
        ClientConnectionError,
        ClientPayloadError,
        ConnectionResetError,
        ClientError,
        TimeoutError,
    ) as error:
        logger.warning("upstream request failed: %s", error)
        if response is not None:
            with contextlib.suppress(Exception):
                await response.write_eof()
            return response

        return web.Response(status=502, text="upstream stream interrupted")


async def create_app() -> web.Application:
    app = web.Application(client_max_size=1024**3)
    app.router.add_get("/healthz", health)
    app.router.add_get(
        "/.well-known/oauth-protected-resource",
        protected_resource_metadata,
    )
    app.router.add_get(
        "/.well-known/oauth-protected-resource/mcp",
        protected_resource_metadata,
    )
    app.router.add_get(
        "/.well-known/oauth-authorization-server",
        authorization_server_metadata,
    )
    app.router.add_get(
        "/.well-known/openid-configuration",
        authorization_server_metadata,
    )
    app.router.add_route("*", "/{path:.*}", proxy)
    app["client"] = ClientSession()

    async def close_client(app_: web.Application) -> None:
        await app_["client"].close()

    app.on_cleanup.append(close_client)
    return app


if __name__ == "__main__":
    web.run_app(
        create_app(),
        host=os.environ.get("JWT_PROXY_HOST", "0.0.0.0"),
        port=int(os.environ.get("JWT_PROXY_PORT", "8080")),
    )
