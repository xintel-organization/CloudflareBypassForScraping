import logging
import os
import re
import time
import json
import secrets
from contextlib import asynccontextmanager
from typing import Optional, AsyncGenerator
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from bs4 import BeautifulSoup

from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.core.mirror import RequestMirror
from cf_bypasser.server.models import ErrorResponse

# Global instances
global_bypasser = None
global_mirror = None

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for FastAPI application startup and shutdown."""
    global global_bypasser, global_mirror

    logger.info("Starting Cloudflare Bypasser Server...")

    if not os.environ.get("API_TOKEN", "").strip():
        logger.warning(
            "API_TOKEN env var is not set — all requests will be rejected with 503. "
            "Set API_TOKEN in your environment (e.g. docker-compose) to enable the API."
        )

    global_bypasser = CamoufoxBypasser(max_retries=5, log=True)
    global_mirror = RequestMirror(global_bypasser)

    logger.info("Server initialization complete")

    yield

    logger.info("Shutting down Cloudflare Bypasser Server...")
    try:
        if global_mirror:
            await global_mirror.cleanup()
        if global_bypasser:
            await global_bypasser.cleanup()
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
    logger.info("Server shutdown complete")


def is_safe_url(url: str) -> bool:
    """Check if the URL is safe (not localhost/private)."""
    try:
        parsed_url = urlparse(url)
        ip_pattern = re.compile(
            r"^(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]\.\d+\.\d+|192\.168\.\d+\.\d+)$"
        )
        hostname = parsed_url.hostname
        if (hostname and ip_pattern.match(hostname)) or parsed_url.scheme == "file":
            return False
        return True
    except Exception:
        return False


def verify_token(x_api_token: Optional[str] = Header(None)) -> None:
    """Validate X-API-Token header against the API_TOKEN env var (fail closed)."""
    expected = os.environ.get("API_TOKEN", "").strip()
    if not expected:
        logger.error("API_TOKEN env var is not set — refusing request")
        raise HTTPException(status_code=503, detail="Server misconfigured: API_TOKEN not set")
    if not x_api_token or not secrets.compare_digest(x_api_token, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Token header")


def setup_routes(app: FastAPI):
    """Setup routes for the FastAPI application. Only /zonaprop is exposed."""

    @app.api_route(
        "/zonaprop/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        dependencies=[Depends(verify_token)],
    )
    async def zonaprop_request(request: Request, path: str = ""):
        """
        ZonaProp-specific endpoint that extracts preloaded state JSON from the page.

        Required Headers:
        - X-API-Token: Authentication token (must match server's API_TOKEN env var)
        - x-hostname: Target hostname (e.g., "zonaprop.com.ar")

        Optional Headers:
        - x-proxy: Proxy URL (http://, https://, socks4://, socks5://)
        - x-bypass-cache: Force fresh cookie generation (true/false)
        """
        try:
            start_time = time.time()

            headers = dict(request.headers)

            hostname = None
            proxy = None
            bypass_cache = False

            for key, value in headers.items():
                key_lower = key.lower()
                if key_lower == 'x-hostname':
                    hostname = value
                elif key_lower == 'x-proxy':
                    proxy = value
                elif key_lower == 'x-bypass-cache':
                    bypass_cache = value.lower() in ('true', '1', 'yes', 'on')

            if not hostname:
                raise HTTPException(
                    status_code=400,
                    detail="x-hostname header is required for ZonaProp requests"
                )

            if not is_safe_url(f"https://{hostname}"):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid or unsafe hostname - localhost and private IPs are not allowed"
                )

            if proxy and not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                raise HTTPException(
                    status_code=400,
                    detail="x-proxy must start with http://, https://, socks4://, or socks5://"
                )

            logger.info(f"ZonaProp request: {request.method} {hostname}/{path}")
            if proxy:
                logger.info(f"Using proxy: {proxy}")
            if bypass_cache:
                logger.info("x-bypass-cache header detected - forcing fresh cookie generation")

            body = await request.body()
            query_string = str(request.query_params)

            mirror = global_mirror or RequestMirror(global_bypasser)

            status_code, response_headers, response_content = await mirror.mirror_request(
                method=request.method,
                path=f"/{path}" if path else "/",
                query_string=query_string,
                headers=headers,
                body=body
            )

            if status_code != 200:
                logger.warning(f"ZonaProp request returned status {status_code}")
                raise HTTPException(
                    status_code=status_code,
                    detail=f"Target server returned status {status_code}"
                )

            html_content = response_content.decode('utf-8', errors='ignore')
            soup = BeautifulSoup(html_content, 'lxml')

            script_tag = soup.find('script', id="preloadedData")
            if not script_tag:
                logger.error("No script tag found with id='preloadedData'")
                raise HTTPException(
                    status_code=404,
                    detail="No script tag found with id='preloadedData' in the page"
                )

            script_text = script_tag.text.strip()

            preloaded_state_marker = 'window.__PRELOADED_STATE__ = '
            start_index = script_text.find(preloaded_state_marker)

            if start_index == -1:
                logger.error("window.__PRELOADED_STATE__ marker not found in script")
                raise HTTPException(
                    status_code=404,
                    detail="window.__PRELOADED_STATE__ marker not found in script tag"
                )

            json_start = start_index + len(preloaded_state_marker)
            json_text = script_text[json_start:].strip()

            try:
                json_text_cleaned = json_text
                if json_text_cleaned.endswith(';'):
                    json_text_cleaned = json_text_cleaned[:-1]
                preloaded_data = json.loads(json_text_cleaned)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {e}")
                try:
                    brace_count = 0
                    json_end = 0
                    for i, char in enumerate(json_text):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                json_end = i + 1
                                break

                    if json_end > 0:
                        json_text_cleaned = json_text[:json_end]
                        preloaded_data = json.loads(json_text_cleaned)
                    else:
                        raise HTTPException(
                            status_code=500,
                            detail=f"Failed to extract valid JSON: {str(e)}"
                        )
                except Exception as parse_error:
                    logger.error(f"Failed to parse JSON after cleanup: {parse_error}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Failed to parse JSON from script tag: {str(parse_error)}"
                    )

            processing_time = int((time.time() - start_time) * 1000)
            logger.info(f"ZonaProp request completed successfully in {processing_time}ms")

            return JSONResponse(content=preloaded_data)

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error processing ZonaProp request: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
