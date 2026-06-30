import asyncio
import logging
import os
import re
import time
import json
import secrets
from contextlib import asynccontextmanager
from typing import Optional, AsyncGenerator, Any, Dict
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from bs4 import BeautifulSoup

from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.core.mirror import RequestMirror
from cf_bypasser.server.models import ErrorResponse, ZonapropBatchRequest
from cf_bypasser.utils.misc import md5_hash

# Global instances
global_bypasser = None
global_mirror = None

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for FastAPI application startup and shutdown."""
    global global_bypasser, global_mirror

    logger.info("Starting Cloudflare Bypasser Server...")

    # if not os.environ.get("API_TOKEN", "").strip():
    #     logger.warning(
    #         "API_TOKEN env var is not set — all requests will be rejected with 503. "
    #         "Set API_TOKEN in your environment (e.g. docker-compose) to enable the API."
    #     )

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


# def verify_token(x_api_token: Optional[str] = Header(None)) -> None:
#     """Validate X-API-Token header against the API_TOKEN env var (fail closed)."""
#     expected = os.environ.get("API_TOKEN", "").strip()
#     if not expected:
#         logger.error("API_TOKEN env var is not set — refusing request")
#         raise HTTPException(status_code=503, detail="Server misconfigured: API_TOKEN not set")
#     if not x_api_token or not secrets.compare_digest(x_api_token, expected):
#         raise HTTPException(status_code=401, detail="Invalid or missing X-API-Token header")


def extract_preloaded_state(html_content: str) -> Any:
    """Extract and parse window.__PRELOADED_STATE__ from a ZonaProp page.

    Raises ValueError if the marker or valid JSON cannot be found.
    """
    soup = BeautifulSoup(html_content, 'lxml')

    script_tag = soup.find('script', id="preloadedData")
    if not script_tag:
        raise ValueError("No script tag found with id='preloadedData' in the page")

    script_text = script_tag.text.strip()

    preloaded_state_marker = 'window.__PRELOADED_STATE__ = '
    start_index = script_text.find(preloaded_state_marker)
    if start_index == -1:
        raise ValueError("window.__PRELOADED_STATE__ marker not found in script tag")

    json_start = start_index + len(preloaded_state_marker)
    json_text = script_text[json_start:].strip()

    # Use raw_decode so trailing content after the object (e.g. ";window.X=...")
    # is ignored. A naive brace count would miscount braces that appear inside
    # string values (property descriptions) and truncate the JSON.
    try:
        obj, _ = json.JSONDecoder().raw_decode(json_text)
        return obj
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to extract valid JSON: {e}")


def split_path_query(path_with_query: str) -> tuple[str, str]:
    """Split 'path?query' into ('/path', 'query'). Leading slash is normalized."""
    if '?' in path_with_query:
        path, query = path_with_query.split('?', 1)
    else:
        path, query = path_with_query, ''
    path = path.lstrip('/')
    return (f"/{path}" if path else "/", query)


def setup_routes(app: FastAPI):
    """Setup routes for the FastAPI application. Only /zonaprop is exposed."""

    @app.post("/zonaprop-batch")
    async def zonaprop_batch(request: Request, payload: ZonapropBatchRequest):
        """Fetch many ZonaProp pages in parallel, reusing a single cf_clearance.

        The Cloudflare clearance cookie is generated once (cached), then all pages
        are fetched concurrently with curl_cffi up to `concurrency` at a time.

        Required Headers:
        - x-hostname
        Optional Headers:
        - x-proxy, x-bypass-cache
        """
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
            raise HTTPException(status_code=400, detail="x-hostname header is required")
        if not is_safe_url(f"https://{hostname}"):
            raise HTTPException(
                status_code=400,
                detail="Invalid or unsafe hostname - localhost and private IPs are not allowed",
            )
        if proxy and not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            raise HTTPException(
                status_code=400,
                detail="x-proxy must start with http://, https://, socks4://, or socks5://",
            )

        mirror = global_mirror or RequestMirror(global_bypasser)

        # Prime the cf_clearance ONCE before fanning out. Without this, every
        # concurrent fetch would miss the cache and try to spawn its own browser.
        first_path, _ = split_path_query(payload.paths[0])
        prime_url = mirror.build_target_url(hostname, first_path)
        if bypass_cache:
            cache_key = md5_hash(urlparse(prime_url).netloc + (proxy or ""))
            mirror.bypasser.cookie_cache.invalidate(cache_key)
        cf_data = await mirror.bypasser.get_or_generate_cookies(prime_url, proxy)
        if not cf_data:
            raise HTTPException(
                status_code=502,
                detail="Failed to obtain Cloudflare clearance cookies for hostname",
            )

        logger.info(
            f"ZonaProp batch: {len(payload.paths)} pages, concurrency={payload.concurrency}, host={hostname}"
        )

        # Mirror headers passed through to each per-page request.
        base_headers: Dict[str, str] = {'x-hostname': hostname}
        if proxy:
            base_headers['x-proxy'] = proxy

        semaphore = asyncio.Semaphore(payload.concurrency)

        async def fetch_one(path_with_query: str) -> Dict[str, Any]:
            page_path, query_string = split_path_query(path_with_query)
            async with semaphore:
                try:
                    status_code, _resp_headers, content = await mirror.mirror_request(
                        method="GET",
                        path=page_path,
                        query_string=query_string,
                        headers=dict(base_headers),
                        body=None,
                    )
                    if status_code != 200:
                        return {
                            "path": path_with_query,
                            "status": "error",
                            "status_code": status_code,
                            "data": None,
                            "error": f"Target returned status {status_code}",
                        }
                    data = extract_preloaded_state(content.decode('utf-8', errors='ignore'))
                    return {
                        "path": path_with_query,
                        "status": "ok",
                        "status_code": status_code,
                        "data": data,
                        "error": None,
                    }
                except Exception as e:
                    return {
                        "path": path_with_query,
                        "status": "error",
                        "status_code": None,
                        "data": None,
                        "error": str(e),
                    }

        results = await asyncio.gather(*(fetch_one(p) for p in payload.paths))

        succeeded = sum(1 for r in results if r["status"] == "ok")
        elapsed_ms = int((time.time() - start_time) * 1000)
        logger.info(
            f"ZonaProp batch completed: {succeeded}/{len(results)} ok in {elapsed_ms}ms"
        )

        return JSONResponse(content={
            "total": len(results),
            "succeeded": succeeded,
            "failed": len(results) - succeeded,
            "elapsed_ms": elapsed_ms,
            "results": results,
        })

    @app.api_route(
        "/zonaprop/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    )
    async def zonaprop_request(request: Request, path: str = ""):
        """
        ZonaProp-specific endpoint that extracts preloaded state JSON from the page.

        Required Headers:
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
            try:
                preloaded_data = extract_preloaded_state(html_content)
            except ValueError as e:
                logger.error(f"Failed to extract preloaded state: {e}")
                raise HTTPException(status_code=502, detail=str(e))

            processing_time = int((time.time() - start_time) * 1000)
            logger.info(f"ZonaProp request completed successfully in {processing_time}ms")

            return JSONResponse(content=preloaded_data)

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error processing ZonaProp request: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
