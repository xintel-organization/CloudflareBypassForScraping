from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, HttpUrl, field_validator


class CookieRequest(BaseModel):
    """Request model for cookie endpoint."""
    url: HttpUrl = Field(..., description="Target URL to get cookies for")
    retries: int = Field(5, ge=1, le=10, description="Number of retry attempts")
    proxy: Optional[str] = Field(None, description="Proxy URL (optional)")
    
    @field_validator('proxy')
    @classmethod
    def validate_proxy(cls, v):
        if v and not v.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            raise ValueError('Proxy must start with http://, https://, socks4://, or socks5://')
        return v


class CookieResponse(BaseModel):
    """Response model for cookie endpoint."""
    cookies: Dict[str, str] = Field(..., description="Generated cookies")
    user_agent: str = Field(..., description="User agent used for cookie generation")


class HeadersMetadata(BaseModel):
    """Metadata for cached headers."""
    timestamp: str = Field(..., description="When the cookies were generated (ISO format)")
    expires_at: str = Field(..., description="When the cookies expire (ISO format)")


class HeadersResponse(BaseModel):
    """Response model for get-headers endpoint."""
    cookies: Dict[str, str] = Field(..., description="Generated cookies")
    user_agent: str = Field(..., description="User agent used for cookie generation")
    metadata: HeadersMetadata = Field(..., description="Cache metadata")
    formatted_headers: str = Field(..., description="HTTP-ready headers (Cookie and User-Agent)")


class MirrorRequestHeaders(BaseModel):
    """Headers model for mirror requests."""
    x_hostname: str = Field(..., alias="x-hostname", description="Target hostname")
    x_proxy: Optional[str] = Field(None, alias="x-proxy", description="Proxy URL (optional)")
    x_bypass_cache: Optional[bool] = Field(False, alias="x-bypass-cache", description="Bypass cookie cache")
    
    @field_validator('x_proxy')
    @classmethod
    def validate_proxy(cls, v):
        if v and not v.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            raise ValueError('Proxy must start with http://, https://, socks4://, or socks5://')
        return v
    
    @field_validator('x_hostname')
    @classmethod
    def validate_hostname(cls, v):
        if not v or v.strip() == '':
            raise ValueError('x-hostname cannot be empty')
        return v.strip()


class MirrorResponse(BaseModel):
    """Response model for mirror requests."""
    status_code: int = Field(..., description="HTTP status code from target")
    headers: Dict[str, str] = Field(..., description="Response headers from target")
    content_length: int = Field(..., description="Length of response content")
    content_type: Optional[str] = Field(None, description="Content type of response")


class ZonapropBatchRequest(BaseModel):
    """Request body for the parallel ZonaProp batch endpoint."""
    paths: List[str] = Field(
        ...,
        min_length=1,
        description="List of path (+ optional query string) entries to fetch, e.g. "
                    "['departamentos-venta.html', 'departamentos-venta-pagina-2.html']",
    )
    concurrency: int = Field(
        15, ge=1, le=50,
        description="Max number of pages fetched in parallel (cf_clearance is reused across all)",
    )

    @field_validator('paths')
    @classmethod
    def validate_paths(cls, v):
        cleaned = [p.strip() for p in v if p and p.strip()]
        if not cleaned:
            raise ValueError('paths must contain at least one non-empty entry')
        return cleaned


class ZonapropPageResult(BaseModel):
    """Result for a single page within a batch."""
    path: str = Field(..., description="The requested path")
    status: str = Field(..., description="'ok' or 'error'")
    status_code: Optional[int] = Field(None, description="HTTP status code from the target")
    data: Optional[Any] = Field(None, description="Parsed __PRELOADED_STATE__ JSON (when status == 'ok')")
    error: Optional[str] = Field(None, description="Error message (when status == 'error')")


class ZonapropBatchResponse(BaseModel):
    """Response for the parallel ZonaProp batch endpoint."""
    total: int = Field(..., description="Number of pages requested")
    succeeded: int = Field(..., description="Number of pages parsed successfully")
    failed: int = Field(..., description="Number of pages that failed")
    elapsed_ms: int = Field(..., description="Total wall-clock time for the batch")
    results: List[ZonapropPageResult] = Field(..., description="Per-page results, in request order")


class CacheStatsResponse(BaseModel):
    """Response model for cache statistics."""
    cached_entries: int = Field(..., description="Number of active cached entries")
    total_hostnames: int = Field(..., description="Total number of hostnames in cache")
    hostnames: List[str] = Field(..., description="List of cached hostnames")


class CacheClearResponse(BaseModel):
    """Response model for cache clear operation."""
    status: str = Field(..., description="Operation status")
    message: str = Field(..., description="Operation message")


class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code")
    timestamp: Optional[str] = Field(None, description="Error timestamp")


class MirrorRequestInfo(BaseModel):
    """Information about a mirror request for logging/debugging."""
    method: str = Field(..., description="HTTP method")
    hostname: str = Field(..., description="Target hostname")
    path: str = Field(..., description="Request path")
    proxy_used: Optional[str] = Field(None, description="Proxy used (if any)")
    cache_bypassed: bool = Field(False, description="Whether cache was bypassed")
    attempt_number: int = Field(1, description="Attempt number")
    max_attempts: int = Field(3, description="Maximum attempts")


class CookieGenerationInfo(BaseModel):
    """Information about cookie generation process."""
    hostname: str = Field(..., description="Target hostname")
    cache_hit: bool = Field(..., description="Whether cookies were found in cache")
    generation_time_ms: Optional[int] = Field(None, description="Time taken to generate cookies (ms)")
    user_agent: str = Field(..., description="User agent used")
    cookie_count: int = Field(..., description="Number of cookies generated")
    cf_cookies: List[str] = Field(..., description="List of Cloudflare-specific cookie names")


class ProxyInfo(BaseModel):
    """Proxy configuration information."""
    proxy_url: str = Field(..., description="Proxy URL")
    proxy_type: str = Field(..., description="Proxy type (http, https, socks4, socks5)")
    has_auth: bool = Field(..., description="Whether proxy has authentication")
    
    @field_validator('proxy_type')
    @classmethod
    def validate_proxy_type(cls, v):
        allowed_types = ['http', 'https', 'socks4', 'socks5']
        if v not in allowed_types:
            raise ValueError(f'Proxy type must be one of: {allowed_types}')
        return v


class BrowserConfigInfo(BaseModel):
    """Browser configuration information."""
    os: str = Field(..., description="Operating system used")
    firefox_version: int = Field(..., description="Firefox version")
    screen_resolution: str = Field(..., description="Screen resolution")
    user_agent: str = Field(..., description="Generated user agent")
    language: str = Field(..., description="Browser language")


class BypassAttemptResult(BaseModel):
    """Result of a bypass attempt."""
    success: bool = Field(..., description="Whether bypass was successful")
    attempt_number: int = Field(..., description="Attempt number")
    challenge_type: Optional[str] = Field(None, description="Type of challenge encountered")
    time_taken_ms: int = Field(..., description="Time taken for this attempt")
    error_message: Optional[str] = Field(None, description="Error message if failed")