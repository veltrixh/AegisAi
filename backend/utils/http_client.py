import asyncio
import time
from typing import Optional, Dict, Any, Tuple
import httpx
from backend.utils.logger import logger
from backend.utils.sanitizer import sanitize_headers, truncate_snippet

DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "AEGIS-AI-Security-Scanner/2.0 (Security Audit Engine)"

class ScannerResponse:
    """Standardized response container for deterministic scanner analysis."""
    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        text: str,
        elapsed_ms: float,
        url: str,
        method: str,
        error: Optional[str] = None
    ):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.elapsed_ms = elapsed_ms
        self.url = url
        self.method = method
        self.length = len(text.encode("utf-8", errors="ignore"))
        self.error = error

    @property
    def is_success(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "response_time_ms": round(self.elapsed_ms, 2),
            "content_length": self.length,
            "headers": sanitize_headers(self.headers),
            "error": self.error,
        }

class AsyncScannerClient:
    """
    High-performance, rate-limited, resilient HTTP client designed
    for security probing and deterministic evidence capture.
    """
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_concurrency: int = 10,
        requests_per_sec: float = 20.0,
        verify_ssl: bool = False,
        user_agent: str = DEFAULT_USER_AGENT,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.min_interval = 1.0 / max(requests_per_sec, 0.1) if requests_per_sec > 0 else 0
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()
        
        default_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if headers:
            default_headers.update(headers)

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=5.0),
            verify=verify_ssl,
            follow_redirects=False,
            proxy=proxy,
            headers=default_headers,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
        )

    async def _rate_limit(self):
        if self.min_interval > 0:
            async with self._lock:
                now = time.time()
                elapsed = now - self._last_request_time
                if elapsed < self.min_interval:
                    await asyncio.sleep(self.min_interval - elapsed)
                self._last_request_time = time.time()

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        retries: int = 1
    ) -> ScannerResponse:
        await self._rate_limit()

        async with self.semaphore:
            start_time = time.perf_counter()
            attempt = 0
            last_err = None

            while attempt <= retries:
                try:
                    res = await self.client.request(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=headers
                    )
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    return ScannerResponse(
                        status_code=res.status_code,
                        headers=dict(res.headers),
                        text=res.text,
                        elapsed_ms=elapsed_ms,
                        url=str(res.url),
                        method=method
                    )
                except httpx.RequestError as exc:
                    last_err = exc
                    attempt += 1
                    if attempt <= retries:
                        await asyncio.sleep(0.3 * attempt)
                except Exception as exc:
                    last_err = exc
                    break

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            err_msg = f"{type(last_err).__name__}: {str(last_err)}" if last_err else "Unknown error"
            logger.debug(f"Request failed for {method} {url}: {err_msg}")
            return ScannerResponse(
                status_code=0,
                headers={},
                text="",
                elapsed_ms=elapsed_ms,
                url=url,
                method=method,
                error=err_msg
            )

    async def get(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ScannerResponse:
        return await self.request("GET", url, params=params, headers=headers)

    async def post(self, url: str, data: Optional[Dict[str, Any]] = None, json_data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ScannerResponse:
        return await self.request("POST", url, data=data, json_data=json_data, headers=headers)

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
