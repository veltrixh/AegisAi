import pytest
import httpx
from tests.fixtures.vulnerable_app import app
from backend.utils.http_client import AsyncScannerClient
from backend.scanners.discovery import DiscoveryScanner
from backend.scanners.sqli import SQLInjectionScanner
from backend.scanners.xss import XSSScanner
from backend.scanners.csrf import CSRFScanner
from backend.scanners.ssrf import SSRFScanner
from backend.scanners.headers import SecurityHeadersScanner
from backend.scanners.api import APISecurityScanner

@pytest.fixture
def test_client():
    client = AsyncScannerClient()
    # Mock inner httpx client with ASGI transport pointing to vulnerable fixture app
    client.client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        follow_redirects=False
    )
    return client

@pytest.mark.asyncio
async def test_discovery_scanner(test_client):
    scanner = DiscoveryScanner(client=test_client)
    context = {}
    await scanner.scan("http://testserver/", context)

    assert "baseline" in context
    assert len(context["discovered_endpoints"]) >= 1
    assert len(context["discovered_forms"]) >= 1
    assert "id" in context["discovered_params"] or "username" in context["discovered_params"]

@pytest.mark.asyncio
async def test_sqli_scanner_detects_flaw(test_client):
    scanner = SQLInjectionScanner(client=test_client)
    context = {"discovered_params": ["id"]}
    findings = await scanner.scan("http://testserver/products", context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "SQL Injection"
    assert finding.parameter == "id"
    assert finding.confidence >= 80.0
    assert "mysql" in (finding.evidence.error_signature or "").lower()

@pytest.mark.asyncio
async def test_xss_scanner_detects_reflection(test_client):
    scanner = XSSScanner(client=test_client)
    context = {"discovered_params": ["q"]}
    findings = await scanner.scan("http://testserver/search", context)

    assert len(findings) == 1
    finding = findings[0]
    assert "Cross-Site Scripting" in finding.type
    assert finding.parameter == "q"
    assert finding.confidence >= 80.0

@pytest.mark.asyncio
async def test_csrf_scanner_detects_missing_token(test_client):
    scanner = CSRFScanner(client=test_client)
    context = {}
    findings = await scanner.scan("http://testserver/account", context)

    assert len(findings) == 1
    finding = findings[0]
    assert "CSRF" in finding.type
    assert finding.method == "POST"

@pytest.mark.asyncio
async def test_ssrf_scanner_detects_probe(test_client):
    scanner = SSRFScanner(client=test_client)
    context = {"discovered_params": ["url"]}
    findings = await scanner.scan("http://testserver/fetch", context)

    assert len(findings) >= 1
    finding = findings[0]
    assert "SSRF" in finding.type

@pytest.mark.asyncio
async def test_security_headers_scanner(test_client):
    scanner = SecurityHeadersScanner(client=test_client)
    context = {}
    findings = await scanner.scan("http://testserver/", context)

    assert len(findings) >= 1
    assert any("Security Headers" in f.type for f in findings)

@pytest.mark.asyncio
async def test_api_security_scanner(test_client):
    scanner = APISecurityScanner(client=test_client)
    context = {}
    findings = await scanner.scan("http://testserver/", context)

    assert len(findings) >= 1
    assert any("API" in f.type for f in findings)
