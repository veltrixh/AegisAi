import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, Any, List, Set
from bs4 import BeautifulSoup
from backend.scanners.base import BaseScanner
from backend.models.finding import FindingModel
from backend.utils.http_client import ScannerResponse, AsyncScannerClient
from backend.utils.logger import logger

class DiscoveryScanner(BaseScanner):
    """
    Discovery engine: Crawls target, parses baseline responses,
    extracts links, forms, parameters, and input fields to seed active scans.
    """
    name = "Discovery & Reconnaissance Engine"
    vulnerability_type = "discovery"
    category = "passive"

    async def scan(self, target: str, context: Dict[str, Any]) -> List[FindingModel]:
        logger.info(f"Starting target discovery on: {target}")
        if not self.client:
            self.client = AsyncScannerClient()

        # Step 1: Baseline Request
        baseline: ScannerResponse = await self.client.get(target)
        context["baseline"] = baseline

        discovered_endpoints: Set[str] = {target}
        discovered_forms: List[Dict[str, Any]] = []
        discovered_params: Set[str] = set()

        # Parse query params from target
        parsed_target = urlparse(target)
        if parsed_target.query:
            for param in parse_qs(parsed_target.query).keys():
                discovered_params.add(param)

        # Parse HTML if response is valid
        if baseline.is_success and baseline.text:
            try:
                soup = BeautifulSoup(baseline.text, "html.parser")

                # Extract Links
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("#") or href.startswith("javascript:"):
                        continue
                    full_url = urljoin(target, href)
                    parsed_url = urlparse(full_url)
                    if parsed_url.netloc == parsed_target.netloc:
                        discovered_endpoints.add(full_url)
                        if parsed_url.query:
                            for param in parse_qs(parsed_url.query).keys():
                                discovered_params.add(param)

                # Extract Forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    form_url = urljoin(target, action) if action else target
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        inp_type = inp.get("type", "text")
                        val = inp.get("value", "")
                        if name:
                            inputs.append({"name": name, "type": inp_type, "value": val})
                            discovered_params.add(name)
                    discovered_forms.append({
                        "url": form_url,
                        "method": method,
                        "inputs": inputs,
                        "has_csrf_token": any(
                            any(token in inp["name"].lower() for token in ["csrf", "_token", "xsrf"])
                            for inp in inputs
                        )
                    })
            except Exception as e:
                logger.warning(f"Error parsing HTML during discovery: {e}")

        # Common parameter defaults if none discovered
        if not discovered_params:
            discovered_params.update(["id", "q", "search", "query", "user", "page", "redirect", "url", "file"])

        context["discovered_endpoints"] = list(discovered_endpoints)[:20]
        context["discovered_forms"] = discovered_forms
        context["discovered_params"] = list(discovered_params)
        logger.info(
            f"Discovery complete: Found {len(discovered_endpoints)} endpoints, "
            f"{len(discovered_forms)} forms, {len(discovered_params)} parameters."
        )

        return []  # Discovery populates context for other scanners
