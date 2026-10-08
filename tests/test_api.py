import pytest
import httpx
from backend.main import app

@pytest.mark.asyncio
async def test_api_health():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"

@pytest.mark.asyncio
async def test_api_scan_lifecycle():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Launch scan
        launch_res = await client.post("/api/scans", json={
            "target_url": "http://example.com",
            "profile": "quick"
        })
        assert launch_res.status_code == 200
        scan_data = launch_res.json()
        scan_id = scan_data["id"]
        assert scan_data["status"] in ("pending", "running", "completed")

        # Get scan details
        get_res = await client.get(f"/api/scans/{scan_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == scan_id

        # List scans
        list_res = await client.get("/api/scans")
        assert list_res.status_code == 200
        scans = list_res.json()
        assert any(s["id"] == scan_id for s in scans)

        # Cancel scan
        cancel_res = await client.post(f"/api/scans/{scan_id}/cancel")
        assert cancel_res.status_code == 200
