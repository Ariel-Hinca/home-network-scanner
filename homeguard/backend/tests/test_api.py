import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

LOCAL = {"X-HomeGuard-Request": "1"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    database = tmp_path / "homeguard.db"
    monkeypatch.setenv("HOMEGUARD_DATABASE_URL", f"sqlite:///{database.as_posix()}")
    from app.config import get_settings

    get_settings.cache_clear()
    from app.main import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_health_reports_scope_policy(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["api_host"] == "127.0.0.1"
    assert body["scope_policy"]["allowed_ranges"] == [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]
    assert body["scope_policy"]["max_scope"] == "/16"
    assert body["scope_policy"]["default_scope"] == "/24"
    assert body["scope_policy"]["scan_scope"] == "/24"
    assert body["nmap"] in {"ok", "missing"}


def test_validate_rejects_public_cidr(client: TestClient) -> None:
    response = client.post("/api/networks/validate", json={"cidr": "8.8.8.0/24"}, headers=LOCAL)
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "public_range"


def test_validate_rejects_scope_larger_than_16(client: TestClient) -> None:
    response = client.post("/api/networks/validate", json={"cidr": "10.0.0.0/8"}, headers=LOCAL)
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "scope_too_large"


def test_validate_accepts_private_24(client: TestClient) -> None:
    response = client.post("/api/networks/validate", json={"cidr": "192.168.50.0/24"}, headers=LOCAL)
    assert response.status_code == 200
    body = response.json()
    assert body["cidr"] == "192.168.50.0/24"
    assert body["private"] is True
    assert body["within_max_scope"] is True


def test_mutating_call_requires_local_header(client: TestClient) -> None:
    response = client.post("/api/networks/validate", json={"cidr": "192.168.1.0/24"})
    assert response.status_code == 403


def test_saving_a_network_requires_a_session(client: TestClient) -> None:
    response = client.post(
        "/api/networks",
        json={"name": "Home", "cidr": "192.168.1.0/24"},
        headers=LOCAL,
    )
    assert response.status_code == 401


def test_setup_then_save_private_network(client: TestClient) -> None:
    created = client.post("/api/setup", json={"passphrase": "correct horse battery"}, headers=LOCAL)
    assert created.status_code == 201
    assert created.json()["authenticated"] is True

    saved = client.post(
        "/api/networks",
        json={"name": "Home", "cidr": "192.168.1.40/24"},
        headers=LOCAL,
    )
    assert saved.status_code == 201
    assert saved.json()["cidr"] == "192.168.1.0/24"
    assert saved.json()["ownership_confirmed"] is False

    rejected = client.post(
        "/api/networks",
        json={"name": "Elsewhere", "cidr": "203.0.113.0/24"},
        headers=LOCAL,
    )
    assert rejected.status_code == 400
    listing = client.get("/api/networks")
    assert [row["cidr"] for row in listing.json()] == ["192.168.1.0/24"]


DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <hostnames><hostname name="laptop.home" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.30" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="closed"/></port></ports>
  </host>
</nmaprun>
"""


def _sign_in(client: TestClient) -> None:
    created = client.post("/api/setup", json={"passphrase": "correct horse battery"}, headers=LOCAL)
    assert created.status_code == 201


def _save(client: TestClient, cidr: str = "192.168.1.0/24") -> int:
    saved = client.post("/api/networks", json={"name": "Home", "cidr": cidr}, headers=LOCAL)
    assert saved.status_code == 201
    return saved.json()["id"]


def _wait(client: TestClient, scan_id: int, timeout: float = 5) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        last = response.json()
        if last["status"] in {"completed", "failed", "cancelled"}:
            return last
        time.sleep(0.05)
    raise AssertionError(f"scan stayed {last.get('status')}")


def test_discovery_records_only_devices_that_answered(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(_nmap_bin, _cidr, xml_path: Path, _cancel_event, _timeout_seconds, _on_process=None):
        xml_path.write_text(DISCOVERY_XML, encoding="utf-8")
        return "completed"

    monkeypatch.setattr("app.workers.scan_worker.find_nmap", lambda _path: "nmap-test")
    monkeypatch.setattr("app.workers.scan_worker.run_discovery", fake)
    _sign_in(client)
    network_id = _save(client)
    confirmed = client.post(f"/api/networks/{network_id}/confirm", headers=LOCAL)
    assert confirmed.status_code == 200
    assert confirmed.json()["ownership_confirmed"] is True

    started = client.post(
        "/api/scans",
        json={"network_id": network_id, "profile": "discovery"},
        headers=LOCAL,
    )
    assert started.status_code == 201
    finished = _wait(client, started.json()["id"])
    assert finished["status"] == "completed"
    assert finished["host_count"] == 1
    hosts = client.get(f"/api/scans/{finished['id']}/hosts")
    assert hosts.status_code == 200
    assert hosts.json() == [{"ip": "192.168.1.20", "hostname": "laptop.home", "state": "up"}]


def test_discovery_requires_confirmation(client: TestClient) -> None:
    _sign_in(client)
    network_id = _save(client)
    started = client.post(
        "/api/scans",
        json={"network_id": network_id, "profile": "discovery"},
        headers=LOCAL,
    )
    assert started.status_code == 409
    assert started.json()["detail"]["code"] == "ownership_required"


def test_discovery_rejects_a_network_larger_than_24(client: TestClient) -> None:
    _sign_in(client)
    network_id = _save(client, "10.10.0.0/16")
    confirmed = client.post(f"/api/networks/{network_id}/confirm", headers=LOCAL)
    assert confirmed.status_code == 200
    started = client.post(
        "/api/scans",
        json={"network_id": network_id, "profile": "discovery"},
        headers=LOCAL,
    )
    assert started.status_code == 400
    assert started.json()["detail"]["code"] == "scan_scope_too_large"


def test_second_discovery_is_rejected_while_one_is_running(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(_nmap_bin, _cidr, _xml_path, cancel_event, _timeout_seconds, _on_process=None):
        cancel_event.wait(2)
        return "cancelled"

    monkeypatch.setattr("app.workers.scan_worker.find_nmap", lambda _path: "nmap-test")
    monkeypatch.setattr("app.workers.scan_worker.run_discovery", fake)
    _sign_in(client)
    network_id = _save(client)
    assert client.post(f"/api/networks/{network_id}/confirm", headers=LOCAL).status_code == 200
    first = client.post("/api/scans", json={"network_id": network_id, "profile": "discovery"}, headers=LOCAL)
    assert first.status_code == 201
    deadline = time.time() + 3
    while time.time() < deadline:
        if client.get(f"/api/scans/{first.json()['id']}").json()["status"] == "running":
            break
        time.sleep(0.05)
    second = client.post("/api/scans", json={"network_id": network_id, "profile": "discovery"}, headers=LOCAL)
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "scan_in_progress"
    cancelled = client.post(f"/api/scans/{first.json()['id']}/cancel", headers=LOCAL)
    assert cancelled.status_code == 200
    assert _wait(client, first.json()["id"])["status"] == "cancelled"


def test_duplicate_network_is_rejected_and_a_saved_network_can_be_removed(client: TestClient) -> None:
    _sign_in(client)
    network_id = _save(client)
    duplicate = client.post(
        "/api/networks",
        json={"name": "Wi-Fi", "cidr": "192.168.1.0/24"},
        headers=LOCAL,
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "network_already_saved"

    removed = client.delete(f"/api/networks/{network_id}", headers=LOCAL)
    assert removed.status_code == 204
    assert client.get("/api/networks").json() == []


def test_scan_start_requires_a_session(client: TestClient) -> None:
    response = client.post("/api/scans", json={"network_id": 1, "profile": "discovery"}, headers=LOCAL)
    assert response.status_code == 401
    assert client.get("/api/scans").status_code == 401
