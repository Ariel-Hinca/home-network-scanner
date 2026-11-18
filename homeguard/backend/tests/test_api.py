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


def test_scan_start_is_not_implemented(client: TestClient) -> None:
    response = client.post("/api/scans")
    assert response.status_code == 501
    assert response.json()["detail"]["code"] == "not_in_this_phase"
    assert client.get("/api/scans").json() == []
