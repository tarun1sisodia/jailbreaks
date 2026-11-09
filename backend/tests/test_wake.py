"""Wake endpoint: secret-gated, no keepalive, honest 202 while waking."""

import os

os.environ["WEBPROBE_API_KEY"] = "test-key"

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("WAKE_SECRET", raising=False)
    monkeypatch.delenv("INSTABOX_API_KEY", raising=False)
    yield


def test_wake_not_configured_returns_503():
    client = TestClient(server.app)
    response = client.post("/api/wake/box6", headers={"X-Wake-Secret": "anything"})
    assert response.status_code == 503


def test_wake_wrong_secret_returns_401(monkeypatch):
    monkeypatch.setenv("WAKE_SECRET", "correct-secret")
    client = TestClient(server.app)
    response = client.post("/api/wake/box6", headers={"X-Wake-Secret": "wrong-secret"})
    assert response.status_code == 401


def test_wake_without_instabox_key_returns_503(monkeypatch):
    monkeypatch.setenv("WAKE_SECRET", "correct-secret")
    client = TestClient(server.app)
    response = client.post("/api/wake/box6", headers={"X-Wake-Secret": "correct-secret"})
    assert response.status_code == 503


def test_wake_ready_returns_200(monkeypatch):
    monkeypatch.setenv("WAKE_SECRET", "correct-secret")
    monkeypatch.setattr(server, "_wake_box6", lambda: {"ready": True, "state": "running", "woke": True})
    client = TestClient(server.app)
    response = client.post("/api/wake/box6", headers={"X-Wake-Secret": "correct-secret"})
    assert response.status_code == 200
    assert response.json()["ready"] is True


def test_wake_still_waking_returns_202_not_silent_success(monkeypatch):
    monkeypatch.setenv("WAKE_SECRET", "correct-secret")
    monkeypatch.setattr(server, "_wake_box6", lambda: {"ready": False, "state": "suspended", "woke": True})
    client = TestClient(server.app)
    response = client.post("/api/wake/box6", headers={"X-Wake-Secret": "correct-secret"})
    assert response.status_code == 202
    assert response.json()["ready"] is False
