"""One process serves the API and the built UI; API routes always win; no build means API only."""
import importlib

import pytest
from fastapi.testclient import TestClient


def _load_app(monkeypatch, dist):
    if dist is None:
        monkeypatch.delenv("FRONTEND_DIST", raising=False)
    else:
        monkeypatch.setenv("FRONTEND_DIST", str(dist))
    import app.main as main

    return importlib.reload(main).app


@pytest.fixture
def dist(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<html><body>UI-INDEX</body></html>", encoding="utf-8")
    (tmp_path / "assets" / "app.js").write_text("console.log('ui')", encoding="utf-8")
    return tmp_path


def test_the_built_ui_is_served_at_the_root_and_assets_resolve(monkeypatch, dist):
    client = TestClient(_load_app(monkeypatch, dist))
    root = client.get("/")
    assert root.status_code == 200 and "UI-INDEX" in root.text
    assert client.get("/assets/app.js").text == "console.log('ui')"


def test_api_routes_win_over_the_ui_mount(monkeypatch, dist):
    client = TestClient(_load_app(monkeypatch, dist))
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/analyze/not-a-job").status_code == 404  # the API's own 404, not the UI's
    assert "UI-INDEX" not in client.get("/analyze/not-a-job").text
    assert client.post("/analyze", files={"file": ("x.txt", b"hello")}).status_code == 400  # the real upload rule still applies


def test_without_a_build_only_the_api_is_served(monkeypatch, tmp_path):
    client = TestClient(_load_app(monkeypatch, tmp_path / "does-not-exist"))
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 404


def test_a_missing_file_is_a_404_not_a_server_error(monkeypatch, dist):
    client = TestClient(_load_app(monkeypatch, dist))
    assert client.get("/nope.js").status_code == 404


def test_path_traversal_cannot_leave_the_ui_directory(monkeypatch, dist):
    (dist.parent / "secret.txt").write_text("TOP-SECRET", encoding="utf-8")
    client = TestClient(_load_app(monkeypatch, dist))
    for path in ("/../secret.txt", "/..%2fsecret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt"):
        assert "TOP-SECRET" not in client.get(path).text


def test_reload_leaves_the_module_usable_for_other_tests(monkeypatch):
    app = _load_app(monkeypatch, None)  # restore the default for later tests
    assert TestClient(app).get("/health").status_code == 200
