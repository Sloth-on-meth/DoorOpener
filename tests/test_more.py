"""Additional integration tests: battery edge cases and admin log parsing."""
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock


def client_app():
    from app import app as flask_app
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def test_battery_out_of_range_and_none_paths():
    import app as app_module

    # Out of range value
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"state": "150"}
    with patch.object(app_module.ha_client.session, "get", return_value=mock_response):
        c = client_app()
        response = c.get("/battery")
        assert response.get_json()["level"] is None

    # None value
    mock_response2 = MagicMock()
    mock_response2.status_code = 200
    mock_response2.json.return_value = {"state": None}
    with patch.object(app_module.ha_client.session, "get", return_value=mock_response2):
        c = client_app()
        response2 = c.get("/battery")
        assert response2.get_json()["level"] is None


def test_admin_logs_old_format_parsing():
    old_line = "2025-09-01T12:00:00Z - 1.2.3.4 - alice - SUCCESS - Door opened\n"
    from io import BytesIO

    file_obj = BytesIO(old_line.encode("utf-8"))
    with patch("os.path.exists", return_value=True), \
         patch("os.path.getsize", return_value=len(old_line.encode("utf-8"))), \
         patch("builtins.open", return_value=file_obj):
        c = client_app()
        with c.session_transaction() as s:
            s["admin_authenticated"] = True
            s["admin_login_time"] = datetime.now(timezone.utc).isoformat()
        r = c.get("/admin/logs")
        assert r.status_code == 200
        data = r.get_json()
        assert any(row.get("user") == "alice" for row in data.get("logs", []))
