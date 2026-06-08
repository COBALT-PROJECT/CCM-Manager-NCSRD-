def test_health_check(http, base_url):
    response = http.get(f"{base_url}/")
    assert response.status_code == 200
    payload = response.json()
    assert "message" in payload


def test_auth_status(http, base_url):
    response = http.get(f"{base_url}/auth/status")
    assert response.status_code == 200
    payload = response.json()
    assert "auth_enabled" in payload
    assert "status" in payload
