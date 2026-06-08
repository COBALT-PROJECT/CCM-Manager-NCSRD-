import uuid


def test_metrics_crud(http, base_url):
    metric_id = f"metric-{uuid.uuid4()}"
    payload = {
        "id": metric_id,
        "name": "Metric",
        "description": "Test metric",
    }

    response = http.post(f"{base_url}/metrics", json=payload)
    assert response.status_code == 201

    response = http.get(f"{base_url}/metrics/{metric_id}")
    assert response.status_code == 200
    assert response.json().get("id") == metric_id

    response = http.get(f"{base_url}/metrics/{metric_id}-missing")
    assert response.status_code == 404


def test_metrics_list(http, base_url):
    response = http.get(f"{base_url}/metrics")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_metrics_requires_json(http, base_url):
    response = http.post(f"{base_url}/metrics", data="")
    assert response.status_code == 400


def test_metrics_requires_id(http, base_url):
    response = http.post(f"{base_url}/metrics", json={"name": "Missing id"})

    assert response.status_code == 400
    assert "id" in response.json().get("error", "")


def test_metrics_bulk_upsert(http, base_url):
    metric_ids = [f"metric-{uuid.uuid4()}", f"metric-{uuid.uuid4()}"]

    response = http.put(
        f"{base_url}/metrics",
        json=[
            {"id": metric_ids[0], "name": "Metric 1"},
            {"id": metric_ids[1], "name": "Metric 2"},
        ],
    )

    assert response.status_code == 201
    assert "2 metrics saved" in response.json().get("message", "")

    response = http.get(f"{base_url}/metrics/{metric_ids[0]}")
    assert response.status_code == 200


def test_risks_crud(http, base_url):
    risk_id = f"risk-{uuid.uuid4()}"
    payload = {
        "risk_id": risk_id,
        "risk_name": "Risk",
    }

    response = http.post(f"{base_url}/risks", json=payload)
    assert response.status_code == 201

    response = http.get(f"{base_url}/risks/{risk_id}")
    assert response.status_code == 200
    assert response.json().get("risk_id") == risk_id

    response = http.get(f"{base_url}/risks/{risk_id}-missing")
    assert response.status_code == 404


def test_risks_requires_json(http, base_url):
    response = http.post(f"{base_url}/risks", data="")
    assert response.status_code == 400


def test_risks_requires_risk_id(http, base_url):
    response = http.post(f"{base_url}/risks", json={"risk_name": "Missing id"})

    assert response.status_code == 400
    assert "risk_id" in response.json().get("error", "")


def test_threats_crud(http, base_url):
    threat_id = f"threat-{uuid.uuid4()}"
    payload = {
        "threat_id": threat_id,
        "name": "Threat",
    }

    response = http.post(f"{base_url}/threats", json=payload)
    assert response.status_code == 201

    response = http.get(f"{base_url}/threats/{threat_id}")
    assert response.status_code == 200
    assert response.json().get("threat_id") == threat_id

    response = http.get(f"{base_url}/threats/{threat_id}-missing")
    assert response.status_code == 404


def test_threats_requires_json(http, base_url):
    response = http.post(f"{base_url}/threats", data="")

    assert response.status_code == 400


def test_threats_requires_threat_id(http, base_url):
    response = http.post(f"{base_url}/threats", json={"name": "Missing id"})

    assert response.status_code == 400
    assert "threat_id" in response.json().get("error", "")


def test_controls_crud(http, base_url):
    control_id = f"control-{uuid.uuid4()}"
    payload = {
        "control_id": control_id,
        "name": "Control",
    }

    response = http.post(f"{base_url}/controls", json=payload)
    assert response.status_code == 201

    response = http.get(f"{base_url}/controls/{control_id}")
    assert response.status_code == 200
    assert response.json().get("control_id") == control_id

    response = http.get(f"{base_url}/controls/{control_id}-missing")
    assert response.status_code == 404


def test_controls_requires_json(http, base_url):
    response = http.post(f"{base_url}/controls", data="")
    assert response.status_code == 400


def test_controls_requires_identifier(http, base_url):
    response = http.post(f"{base_url}/controls", json={"name": "Missing id"})

    assert response.status_code == 400
    assert "control_id" in response.json().get("error", "")


def test_controls_accepts_associated_control_requirement_as_identifier(http, base_url):
    control_id = f"control-{uuid.uuid4()}"
    payload = {
        "associated_control_requirement": control_id,
        "name": "Control",
    }

    response = http.post(f"{base_url}/controls", json=payload)
    assert response.status_code == 201

    response = http.get(f"{base_url}/controls/{control_id}")
    assert response.status_code == 200
    assert response.json().get("control_id") == control_id
