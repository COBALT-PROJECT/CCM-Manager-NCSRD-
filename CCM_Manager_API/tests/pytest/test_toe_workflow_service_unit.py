from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from services import toe_service, toe_workflow_service


pytestmark = pytest.mark.unit


class DummyResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("No JSON response")
        return self._payload


def test_schedule_is_disabled_by_default(monkeypatch):
    collection = Mock()
    monkeypatch.setattr(toe_workflow_service, "TOE_ID_HANDOFF_ENABLED", False)
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)

    result = toe_workflow_service.schedule_toe_workflow("toe-123")

    assert result["status"] == "disabled"
    collection.update_one.assert_not_called()


def test_schedule_upserts_by_actual_toe_id(monkeypatch):
    collection = Mock()
    now = datetime(2026, 7, 30, 12, 0, 0)
    collection.find_one.return_value = {
        "toe_id": "toe-actual",
        "state": "pending_handoff",
        "next_run_at": now,
    }
    monkeypatch.setattr(toe_workflow_service, "TOE_ID_HANDOFF_ENABLED", True)
    monkeypatch.setattr(toe_workflow_service, "SDT_ID_SYNC_ENABLED", True)
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)

    result = toe_workflow_service.schedule_toe_workflow(
        "toe-actual",
        sdt_attempt_status="failed",
        sdt_attempt_status_code=502,
        now=now,
    )

    first_call = collection.update_one.call_args_list[0]
    assert first_call.args[0] == {"toe_id": "toe-actual"}
    assert first_call.kwargs["upsert"] is True
    assert first_call.args[1]["$set"]["sdt_attempt_status"] == "failed"
    assert first_call.args[1]["$set"]["sdt_attempt_status_code"] == 502
    assert result == {
        "status": "scheduled",
        "toe_id": "toe-actual",
        "state": "pending_handoff",
        "next_run_at": now,
    }


def test_claim_due_job_uses_atomic_lease(monkeypatch):
    collection = Mock()
    now = datetime(2026, 7, 30, 12, 0, 0)
    collection.find_one_and_update.return_value = {"toe_id": "toe-actual"}
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)
    monkeypatch.setattr(toe_workflow_service, "TOE_WORKFLOW_LEASE_SECONDS", 90)

    result = toe_workflow_service.claim_due_job("worker-1", now=now)

    assert result == {"toe_id": "toe-actual"}
    call = collection.find_one_and_update.call_args
    assert call.args[0]["enabled"] is True
    assert call.args[1]["$set"]["lease_owner"] == "worker-1"
    assert call.args[1]["$set"]["lease_until"] == now + timedelta(seconds=90)
    assert call.kwargs["sort"] == [("next_run_at", 1)]


def test_worker_startup_reactivates_persisted_jobs(monkeypatch):
    collection = Mock()
    now = datetime(2026, 7, 30, 12, 0, 0)
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)
    monkeypatch.setattr(toe_workflow_service, "TOE_ID_HANDOFF_ENABLED", True)
    monkeypatch.setattr(toe_workflow_service, "SDT_ID_SYNC_ENABLED", True)

    toe_workflow_service.activate_completed_handoffs_for_sync(now=now)

    assert collection.update_many.call_count == 2
    pending_filter = collection.update_many.call_args_list[0].args[0]
    pending_update = collection.update_many.call_args_list[0].args[1]["$set"]
    sync_update = collection.update_many.call_args_list[1].args[1]["$set"]
    assert pending_update["state"] == "pending_handoff"
    assert pending_update["next_run_at"] == now
    assert {"lease_until": {"$lte": now}} in pending_filter["$or"]
    assert sync_update["state"] == "id_sync_active"
    assert sync_update["next_run_at"] == now


def test_health_must_return_200_before_toe_id_is_sent(monkeypatch):
    collection = Mock()
    requests = []
    now = datetime(2026, 7, 30, 12, 0, 0)

    def fake_authed_request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        return DummyResponse(503, {"status": "starting"})

    monkeypatch.setattr(toe_workflow_service, "TOE_ID_HANDOFF_ENABLED", True)
    monkeypatch.setattr(
        toe_workflow_service,
        "TOE_CONNECTOR_HEALTH_URL",
        "http://connector.test/health",
    )
    monkeypatch.setattr(
        toe_workflow_service,
        "TOE_CONNECTOR_ID_URL",
        "http://connector.test/api/IDSconnector/TOE/id",
    )
    monkeypatch.setattr(toe_workflow_service, "authed_request", fake_authed_request)
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)

    result = toe_workflow_service.process_claimed_job(
        {
            "_id": "job-1",
            "toe_id": "toe-actual",
            "handoff_status": "pending",
            "handoff_attempts": 0,
        },
        now=now,
    )

    assert result["status"] == "retrying"
    assert result["phase"] == "health"
    assert len(requests) == 1
    assert requests[0][0:2] == ("GET", "http://connector.test/health")
    update = collection.update_one.call_args.args[1]
    assert update["$set"]["last_status_code"] == 503
    assert update["$set"]["next_run_at"] > now


def test_healthy_connector_receives_actual_toe_id(monkeypatch):
    collection = Mock()
    requests = []
    now = datetime(2026, 7, 30, 12, 0, 0)

    def fake_authed_request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        if method == "GET":
            return DummyResponse(200, {"status": "healthy"})
        return DummyResponse(200, {"status": "accepted"})

    monkeypatch.setattr(toe_workflow_service, "TOE_ID_HANDOFF_ENABLED", True)
    monkeypatch.setattr(toe_workflow_service, "SDT_ID_SYNC_ENABLED", True)
    monkeypatch.setattr(
        toe_workflow_service,
        "TOE_CONNECTOR_HEALTH_URL",
        "http://connector.test/health",
    )
    monkeypatch.setattr(
        toe_workflow_service,
        "TOE_CONNECTOR_ID_URL",
        "http://connector.test/api/IDSconnector/TOE/id",
    )
    monkeypatch.setattr(toe_workflow_service, "TOE_CONNECTOR_ID_FIELD", "toe_id")
    monkeypatch.setattr(toe_workflow_service, "authed_request", fake_authed_request)
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)
    monkeypatch.setattr(
        toe_workflow_service,
        "auth_context",
        lambda service: {"service": service},
    )

    result = toe_workflow_service.process_claimed_job(
        {
            "_id": "job-1",
            "toe_id": "toe-actual",
            "handoff_status": "pending",
            "handoff_attempts": 0,
        },
        now=now,
    )

    assert result["status"] == "sent"
    assert requests == [
        (
            "GET",
            "http://connector.test/health",
            {"timeout": 15.0, "service": "toe_connector_health"},
        ),
        (
            "POST",
            "http://connector.test/api/IDSconnector/TOE/id",
            {
                "json": {"toe_id": "toe-actual"},
                "timeout": 15.0,
                "service": "toe_connector",
            },
        ),
    ]
    update = collection.update_one.call_args.args[1]
    assert update["$set"]["handoff_status"] == "sent"
    assert update["$set"]["state"] == "id_sync_active"
    assert update["$set"]["next_run_at"] == now


def test_unauthorized_handoff_keeps_retrying(monkeypatch):
    collection = Mock()
    now = datetime(2026, 7, 30, 12, 0, 0)

    def fake_authed_request(method, url, **kwargs):
        if method == "GET":
            return DummyResponse(200, {"status": "healthy"})
        return DummyResponse(401, {
            "detail": {
                "code": "INVALID_BEARER_TOKEN",
                "message": "Could not validate caller JWT with Authentication Manager.",
            }
        })

    monkeypatch.setattr(toe_workflow_service, "TOE_ID_HANDOFF_ENABLED", True)
    monkeypatch.setattr(toe_workflow_service, "TOE_CONNECTOR_RETRY_SECONDS", 30)
    monkeypatch.setattr(toe_workflow_service, "TOE_CONNECTOR_RETRY_MAX_SECONDS", 30)
    monkeypatch.setattr(
        toe_workflow_service,
        "TOE_CONNECTOR_HEALTH_URL",
        "http://connector.test/health",
    )
    monkeypatch.setattr(
        toe_workflow_service,
        "TOE_CONNECTOR_ID_URL",
        "http://connector.test/api/IDSconnector/TOE/id",
    )
    monkeypatch.setattr(toe_workflow_service, "authed_request", fake_authed_request)
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)

    result = toe_workflow_service.process_claimed_job(
        {
            "_id": "job-1",
            "toe_id": "toe-actual",
            "handoff_status": "retrying",
            "handoff_attempts": 42,
        },
        now=now,
    )

    assert result == {
        "status": "retrying",
        "phase": "send_toe_id",
        "next_run_at": now + timedelta(seconds=30),
    }
    update = collection.update_one.call_args.args[1]
    assert update["$set"]["handoff_status"] == "retrying"
    assert update["$set"]["last_status_code"] == 401
    assert update["$set"]["last_response"]["detail"]["code"] == "INVALID_BEARER_TOKEN"


def test_periodic_sync_uses_expected_query_parameters(monkeypatch):
    collection = Mock()
    requests = []
    now = datetime(2026, 7, 30, 12, 0, 0)

    def fake_authed_request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        return DummyResponse(200, {"status": "synchronized"})

    monkeypatch.setattr(toe_workflow_service, "SDT_ID_SYNC_ENABLED", True)
    monkeypatch.setattr(
        toe_workflow_service,
        "SDT_ID_SYNC_URL",
        "http://sdtm.test/api/SDT/sync/ids",
    )
    monkeypatch.setattr(toe_workflow_service, "SDT_ID_SYNC_INTERVAL_SECONDS", 300)
    monkeypatch.setattr(toe_workflow_service, "authed_request", fake_authed_request)
    monkeypatch.setattr(toe_workflow_service, "toe_workflow_jobs_col", collection)
    monkeypatch.setattr(
        toe_workflow_service,
        "auth_context",
        lambda service: {"service": service},
    )

    result = toe_workflow_service.process_claimed_job(
        {
            "_id": "job-1",
            "toe_id": "toe-actual",
            "handoff_status": "sent",
            "category": "AI",
            "data_path": "all",
            "sync_attempts": 0,
        },
        now=now,
    )

    assert result["status"] == "synchronized"
    assert requests == [
        (
            "GET",
            "http://sdtm.test/api/SDT/sync/ids",
            {
                "params": {
                    "category": "AI",
                    "toe_id": "toe-actual",
                    "data_path": "all",
                },
                "timeout": 15.0,
                "service": "sdt",
            },
        )
    ]
    update = collection.update_one.call_args.args[1]
    assert update["$set"]["next_run_at"] == now + timedelta(seconds=300)
    assert update["$set"]["sync_status"] == "synchronized"


def test_sdt_failure_still_schedules_connector_handoff(monkeypatch):
    toe_id = "toe-deployed-despite-500"
    scheduled = []
    monkeypatch.setattr(toe_service, "FORWARD_URL", "")
    monkeypatch.setattr(toe_service.toes_col, "update_one", Mock())
    monkeypatch.setattr(
        toe_service,
        "_sync_to_sdtm",
        lambda *args, **kwargs: (
            {
                "sdtm_status": "failed",
                "sdtm_attempted": True,
                "sdtm_status_code": 502,
                "sdtm_response": {"error": "Remote returned 500"},
            },
            502,
        ),
    )
    monkeypatch.setattr(
        toe_service.toe_workflow_service,
        "schedule_toe_workflow",
        lambda value, **kwargs: scheduled.append((value, kwargs))
        or {"status": "scheduled", "toe_id": value},
    )

    payload, status_code = toe_service.upload_toe_descriptor(
        {
            "component": {
                "component-definition": {
                    "components": [
                        {
                            "uuid": toe_id,
                            "title": "AI ToE",
                        }
                    ]
                }
            }
        },
        deploy_sdt=True,
    )

    assert status_code == 200
    assert payload["sdtm_status"] == "failed"
    assert payload["toe_id_handoff"]["status"] == "scheduled"
    assert scheduled == [
        (
            toe_id,
            {
                "sdt_attempt_status": "failed",
                "sdt_attempt_status_code": 502,
            },
        )
    ]


def test_predeployment_skip_does_not_schedule_handoff(monkeypatch):
    monkeypatch.setattr(toe_service, "FORWARD_URL", "")
    monkeypatch.setattr(toe_service.toes_col, "update_one", Mock())
    schedule = Mock()
    monkeypatch.setattr(
        toe_service,
        "_sync_to_sdtm",
        lambda *args, **kwargs: (
            {
                "sdtm_status": "skipped",
                "sdtm_attempted": False,
                "sdtm_reason": "No BOM",
            },
            200,
        ),
    )
    monkeypatch.setattr(
        toe_service.toe_workflow_service,
        "schedule_toe_workflow",
        schedule,
    )

    payload, status_code = toe_service.upload_toe_descriptor(
        {
            "component": {
                "component-definition": {
                    "components": [
                        {
                            "uuid": "toe-without-bom",
                            "title": "ToE",
                        }
                    ]
                }
            }
        },
        deploy_sdt=True,
    )

    assert status_code == 200
    assert payload["sdtm_attempted"] is False
    schedule.assert_not_called()


def test_handoff_scheduling_failure_does_not_fail_toe_upload(monkeypatch):
    monkeypatch.setattr(toe_service, "FORWARD_URL", "")
    monkeypatch.setattr(toe_service.toes_col, "update_one", Mock())
    monkeypatch.setattr(
        toe_service,
        "_sync_to_sdtm",
        lambda *args, **kwargs: (
            {
                "sdtm_status": "failed",
                "sdtm_attempted": True,
                "sdtm_status_code": 502,
            },
            502,
        ),
    )
    monkeypatch.setattr(
        toe_service.toe_workflow_service,
        "schedule_toe_workflow",
        Mock(side_effect=RuntimeError("Mongo workflow collection unavailable")),
    )

    payload, status_code = toe_service.upload_toe_descriptor(
        {
            "component": {
                "component-definition": {
                    "components": [
                        {
                            "uuid": "toe-scheduling-failure",
                            "title": "ToE",
                        }
                    ]
                }
            }
        },
        deploy_sdt=True,
    )

    assert status_code == 200
    assert payload["toe_id_handoff"]["status"] == "scheduling_failed"
