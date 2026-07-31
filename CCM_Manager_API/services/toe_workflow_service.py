import json
import logging
from datetime import datetime, timedelta

from pymongo import ReturnDocument

from auth import auth_context, authed_request
from config import (
    SDT_ID_SYNC_CATEGORY,
    SDT_ID_SYNC_DATA_PATH,
    SDT_ID_SYNC_ENABLED,
    SDT_ID_SYNC_INTERVAL_SECONDS,
    SDT_ID_SYNC_TIMEOUT_SECONDS,
    SDT_ID_SYNC_URL,
    TOE_CONNECTOR_HEALTH_URL,
    TOE_CONNECTOR_ID_FIELD,
    TOE_CONNECTOR_ID_URL,
    TOE_CONNECTOR_RETRY_MAX_SECONDS,
    TOE_CONNECTOR_RETRY_SECONDS,
    TOE_CONNECTOR_TIMEOUT_SECONDS,
    TOE_ID_HANDOFF_ENABLED,
    TOE_WORKFLOW_LEASE_SECONDS,
    TOE_WORKFLOW_RESPONSE_MAX_CHARS,
)
from db import toe_workflow_jobs_col
from utils import mongo_safe_document


LOGGER = logging.getLogger("ccm.toe_workflow")


def _utcnow():
    return datetime.utcnow()


def _positive_seconds(value, minimum=1.0):
    try:
        return max(float(value), minimum)
    except (TypeError, ValueError):
        return minimum


def _response_body(response):
    try:
        body = response.json()
    except ValueError:
        body = response.text

    safe_body = mongo_safe_document(body)
    try:
        encoded = json.dumps(safe_body, default=str)
    except (TypeError, ValueError):
        encoded = str(safe_body)

    limit = max(int(TOE_WORKFLOW_RESPONSE_MAX_CHARS), 256)
    if len(encoded) > limit:
        return encoded[:limit] + "...[truncated]"
    return safe_body


def _retry_delay(attempt_number):
    base = _positive_seconds(TOE_CONNECTOR_RETRY_SECONDS)
    maximum = max(_positive_seconds(TOE_CONNECTOR_RETRY_MAX_SECONDS), base)
    exponent = min(max(int(attempt_number) - 1, 0), 10)
    return min(base * (2 ** exponent), maximum)


def ensure_indexes():
    toe_workflow_jobs_col.create_index("toe_id", unique=True)
    toe_workflow_jobs_col.create_index(
        [("enabled", 1), ("next_run_at", 1), ("lease_until", 1)]
    )


def activate_completed_handoffs_for_sync(now=None):
    current_time = now or _utcnow()
    if TOE_ID_HANDOFF_ENABLED:
        toe_workflow_jobs_col.update_many(
            {
                "enabled": True,
                "handoff_status": {"$ne": "sent"},
                "$or": [
                    {"lease_until": None},
                    {"lease_until": {"$exists": False}},
                    {"lease_until": {"$lte": current_time}},
                ],
            },
            {
                "$set": {
                    "state": "pending_handoff",
                    "handoff_status": "pending",
                    "next_run_at": current_time,
                    "updated_at": current_time,
                }
            },
        )

    if SDT_ID_SYNC_ENABLED:
        toe_workflow_jobs_col.update_many(
            {
                "enabled": True,
                "handoff_status": "sent",
                "$or": [
                    {"next_run_at": None},
                    {"next_run_at": {"$exists": False}},
                ],
            },
            {
                "$set": {
                    "state": "id_sync_active",
                    "sync_status": "pending",
                    "next_run_at": current_time,
                    "updated_at": current_time,
                }
            },
        )


def schedule_toe_workflow(
    toe_id,
    sdt_attempt_status=None,
    sdt_attempt_status_code=None,
    category=None,
    data_path=None,
    now=None,
):
    if not TOE_ID_HANDOFF_ENABLED:
        return {
            "status": "disabled",
            "reason": "TOE_ID_HANDOFF_ENABLED is false.",
        }

    if not toe_id:
        return {
            "status": "not_scheduled",
            "reason": "Missing ToE ID.",
        }

    current_time = now or _utcnow()
    normalized_toe_id = str(toe_id)
    toe_workflow_jobs_col.update_one(
        {"toe_id": normalized_toe_id},
        {
            "$set": {
                "enabled": True,
                "category": category or SDT_ID_SYNC_CATEGORY,
                "data_path": data_path or SDT_ID_SYNC_DATA_PATH,
                "sdt_attempt_status": sdt_attempt_status,
                "sdt_attempt_status_code": sdt_attempt_status_code,
                "updated_at": current_time,
            },
            "$setOnInsert": {
                "toe_id": normalized_toe_id,
                "state": "pending_handoff",
                "handoff_status": "pending",
                "sync_status": "pending" if SDT_ID_SYNC_ENABLED else "disabled",
                "handoff_attempts": 0,
                "sync_attempts": 0,
                "consecutive_failures": 0,
                "next_run_at": current_time,
                "lease_until": None,
                "created_at": current_time,
            },
        },
        upsert=True,
    )
    toe_workflow_jobs_col.update_one(
        {
            "toe_id": normalized_toe_id,
            "handoff_status": {"$ne": "sent"},
        },
        {
            "$set": {
                "state": "pending_handoff",
                "handoff_status": "pending",
                "next_run_at": current_time,
                "updated_at": current_time,
            }
        },
    )
    job = toe_workflow_jobs_col.find_one(
        {"toe_id": normalized_toe_id},
        {"_id": 0, "toe_id": 1, "state": 1, "next_run_at": 1},
    ) or {}
    return {
        "status": "scheduled",
        "toe_id": normalized_toe_id,
        "state": job.get("state", "pending_handoff"),
        "next_run_at": job.get("next_run_at", current_time),
    }


def claim_due_job(worker_id, now=None):
    current_time = now or _utcnow()
    lease_until = current_time + timedelta(
        seconds=_positive_seconds(TOE_WORKFLOW_LEASE_SECONDS)
    )
    return toe_workflow_jobs_col.find_one_and_update(
        {
            "enabled": True,
            "next_run_at": {"$ne": None, "$lte": current_time},
            "$or": [
                {"lease_until": None},
                {"lease_until": {"$exists": False}},
                {"lease_until": {"$lte": current_time}},
            ],
        },
        {
            "$set": {
                "lease_owner": worker_id,
                "lease_until": lease_until,
                "last_claimed_at": current_time,
                "updated_at": current_time,
            }
        },
        sort=[("next_run_at", 1)],
        return_document=ReturnDocument.AFTER,
    )


def _job_filter(job):
    if job.get("_id") is not None:
        query = {"_id": job["_id"]}
    else:
        query = {"toe_id": job["toe_id"]}
    if job.get("lease_owner"):
        query["lease_owner"] = job["lease_owner"]
    return query


def _finish_job(job, values, increments=None):
    update = {
        "$set": values,
        "$unset": {
            "lease_owner": "",
            "lease_until": "",
        },
    }
    if increments:
        update["$inc"] = increments
    toe_workflow_jobs_col.update_one(_job_filter(job), update)


def _park_job(job, state, status_field, now):
    _finish_job(
        job,
        {
            "state": state,
            status_field: "disabled",
            "next_run_at": None,
            "updated_at": now,
        },
    )


def _retry_handoff(job, phase, message, now, status_code=None, response_body=None):
    attempt = int(job.get("handoff_attempts", 0)) + 1
    next_run = now + timedelta(seconds=_retry_delay(attempt))
    values = {
        "state": "waiting_for_connector",
        "handoff_status": "retrying",
        "last_phase": phase,
        "last_error": str(message),
        "last_status_code": status_code,
        "last_response": response_body,
        "last_attempt_at": now,
        "next_run_at": next_run,
        "updated_at": now,
    }
    _finish_job(
        job,
        values,
        increments={"handoff_attempts": 1, "consecutive_failures": 1},
    )
    LOGGER.warning(
        "ToE connector handoff retry scheduled toe_id=%s phase=%s status=%s next_run_at=%s error=%s",
        job.get("toe_id"),
        phase,
        status_code,
        next_run.isoformat(),
        message,
    )
    return {
        "status": "retrying",
        "phase": phase,
        "next_run_at": next_run,
    }


def _process_handoff(job, now):
    if not TOE_ID_HANDOFF_ENABLED:
        _park_job(job, "handoff_disabled", "handoff_status", now)
        return {"status": "disabled", "phase": "handoff"}

    if not TOE_CONNECTOR_HEALTH_URL or not TOE_CONNECTOR_ID_URL:
        return _retry_handoff(
            job,
            "configuration",
            "ToE connector health or ID endpoint is not configured.",
            now,
        )

    try:
        health_response = authed_request(
            "GET",
            TOE_CONNECTOR_HEALTH_URL,
            timeout=_positive_seconds(TOE_CONNECTOR_TIMEOUT_SECONDS),
            service="toe_connector_health",
        )
    except Exception as exc:
        return _retry_handoff(job, "health", exc, now)

    health_body = _response_body(health_response)
    if health_response.status_code != 200:
        return _retry_handoff(
            job,
            "health",
            f"Health check returned HTTP {health_response.status_code}.",
            now,
            status_code=health_response.status_code,
            response_body=health_body,
        )

    request_body = {TOE_CONNECTOR_ID_FIELD: str(job["toe_id"])}
    try:
        handoff_response = authed_request(
            "POST",
            TOE_CONNECTOR_ID_URL,
            json=request_body,
            timeout=_positive_seconds(TOE_CONNECTOR_TIMEOUT_SECONDS),
            service="toe_connector",
        )
    except Exception as exc:
        return _retry_handoff(job, "send_toe_id", exc, now)

    handoff_body = _response_body(handoff_response)
    if not 200 <= handoff_response.status_code < 300:
        return _retry_handoff(
            job,
            "send_toe_id",
            f"ToE ID endpoint returned HTTP {handoff_response.status_code}.",
            now,
            status_code=handoff_response.status_code,
            response_body=handoff_body,
        )

    if SDT_ID_SYNC_ENABLED:
        state = "id_sync_active"
        sync_status = "pending"
        next_run = now
    else:
        state = "handoff_complete"
        sync_status = "disabled"
        next_run = None

    _finish_job(
        job,
        {
            "state": state,
            "handoff_status": "sent",
            "handoff_sent_at": now,
            "sync_status": sync_status,
            "last_phase": "send_toe_id",
            "last_error": None,
            "last_status_code": handoff_response.status_code,
            "last_response": handoff_body,
            "last_attempt_at": now,
            "next_run_at": next_run,
            "consecutive_failures": 0,
            "updated_at": now,
            "outbound_auth": [auth_context("toe_connector")],
        },
        increments={"handoff_attempts": 1},
    )
    LOGGER.info(
        "ToE ID delivered toe_id=%s status=%s sync_enabled=%s",
        job.get("toe_id"),
        handoff_response.status_code,
        SDT_ID_SYNC_ENABLED,
    )
    return {
        "status": "sent",
        "phase": "send_toe_id",
        "status_code": handoff_response.status_code,
    }


def _retry_sync(job, message, now, status_code=None, response_body=None):
    attempt = int(job.get("sync_attempts", 0)) + 1
    next_run = now + timedelta(seconds=_retry_delay(attempt))
    _finish_job(
        job,
        {
            "state": "id_sync_active",
            "sync_status": "retrying",
            "last_phase": "sync_ids",
            "last_error": str(message),
            "last_status_code": status_code,
            "last_response": response_body,
            "last_sync_attempt_at": now,
            "next_run_at": next_run,
            "updated_at": now,
        },
        increments={"sync_attempts": 1, "consecutive_failures": 1},
    )
    LOGGER.warning(
        "SDT ID sync retry scheduled toe_id=%s status=%s next_run_at=%s error=%s",
        job.get("toe_id"),
        status_code,
        next_run.isoformat(),
        message,
    )
    return {
        "status": "retrying",
        "phase": "sync_ids",
        "next_run_at": next_run,
    }


def _process_id_sync(job, now):
    if not SDT_ID_SYNC_ENABLED:
        _park_job(job, "handoff_complete", "sync_status", now)
        return {"status": "disabled", "phase": "sync_ids"}

    if not SDT_ID_SYNC_URL:
        return _retry_sync(job, "SDT ID sync endpoint is not configured.", now)

    params = {
        "category": job.get("category") or SDT_ID_SYNC_CATEGORY,
        "toe_id": str(job["toe_id"]),
        "data_path": job.get("data_path") or SDT_ID_SYNC_DATA_PATH,
    }
    try:
        response = authed_request(
            "GET",
            SDT_ID_SYNC_URL,
            params=params,
            timeout=_positive_seconds(SDT_ID_SYNC_TIMEOUT_SECONDS),
            service="sdt",
        )
    except Exception as exc:
        return _retry_sync(job, exc, now)

    response_body = _response_body(response)
    if not 200 <= response.status_code < 300:
        return _retry_sync(
            job,
            f"SDT ID sync returned HTTP {response.status_code}.",
            now,
            status_code=response.status_code,
            response_body=response_body,
        )

    next_run = now + timedelta(
        seconds=_positive_seconds(SDT_ID_SYNC_INTERVAL_SECONDS)
    )
    _finish_job(
        job,
        {
            "state": "id_sync_active",
            "sync_status": "synchronized",
            "last_phase": "sync_ids",
            "last_error": None,
            "last_status_code": response.status_code,
            "last_response": response_body,
            "last_sync_attempt_at": now,
            "last_sync_success_at": now,
            "next_run_at": next_run,
            "consecutive_failures": 0,
            "updated_at": now,
            "outbound_auth": [auth_context("sdt")],
        },
        increments={"sync_attempts": 1},
    )
    LOGGER.info(
        "SDT IDs synchronized toe_id=%s status=%s next_run_at=%s",
        job.get("toe_id"),
        response.status_code,
        next_run.isoformat(),
    )
    return {
        "status": "synchronized",
        "phase": "sync_ids",
        "status_code": response.status_code,
        "next_run_at": next_run,
    }


def process_claimed_job(job, now=None):
    current_time = now or _utcnow()
    if job.get("handoff_status") != "sent":
        return _process_handoff(job, current_time)
    return _process_id_sync(job, current_time)
