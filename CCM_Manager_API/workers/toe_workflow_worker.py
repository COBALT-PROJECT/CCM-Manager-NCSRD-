import logging
import os
import socket
import time
import uuid

from config import (
    SDT_ID_SYNC_ENABLED,
    TOE_ID_HANDOFF_ENABLED,
    TOE_WORKFLOW_POLL_SECONDS,
)
from services import toe_workflow_service


LOGGER = logging.getLogger("ccm.toe_workflow.worker")


def _worker_id():
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


def run():
    logging.basicConfig(
        level=os.getenv("CCM_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    worker_id = _worker_id()
    poll_seconds = max(float(TOE_WORKFLOW_POLL_SECONDS), 0.5)

    toe_workflow_service.ensure_indexes()
    toe_workflow_service.activate_completed_handoffs_for_sync()
    LOGGER.info(
        "ToE workflow worker started worker_id=%s handoff_enabled=%s id_sync_enabled=%s",
        worker_id,
        TOE_ID_HANDOFF_ENABLED,
        SDT_ID_SYNC_ENABLED,
    )

    while True:
        if not TOE_ID_HANDOFF_ENABLED and not SDT_ID_SYNC_ENABLED:
            time.sleep(max(poll_seconds, 5.0))
            continue

        job = toe_workflow_service.claim_due_job(worker_id)
        if job is None:
            time.sleep(poll_seconds)
            continue

        try:
            toe_workflow_service.process_claimed_job(job)
        except Exception:
            LOGGER.exception(
                "Unexpected ToE workflow failure toe_id=%s; lease will expire for retry",
                job.get("toe_id"),
            )


if __name__ == "__main__":
    run()
