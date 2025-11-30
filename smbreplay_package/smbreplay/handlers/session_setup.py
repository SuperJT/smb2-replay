import logging

logger = logging.getLogger(__name__)


def handle_session_setup(self, op):
    logger.info(
        "Session Setup: Using already established session for replay. Parameters: %s",
        op,
    )
