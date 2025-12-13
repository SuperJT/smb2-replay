import logging

logger = logging.getLogger(__name__)


def handle_session_setup(replayer, op):
    """Handle Session Setup operation (stub).

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    logger.info(
        "Session Setup: Using already established session for replay. Parameters: %s",
        op,
    )
