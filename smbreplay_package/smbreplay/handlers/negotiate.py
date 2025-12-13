import logging

logger = logging.getLogger(__name__)


def handle_negotiate(replayer, op):
    """Handle Negotiate operation (stub).

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    logger.info(
        "Negotiate: Using already established connection for replay. Parameters: %s", op
    )
