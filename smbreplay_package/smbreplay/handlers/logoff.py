import logging

logger = logging.getLogger(__name__)


def handle_logoff(replayer, op):
    """Handle Logoff operation (stub).

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    logger.info(
        "Logoff: Skipping, as session teardown is handled at the end of replay. Parameters: %s",
        op,
    )
