import logging

logger = logging.getLogger(__name__)


def handle_tree_disconnect(replayer, op):
    """Handle Tree Disconnect operation (stub).

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    logger.info(
        "Tree Disconnect: Skipping, as tree teardown is handled at the end of replay. Parameters: %s",
        op,
    )
