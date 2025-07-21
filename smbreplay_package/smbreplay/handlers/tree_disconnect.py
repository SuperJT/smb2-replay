import logging

logger = logging.getLogger(__name__)

def handle_tree_disconnect(self, op):
    logger.info("Tree Disconnect: Skipping, as tree teardown is handled at the end of replay. Parameters: %s", op)
