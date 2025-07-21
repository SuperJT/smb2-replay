import logging

logger = logging.getLogger(__name__)

def handle_negotiate(self, op):
    logger.info("Negotiate: Using already established connection for replay. Parameters: %s", op)
