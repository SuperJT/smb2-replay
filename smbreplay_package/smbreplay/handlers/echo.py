import logging

logger = logging.getLogger(__name__)

def handle_echo(self, op):
    logger.info("Echo: Not implemented. Parameters: %s", op)
