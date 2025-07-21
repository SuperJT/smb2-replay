import logging

logger = logging.getLogger(__name__)

def handle_oplock_break(self, op):
    logger.info("Oplock Break: Not implemented. Parameters: %s", op)
