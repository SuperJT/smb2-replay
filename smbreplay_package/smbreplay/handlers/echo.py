"""
SMB2 Echo handler for modular replay system.
Sends echo/ping requests to the SMB server using smbprotocol.
"""

import logging
from smbprotocol.exceptions import SMBException
from typing import Any, Dict

logger = logging.getLogger(__name__)


def handle_echo(replayer, op: Dict[str, Any], **kwargs):
    """Handle Echo operation using smbprotocol.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing echo parameters
        **kwargs: Additional context (session, etc.)
    """
    try:
        # Get the session from kwargs or use the current session
        session = kwargs.get("session", replayer.session)

        if not session:
            replayer.logger.warning("Echo: No session available for echo operation")
            return

        # Extract echo parameters
        echo_count = int(op.get("smb2.echo.count", 1))

        replayer.logger.debug(f"Echo: Sending {echo_count} echo request(s)")

        # Send echo request(s) to the server
        for i in range(echo_count):
            try:
                session.echo()
                replayer.logger.debug(
                    f"Echo: Successfully sent echo request {i+1}/{echo_count}"
                )
            except SMBException as e:
                replayer.logger.error(
                    f"Echo: Failed to send echo request {i+1}/{echo_count}: {e}"
                )
                break

        replayer.logger.info(f"Echo: Completed {echo_count} echo request(s)")

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Echo: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"Echo operation failed: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Echo: Expected status {expected_status}, got error: {e}"
            )
    except (ValueError, TypeError) as e:
        replayer.logger.error(f"Echo: Invalid parameters: {e}")
    except Exception as e:
        replayer.logger.error(f"Echo: Unexpected error: {e}")
