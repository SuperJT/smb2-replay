"""
Entry point for running smbreplay as a module.
Allows usage like: python -m smbreplay [command] [args]
"""

import sys
import signal
from .main import main

def handle_broken_pipe():
    """Handle broken pipe errors gracefully."""
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

if __name__ == "__main__":
    handle_broken_pipe()
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(1) 