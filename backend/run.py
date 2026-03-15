"""
Safe startup script for IDS API - removes sensitive paths from all output
Run this instead of: python -m uvicorn api.main:app --reload
Just use: python run.py
"""

import uvicorn
import sys
import os
import re
from io import StringIO
from pathlib import Path

# Monkeypatch Uvicorn's ChangeReload to suppress path output
import uvicorn.supervisors.statreload

original_run = uvicorn.supervisors.statreload.StatReload.run

def patched_run(self):
    """Patched version that suppresses directory watching messages"""
    # Suppress the "Will watch for changes" message
    old_stdout = sys.stdout
    try:
        # Capture initial output
        sys.stdout = StringIO()
        # This will print the watched directories, we're suppressing it
        original_run(self)
    finally:
        sys.stdout = old_stdout

# Apply the patch
uvicorn.supervisors.statreload.StatReload.run = patched_run

# Also intercept all stdout/stderr to remove any remaining paths
class PathSanitizer:
    def __init__(self, stream):
        self.stream = stream
    
    def write(self, msg):
        msg = re.sub(
            r"[A-Z]:\\Users\\[^\\]+\\Documents\\FINAL YEAR PROJECTS\\network-ids-system",
            ".",
            msg,
            flags=re.IGNORECASE
        )
        self.stream.write(msg)
    
    def flush(self):
        self.stream.flush()
    
    def isatty(self):
        return hasattr(self.stream, 'isatty') and self.stream.isatty()

sys.stdout = PathSanitizer(sys.stdout)
sys.stderr = PathSanitizer(sys.stderr)

# Now start Uvicorn
if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
