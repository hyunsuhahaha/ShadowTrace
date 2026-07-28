from pathlib import Path
import os

APP = "oscp-workspace"
HOME = Path.home()
CONFIG_DIR = Path(os.getenv("OSCP_WORKSPACE_CONFIG", HOME / ".config" / APP))
DATA_DIR = Path(os.getenv("OSCP_WORKSPACE_DATA", HOME / ".local" / "share" / APP))
STATE_DIR = Path(os.getenv("OSCP_WORKSPACE_STATE", HOME / ".local" / "state" / APP))
WORKSPACE_DIR = Path(os.getenv("OSCP_WORKSPACE_ROOT", HOME / "OSCP-Workspace"))
DB_PATH = Path(os.getenv("OSCP_WORKSPACE_DB", DATA_DIR / "workspace.db"))
for directory in (CONFIG_DIR, DATA_DIR, STATE_DIR, WORKSPACE_DIR):
    directory.mkdir(parents=True, exist_ok=True)
