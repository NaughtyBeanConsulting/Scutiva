import os as _os
from pathlib import Path as _Path

from dotenv import load_dotenv as _load_dotenv

_load_dotenv(_Path(__file__).resolve().parent.parent.parent / ".env")

_debug_env = (_os.getenv("DEBUG", "false") or "false").strip().lower()
_is_debug = _debug_env not in {"0", "false", "no", "off"}

if _is_debug:
	from .development import *  # noqa: F401, F403
else:
	from .production import *  # noqa: F401, F403
from .development import *