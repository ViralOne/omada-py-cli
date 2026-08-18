"""Config discovery + scaffolding for the Omada CLI.

Makes the CLI usable as a global command (`omada ...`) from any directory.
``.env`` load order (first match wins):

1. ``$OMADA_ENV``               - explicit path override
2. ``./.env``                   - current working directory
3. ``~/.config/omada/.env``     - user config (recommended for global use)
4. ``<package parent>/.env``    - the repo checkout next to the ``omada`` package
5. dotenv default search        - cwd + parent directories
"""
import os
from pathlib import Path

from dotenv import load_dotenv

CONFIG_DIR = Path.home() / ".config" / "omada"
USER_CONFIG = CONFIG_DIR / ".env"

ENV_TEMPLATE = """\
# Omada Controller connection (internal API v2) - required
OMADA_URL=https://192.168.0.1:8043
OMADA_USERNAME=your_username
OMADA_PASSWORD=your_password

# Only for the `vpn-client` command (official OpenAPI v1)
OMADA_CLIENT_ID=
OMADA_CLIENT_SECRET=
OMADA_OMADAC_ID=
"""


def load_env() -> None:
    """Load environment variables from the first ``.env`` found (see module doc).

    ``load_dotenv`` never overrides variables already set in the environment,
    so calling this more than once is safe.
    """
    candidates = []
    explicit = os.getenv("OMADA_ENV")
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(Path.cwd() / ".env")
    candidates.append(USER_CONFIG)
    candidates.append(Path(__file__).resolve().parent.parent / ".env")

    for path in candidates:
        if path.is_file():
            load_dotenv(path)
            return

    # Fallback: dotenv's own search (cwd + parents)
    load_dotenv()


def init_config() -> tuple[Path, bool]:
    """Create ``~/.config/omada/.env`` from a template if it doesn't exist.

    Returns ``(path, created)`` where ``created`` is False if it already existed.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if USER_CONFIG.exists():
        return USER_CONFIG, False
    USER_CONFIG.write_text(ENV_TEMPLATE)
    return USER_CONFIG, True


def config_hint() -> str:
    """Human-friendly guidance shown when credentials are missing."""
    return (
        "No Omada credentials found. Set them up one of these ways:\n"
        f"  1. Run:  omada init          # creates {USER_CONFIG}, then edit it\n"
        f"  2. Or create {USER_CONFIG} with OMADA_URL / OMADA_USERNAME / OMADA_PASSWORD\n"
        "  3. Or set OMADA_ENV=/path/to/.env\n"
        "  4. Or pass --url / --username / --password on the command line"
    )
