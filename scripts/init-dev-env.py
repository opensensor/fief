"""Initialize development settings without replacing existing encryption keys."""

import os
import secrets
import shutil
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import dotenv_values, set_key

env_path = Path.cwd() / ".env"
if not env_path.exists():
    shutil.copyfile(Path(__file__).resolve().parents[1] / ".env.dist", env_path)
    env_path.chmod(0o600)

values = dotenv_values(env_path)
if values.get("SECRET") in (None, "", "ThisShouldBeChangedInProduction"):
    set_key(env_path, "SECRET", secrets.token_urlsafe(32))
for key in ("ENCRYPTION_KEY", "MFA_SECRET_ENCRYPTION_KEY"):
    if not values.get(key):
        set_key(env_path, key, Fernet.generate_key().decode())

codespace = os.environ.get("CODESPACE_NAME")
forwarding_domain = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
if codespace and forwarding_domain and not values.get("FIEF_DOMAIN"):
    set_key(env_path, "FIEF_DOMAIN", f"{codespace}-8000.{forwarding_domain}")

print("Development .env is ready; existing keys and settings were preserved.")
