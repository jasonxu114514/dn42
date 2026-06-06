from functools import lru_cache
from urllib.parse import urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict


# Secret values that ship as placeholders in code defaults and .env.example. The backend
# refuses to start with any of these unless insecure defaults are explicitly allowed.
INSECURE_SECRET_VALUES = frozenset(
    {"dev-session-secret", "change-me", "dev-telegram-secret", "change-me-too", ""}
)


class Settings(BaseSettings):
    app_name: str = "dn42 Autopeer"
    host: str = "127.0.0.1"
    port: int = 8000
    domain: str = "127.0.0.1:8000"
    session_secret: str = "dev-session-secret"
    database_url: str = "sqlite:///./autopeer.db"
    local_asn: str = ""
    wireguard_private_key_placeholder: str = "{{WIREGUARD_PRIVATE_KEY}}"

    kioubit_public_key_path: str = "app/keys/public_key.pem"

    telegram_bot_token: str = ""
    telegram_backend_secret: str = "dev-telegram-secret"
    telegram_backend_url: str = ""

    default_agent_url: str = "http://127.0.0.1:8080"

    allow_insecure_defaults: bool = False
    lg_rate_limit: int = 20
    lg_rate_window_seconds: int = 60
    forwarded_ip_header: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def insecure_default_secrets(self) -> list[str]:
        """Return the names of secrets still set to a known insecure default value."""
        flagged = []
        if self.session_secret.strip() in INSECURE_SECRET_VALUES:
            flagged.append("SESSION_SECRET")
        if self.telegram_backend_secret.strip() in INSECURE_SECRET_VALUES:
            flagged.append("TELEGRAM_BACKEND_SECRET")
        return flagged

    @property
    def base_url(self) -> str:
        domain = self.domain.strip().rstrip("/")
        if domain.startswith(("http://", "https://")):
            return domain
        return f"https://{domain}"

    @property
    def bot_backend_url(self) -> str:
        backend_url = self.telegram_backend_url.strip().rstrip("/")
        return backend_url or self.base_url

    @property
    def auth_domain(self) -> str:
        domain = self.domain.strip().rstrip("/")
        parsed = urlsplit(domain if "://" in domain else f"//{domain}")
        return (parsed.netloc or parsed.path).rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
