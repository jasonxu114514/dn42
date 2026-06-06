from functools import lru_cache
from urllib.parse import urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict


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

    default_agent_url: str = "http://127.0.0.1:8080"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def base_url(self) -> str:
        domain = self.domain.strip().rstrip("/")
        if domain.startswith(("http://", "https://")):
            return domain
        return f"https://{domain}"

    @property
    def auth_domain(self) -> str:
        domain = self.domain.strip().rstrip("/")
        parsed = urlsplit(domain if "://" in domain else f"//{domain}")
        return (parsed.netloc or parsed.path).rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
