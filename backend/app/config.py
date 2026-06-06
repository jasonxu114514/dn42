from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "dn42 Autopeer"
    base_url: str = "http://127.0.0.1:8000"
    auth_domain: str = "127.0.0.1:8000"
    session_secret: str = "dev-session-secret"
    database_url: str = "sqlite:///./autopeer.db"
    admin_asns: str = ""
    local_asn: str = ""
    wireguard_private_key_placeholder: str = "{{WIREGUARD_PRIVATE_KEY}}"
    auto_approve_peers: bool = False
    auto_deploy_on_approval: bool = True

    kioubit_public_key_path: str = "app/keys/public_key.pem"

    telegram_bot_token: str = ""
    telegram_backend_secret: str = "dev-telegram-secret"

    default_agent_url: str = "http://127.0.0.1:8080"
    default_agent_token: str = "dev-agent-token"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def admin_asn_set(self) -> set[str]:
        return {asn.strip() for asn in self.admin_asns.split(",") if asn.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
