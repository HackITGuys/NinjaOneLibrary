"""Credentials and tunables for the NinjaOne Public API.

Read from the environment and the `.env` in the current working directory. Callers with
their own configuration can construct `NinjaOneSettings(...)` directly, or point at a
different file with `NinjaOneSettings(_env_file="path/to/.env")`.

SCOPE "monitoring" ONLY. Everything this library does is a read, and monitoring is
NinjaOne's read-only scope (monitoring data *and* organisation structure). Enforcing
read-only at the credential means a bug here cannot change a customer tenant.
"""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class NinjaOneSettings(BaseSettings):
    """NINJA_* settings. Never log or serialise an instance of this."""

    model_config = SettingsConfigDict(
        env_prefix="NINJA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    base_url: str = "https://eu.ninjarmm.com"
    """The instance: app. (US), us2., ca., eu. or oc.ninjarmm.com."""
    client_id: str = ""
    client_secret: SecretStr = SecretStr("")
    scope: str = "monitoring"

    timeout: int = 30
    max_attempts: int = 5
    page_size: int = 500
    """Records per page for paged endpoints."""

    @property
    def api_root(self) -> str:
        return self.base_url.rstrip("/") + "/v2"

    @property
    def token_url(self) -> str:
        return self.base_url.rstrip("/") + "/ws/oauth/token"

    @property
    def spec_url(self) -> str:
        return self.base_url.rstrip("/") + "/apidocs/NinjaRMM-API-v2.json"
