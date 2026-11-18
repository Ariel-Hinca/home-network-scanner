"""Runtime configuration.

Environment variables use the HOMEGUARD_ prefix. See backend/.env.example.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[1]
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_ROOT / ".env",
        env_prefix="HOMEGUARD_",
        extra="ignore",
    )

    app_name: str = "HomeGuard"
    version: str = "0.1.0"
    environment: str = "local"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    database_url: str = "sqlite:///./data/homeguard.db"
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    # Prefix length 16 is a /16, the largest acceptable scope.
    largest_prefix_length: int = 16
    default_prefix_length: int = 24
    session_ttl_hours: int = 12
    session_cookie_name: str = "homeguard_session"
    cookie_secure: bool = False
    local_request_header: str = "X-HomeGuard-Request"

    @field_validator("api_host")
    @classmethod
    def require_loopback(cls, value: str) -> str:
        host = value.strip().lower()
        if host not in LOOPBACK_HOSTS:
            raise ValueError("HOMEGUARD_API_HOST must be 127.0.0.1, ::1, or localhost")
        if host == "localhost":
            return "127.0.0.1"
        return host

    @field_validator("largest_prefix_length", "default_prefix_length")
    @classmethod
    def prefix_in_range(cls, value: int) -> int:
        if value < 0 or value > 32:
            raise ValueError("Prefix lengths must be between 0 and 32")
        return value

    @model_validator(mode="after")
    def default_scope_fits_under_the_cap(self) -> "Settings":
        if self.default_prefix_length < self.largest_prefix_length:
            raise ValueError(
                "HOMEGUARD_DEFAULT_PREFIX_LENGTH must be a smaller network than "
                "HOMEGUARD_LARGEST_PREFIX_LENGTH"
            )
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
