"""Environment-backed application settings."""

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATFLOW_", env_file=".env", extra="ignore")

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threatflow"
    postgres_user: str = "threatflow"
    postgres_password: SecretStr = SecretStr("")
    raw_storage_backend: Literal["local"] = "local"
    raw_data_dir: str = "data/raw"
    nvd_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_modified_lookback_hours: int = 48
    nvd_page_size: int = 2000
    epss_history_retention_days: int = Field(default=30, ge=1)
    airflow_metadata_retention_days: int = Field(default=90, ge=1)
    airflow_xcom_retention_days: int = Field(default=30, ge=1)
    http_connect_timeout: float = 10
    http_read_timeout: float = 60
    http_retries: int = 3

    @property
    def database_url(self) -> str:
        from urllib.parse import quote_plus

        password = quote_plus(self.postgres_password.get_secret_value())
        return f"postgresql+psycopg://{self.postgres_user}:{password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
