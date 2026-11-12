"""Environment-backed application settings."""

from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATFLOW_", env_file=".env", extra="ignore")

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threatflow"
    postgres_user: str = "threatflow"
    postgres_password: SecretStr = SecretStr("")
    raw_storage_backend: Literal["local", "s3"] = "local"
    raw_data_dir: str = "data/raw"
    silver_data_dir: str = "data/silver"
    s3_replication_enabled: bool = False
    s3_bronze_bucket: str | None = None
    s3_bronze_prefix: str = "bronze"
    aws_region: str | None = None
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

    @model_validator(mode="after")
    def validate_raw_storage_settings(self) -> "Settings":
        if (self.raw_storage_backend == "s3" or self.s3_replication_enabled) and not (
            self.s3_bronze_bucket
        ):
            raise ValueError(
                "s3_bronze_bucket is required for the S3 backend or S3 replication"
            )
        if self.s3_replication_enabled and self.raw_storage_backend != "local":
            raise ValueError("S3 replication requires raw_storage_backend='local'")
        if not self.s3_bronze_prefix.strip("/"):
            raise ValueError("s3_bronze_prefix must contain at least one non-slash character")
        return self

    @property
    def database_url(self) -> str:
        from urllib.parse import quote_plus

        password = quote_plus(self.postgres_password.get_secret_value())
        return f"postgresql+psycopg://{self.postgres_user}:{password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
