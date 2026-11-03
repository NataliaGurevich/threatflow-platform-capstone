"""Environment-backed application settings."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATFLOW_", env_file=".env", extra="ignore")

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threatflow"
    postgres_user: str = "threatflow"
    postgres_password: SecretStr = SecretStr("")
    raw_data_dir: str = "data/raw"
    nvd_api_key: SecretStr | None = None

    @property
    def database_url(self) -> str:
        from urllib.parse import quote_plus

        password = quote_plus(self.postgres_password.get_secret_value())
        return f"postgresql+psycopg://{self.postgres_user}:{password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
