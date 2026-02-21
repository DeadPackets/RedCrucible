from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="REDCRUCIBLE_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    artifact_dir: Path = Path("./artifacts")
    artifact_ttl_seconds: int = 600

    tools_manifest: Path = Path("./tools.yml")

    assembly_cache_dir: Path = Path("./cache/assemblies")


settings = Settings()
