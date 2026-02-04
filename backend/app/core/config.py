from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENV: str = "dev"
    DCS_MODE: str = "on"
    CACHE_LEVEL: int = 0
    CACHE_TTL_CLASSIF_SEC: int = 300
    CACHE_TTL_PDP_SEC: int = 60
    CACHE_TTL_KMS_SEC: int = 10
    CACHE_TTL_PEPPER_SEC: int = 300
    CACHE_MAX_ENTRIES: int = 500

    DCS_CONFIG_PATH: str = ""

    DATABASE_URL: str

    JWT_SECRET: str
    JWT_ISSUER: str = "cinema-dcs-poc"
    JWT_AUDIENCE: str = "cinema-ui"
    JWT_TTL_MINUTES: int = 240

    VAULT_ADDR: str
    VAULT_TOKEN: str
    VAULT_TRANSIT_KEY: str = "cinema-dcs"
    VAULT_KV_PEPPER_PATH: str = "secret/dcs"  # KV v2 path with key "pepper"


settings = Settings()
