from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    database_url: str = "sqlite:////tmp/remindly.db"
    secret_key: str = "KunciRahasiaSementara12345"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # AI/LLM Configuration - supports both MISTRAL_API_KEY and MISTRAL_API
    mistral_api_key: Optional[str] = None
    mistral_api: Optional[str] = None

    # Email (SMTP) Configuration
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str = "example@gmail.com"
    smtp_password: str = "password"
    email_from: str = "Remindly <noreply@remindly.com>"

    class Config:
        env_file = ".env"
     

settings = Settings()
