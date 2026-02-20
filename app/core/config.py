import os
import sys
from typing import Optional, List
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# 1. Force load the .env file
load_dotenv()

class Settings(BaseSettings):
    PROJECT_NAME: str = "Agentic Honey-Pot"
    GOOGLE_API_KEY: Optional[str] = os.getenv("GOOGLE_API_KEY")
    # Support for multiple keys for rotation
    GOOGLE_API_KEYS: List[str] = [
        os.getenv(f"GOOGLE_API_KEY_{i}") for i in range(1, 7) if os.getenv(f"GOOGLE_API_KEY_{i}")
    ]
    GROQ_API_KEYS: List[str] = [
        os.getenv(f"GROQ_API_KEY_{i}") for i in range(1, 7) if os.getenv(f"GROQ_API_KEY_{i}")
    ]
    GROQ_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    API_KEY: str = os.getenv("API_KEY", "ScamPatch_ftw2026Guvi")
    
    # For distributed tracing
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN")
    # Log level for structured logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    @property
    def DATABASE_URL(self) -> str:
        return f"sqlite:///{self.DATABASE_PATH}"
    
    # Hugging Face compatibility: Use /tmp if SPACE_ID is set (HF Spaces)
    IS_HF: bool = os.getenv("SPACE_ID") is not None
    
    @property
    def BASE_DATA_DIR(self) -> str:
        if self.IS_HF:
            return "/tmp/helware_data"
        return os.getcwd()
    
    @property
    def DATABASE_PATH(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "data", "honey.db")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    @property
    def CHECKPOINT_DB_PATH(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "db", "checkpoints.sqlite")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    @property
    def VECTOR_DB_DIR(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "db", "vector_store")
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def REPORTS_DIR(self) -> str:
        path = os.path.join(self.BASE_DATA_DIR, "reports")
        os.makedirs(path, exist_ok=True)
        return path

    def validate_keys(self):
        # Merge primary key into the rotation list if not already present
        if self.GOOGLE_API_KEY and self.GOOGLE_API_KEY not in self.GOOGLE_API_KEYS:
            self.GOOGLE_API_KEYS.insert(0, self.GOOGLE_API_KEY)
            
        if not self.GOOGLE_API_KEYS:
            print("WARNING: No GOOGLE_API_KEYS found. LLM features will fail.")
            # We don't exit(1) here to allow the app to start for non-LLM endpoints

settings = Settings()
settings.validate_keys()