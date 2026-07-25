from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "LLM Intrusion Detection System"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = "sqlite:///../database/ids_database.db"
    
    # LLM API
    GROQ_API_KEY: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
