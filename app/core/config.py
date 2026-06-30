"""
AIGuard Gateway — конфигурация.

Уровень 3 продукта: middleware между AI-агентами и (a) внешними LLM API,
(b) production-базами данных. Цель — то, что в Access Policy Matrix
(Notion, Level 2) описывалось вручную, здесь применяется автоматически
и в реальном времени.
"""
from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    app_name: str = "AIGuard Gateway"
    version: str = "0.1.0-prototype"

    # Куда реально проксируем LLM-запросы (можно переключить на любого вендора)
    upstream_llm_base_url: str = "https://api.openai.com/v1"
    upstream_llm_api_key: str = "REPLACE_ME"

    # SQLite для прототипа БД, которую "защищает" DB-прокси
    # В проде это будет настоящая Postgres/MySQL клиента
    protected_db_path: str = str(Path(__file__).parent.parent / "demo_data" / "protected.db")

    # Хранилище аудит-лога (тоже SQLite для прототипа)
    audit_db_path: str = str(Path(__file__).parent.parent / "demo_data" / "audit_log.db")

    # Политики по умолчанию
    block_on_critical: bool = True   # блокировать запрос целиком при критическом риске
    redact_on_high: bool = True      # редактировать (маскировать) данные при высоком риске

    class Config:
        env_file = ".env"


settings = Settings()
