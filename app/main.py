"""
AIGuard Gateway — Level 3 продукт.

Единая точка входа: один FastAPI-сервис с тремя зонами ответственности:
  /v1/llm/*    — прокси перед внешним LLM API (фильтрует исходящие промпты)
  /v1/db/*     — прокси перед production БД (фильтрует входящие результаты)
  /v1/audit/*  — дашборд и API аудит-лога

Запуск: uvicorn app.main:app --reload --port 8000
Дашборд: http://localhost:8000/v1/audit/dashboard
Docs:    http://localhost:8000/docs
"""
from fastapi import FastAPI
from app.core.config import settings
from app.routers import llm_proxy, db_proxy, audit_dashboard

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "Middleware между AI-агентами и (1) внешними LLM API, (2) production БД. "
        "Автоматизированная реализация Access Policy Matrix из AIGuard Audit Toolkit."
    ),
)

app.include_router(llm_proxy.router)
app.include_router(db_proxy.router)
app.include_router(audit_dashboard.router)


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "version": settings.version,
        "endpoints": {
            "llm_proxy": "/v1/llm/chat/completions",
            "db_proxy": "/v1/db/query",
            "audit_dashboard": "/v1/audit/dashboard",
            "docs": "/docs",
        },
        "demo_agents": [
            "tok_coding_assistant_demo",
            "tok_scoring_agent_demo",
            "tok_support_chatbot_demo",
        ],
    }
