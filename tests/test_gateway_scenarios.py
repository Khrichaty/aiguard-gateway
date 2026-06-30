"""
Интеграционные тесты — те же 4 сценария, что в README, но автоматизированные.
Гоняются в CI при каждом пуше (см. .github/workflows/ci.yml).

Запуск локально: ./venv/bin/pytest tests/ -v
"""
import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Подменяем путь к БД на временный ДО импорта app, чтобы тесты не трогали demo_data
os.environ.setdefault("PROTECTED_DB_PATH", "/tmp/aiguard_test_protected.db")
os.environ.setdefault("AUDIT_DB_PATH", "/tmp/aiguard_test_audit.db")

from app.core.config import settings
settings.protected_db_path = "/tmp/aiguard_test_protected.db"
settings.audit_db_path = "/tmp/aiguard_test_audit.db"

from app.core.seed_demo_db import seed
from app.main import app

CODING_TOKEN = "tok_coding_assistant_demo"
SCORING_TOKEN = "tok_scoring_agent_demo"
CHATBOT_TOKEN = "tok_support_chatbot_demo"


@pytest.fixture(scope="module", autouse=True)
def setup_demo_db():
    for path in (settings.protected_db_path, settings.audit_db_path):
        if os.path.exists(path):
            os.remove(path)
    seed()
    yield


@pytest.fixture
def client():
    return TestClient(app)


def test_coding_assistant_credential_leak_is_blocked(client):
    """Сценарий 1: coding assistant пытается слить connection string + API key в LLM → 403 BLOCK."""
    resp = client.post(
        "/v1/llm/chat/completions",
        headers={"X-Gateway-Token": CODING_TOKEN},
        json={
            "model": "gpt-4o-mini",
            "messages": [{
                "role": "user",
                "content": "postgres://admin:Secret123@prod-db:5432/loans "
                           "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
            }],
        },
    )
    assert resp.status_code == 403
    body = resp.json()["detail"]
    assert body["risk_level"] == "critical"
    assert "api_key" in body["entities_found"]
    assert "db_connection_string" in body["entities_found"]


def test_scoring_agent_sensitive_columns_are_redacted(client):
    """Сценарий 2: scoring agent читает loan_applications → passport/model_params вычищены."""
    resp = client.post(
        "/v1/db/query",
        headers={"X-Gateway-Token": SCORING_TOKEN},
        json={"table": "loan_applications"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["aiguard_meta"]["decision"] == "redact"
    for row in body["rows"]:
        assert row["passport_number"] == "[FIELD BLOCKED BY POLICY]"
        assert row["model_internal_params"] == "[FIELD BLOCKED BY POLICY]"
        # company_name и score_result должны остаться видны — это не over-blocking
        assert row["company_name"] != "[FIELD BLOCKED BY POLICY]"


def test_chatbot_direct_table_access_is_blocked(client):
    """Сценарий 3: chatbot лезет напрямую в investors (не в allowed_tables) → 403 BLOCK."""
    resp = client.post(
        "/v1/db/query",
        headers={"X-Gateway-Token": CHATBOT_TOKEN},
        json={"table": "investors"},
    )
    assert resp.status_code == 403
    assert "не входит в Access Policy" in resp.json()["detail"]["error"]


def test_chatbot_allowed_aggregate_view_passes(client):
    """Сценарий 4: chatbot читает investor_balances_view (разрешённый агрегат) → 200 ALLOW."""
    resp = client.post(
        "/v1/db/query",
        headers={"X-Gateway-Token": CHATBOT_TOKEN},
        json={"table": "investor_balances_view"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["row_count"] == 2
    assert "full_name" in body["rows"][0]
    assert "balance" in body["rows"][0]


def test_unknown_token_is_rejected(client):
    """Незарегистрированный агент не должен пройти ни в один прокси."""
    resp = client.post(
        "/v1/db/query",
        headers={"X-Gateway-Token": "tok_unknown_agent"},
        json={"table": "investors"},
    )
    assert resp.status_code == 401


def test_audit_log_captures_every_decision(client):
    """Каждое решение gateway должно попасть в аудит-лог — это не опционально."""
    client.post(
        "/v1/db/query",
        headers={"X-Gateway-Token": CHATBOT_TOKEN},
        json={"table": "investor_balances_view"},
    )
    resp = client.get("/v1/audit/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_requests"] > 0
