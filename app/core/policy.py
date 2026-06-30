"""
Policy Engine — программное воплощение Access Policy Matrix.

Каждый AI-агент, который ходит через gateway, идентифицируется
своим gateway-токеном. У каждого агента — своя политика:
какой максимальный risk level пропускать, какие таблицы/поля
БД ему доступны, нужно ли редактировать или блокировать.

В Level 2 (Notion) это была ручная таблица, которую вы заполняли
по итогам аудита. Здесь — тот же набор полей, но он реально
применяется к каждому запросу.
"""
from dataclasses import dataclass, field
from enum import Enum

from app.core.detection import RiskLevel


class ActionOnViolation(str, Enum):
    BLOCK = "block"      # полностью отклонить запрос
    REDACT = "redact"    # замаскировать чувствительные данные и пропустить
    ALLOW_LOG = "allow_log"  # пропустить, но громко залогировать


@dataclass
class AgentPolicy:
    agent_id: str
    agent_name: str
    agent_type: str  # "coding_assistant" | "llm_chatbot" | "scoring_agent" | ...
    gateway_token: str

    # Что разрешено отправлять во внешний LLM
    max_risk_to_llm: RiskLevel = RiskLevel.LOW
    action_on_llm_violation: ActionOnViolation = ActionOnViolation.REDACT

    # Что разрешено читать из БД
    allowed_tables: list[str] = field(default_factory=list)
    denied_columns: list[str] = field(default_factory=list)  # запрещённые поля даже в allowed_tables
    max_risk_from_db: RiskLevel = RiskLevel.MEDIUM
    action_on_db_violation: ActionOnViolation = ActionOnViolation.REDACT

    environment: str = "production"  # production | staging | dev


# ─────────────────────────────────────────────────────────────────────────
# ДЕМО-РЕЕСТР ПОЛИТИК — аналог строк Access Policy Matrix для Crowd 1.0
# В проде это хранится в БД и редактируется через админ-панель/API,
# но структура полей ровно та же, что в Notion-таблице.
# ─────────────────────────────────────────────────────────────────────────

DEMO_POLICIES: dict[str, AgentPolicy] = {
    "tok_coding_assistant_demo": AgentPolicy(
        agent_id="agent_001",
        agent_name="Cursor / Coding Assistant",
        agent_type="coding_assistant",
        gateway_token="tok_coding_assistant_demo",
        max_risk_to_llm=RiskLevel.LOW,          # коду нельзя отправлять во внешний LLM ничего чувствительного
        action_on_llm_violation=ActionOnViolation.BLOCK,  # для credentials — жёсткий блок, не маскировка
        allowed_tables=["public_schema_docs"],   # доступ только к документации схемы, не к данным
        denied_columns=["password", "api_key", "ssn", "card_number"],
        max_risk_from_db=RiskLevel.LOW,
        action_on_db_violation=ActionOnViolation.BLOCK,
        environment="production",
    ),
    "tok_scoring_agent_demo": AgentPolicy(
        agent_id="agent_002",
        agent_name="Scoring Agent",
        agent_type="scoring_agent",
        gateway_token="tok_scoring_agent_demo",
        max_risk_to_llm=RiskLevel.MEDIUM,
        action_on_llm_violation=ActionOnViolation.REDACT,
        allowed_tables=["loan_applications"],
        denied_columns=["model_internal_params", "passport_number"],  # commercial secret + PII
        max_risk_from_db=RiskLevel.MEDIUM,
        action_on_db_violation=ActionOnViolation.REDACT,
        environment="production",
    ),
    "tok_support_chatbot_demo": AgentPolicy(
        agent_id="agent_003",
        agent_name="Investor Support Chatbot",
        agent_type="llm_chatbot",
        gateway_token="tok_support_chatbot_demo",
        max_risk_to_llm=RiskLevel.LOW,
        action_on_llm_violation=ActionOnViolation.REDACT,
        allowed_tables=["investor_balances_view"],  # только агрегированное представление
        denied_columns=["transaction_details", "passport_number"],
        max_risk_from_db=RiskLevel.LOW,
        action_on_db_violation=ActionOnViolation.REDACT,
        environment="production",
    ),
}


def get_policy(gateway_token: str) -> AgentPolicy | None:
    return DEMO_POLICIES.get(gateway_token)
