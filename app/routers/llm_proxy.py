"""
LLM Proxy — перехватывает исходящие запросы AI-агента к внешнему LLM API
(OpenAI / Anthropic / Azure OpenAI), сканирует промпт на чувствительные
данные ДО отправки наружу, и в зависимости от политики агента либо
блокирует, либо маскирует, либо пропускает с логированием.

Это прямой ответ на риск из Access Policy Matrix:
"Coding assistant → Production БД заёмщиков" — Критический,
"запрещён прямой доступ AI-инструментов к prod без изоляции".
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.auth import get_agent_policy
from app.core.policy import AgentPolicy, ActionOnViolation
from app.core.detection import scan_text, redact_text, RiskLevel
from app.core import audit

router = APIRouter(prefix="/v1/llm", tags=["LLM Proxy"])

_RISK_ORDER = {RiskLevel.NONE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
               RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: list[ChatMessage]


@router.post("/chat/completions")
async def proxy_chat_completion(
    body: ChatCompletionRequest,
    policy: AgentPolicy = Depends(get_agent_policy),
):
    # Склеиваем весь текст промпта для сканирования
    full_prompt = "\n".join(m.content for m in body.messages)
    scan = scan_text(full_prompt)
    risk = scan.highest_risk

    exceeds_policy = _RISK_ORDER[risk] > _RISK_ORDER[policy.max_risk_to_llm]

    if not exceeds_policy:
        audit.log_event(
            agent_id=policy.agent_id, agent_name=policy.agent_name,
            channel="llm", direction="outbound_to_llm", decision="allow",
            risk_level=risk.value, entities_found=scan.entity_summary,
            excerpt=full_prompt, target=body.model,
        )
        return _mock_llm_response(body.model, full_prompt, redacted=False)

    # Риск превышает то, что разрешено политикой агента
    if policy.action_on_llm_violation == ActionOnViolation.BLOCK:
        audit.log_event(
            agent_id=policy.agent_id, agent_name=policy.agent_name,
            channel="llm", direction="outbound_to_llm", decision="block",
            risk_level=risk.value, entities_found=scan.entity_summary,
            excerpt=full_prompt, target=body.model,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "AIGuard: запрос заблокирован политикой безопасности",
                "risk_level": risk.value,
                "entities_found": scan.entity_summary,
                "policy": f"Агент '{policy.agent_name}' не может отправлять "
                          f"данные уровня {risk.value} во внешний LLM "
                          f"(лимит политики: {policy.max_risk_to_llm.value})",
            },
        )

    # REDACT — маскируем и пропускаем
    redacted_prompt = redact_text(full_prompt, scan.entities)
    audit.log_event(
        agent_id=policy.agent_id, agent_name=policy.agent_name,
        channel="llm", direction="outbound_to_llm", decision="redact",
        risk_level=risk.value, entities_found=scan.entity_summary,
        excerpt=redacted_prompt, target=body.model,
    )
    return _mock_llm_response(body.model, redacted_prompt, redacted=True)


def _mock_llm_response(model: str, prompt: str, redacted: bool) -> dict:
    """
    В прототипе не дёргаем реальный OpenAI API (нужен платный ключ) —
    возвращаем мок-ответ, чтобы показать сквозную механику.
    В проде здесь httpx.post(settings.upstream_llm_base_url, ...).
    """
    return {
        "id": "chatcmpl-aiguard-demo",
        "model": model,
        "aiguard_meta": {
            "redacted_before_send": redacted,
            "note": "Прототип: реальный запрос к LLM не отправлен, это мок ответа",
        },
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": f"[MOCK LLM RESPONSE] Получен промпт "
                               f"({'после редактирования' if redacted else 'без изменений'}): "
                               f"{prompt[:300]}",
                }
            }
        ],
    }
