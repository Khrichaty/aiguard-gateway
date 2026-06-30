"""
Извлекает и проверяет gateway-токен агента из заголовка запроса,
возвращает его AgentPolicy. Это точка входа политики для любого
маршрута gateway.
"""
from fastapi import Header, HTTPException

from app.core.policy import get_policy, AgentPolicy


async def get_agent_policy(x_gateway_token: str = Header(...)) -> AgentPolicy:
    policy = get_policy(x_gateway_token)
    if policy is None:
        raise HTTPException(
            status_code=401,
            detail="Unknown gateway token. Агент не зарегистрирован в Access Policy Matrix.",
        )
    return policy
