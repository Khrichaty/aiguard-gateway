"""
DB Proxy — перехватывает SQL-запросы AI-агента к production-БД.

Делает три вещи, отсутствие которых было риском в Access Policy Matrix:
1. Проверяет, что таблица в allowed_tables агента
   ("Coding assistant имел прямой API к БД заёмщиков" → теперь невозможно)
2. Вычищает denied_columns из результата ДО того, как агент их увидит
   ("Параметры скоринговой модели доступны агенту без изоляции" → теперь поле обнуляется)
3. Сканирует то, что осталось, на PII и применяет ту же политику риска,
   что и LLM-прокси (избыточность — это намеренно, defense in depth)
"""
import sqlite3
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.auth import get_agent_policy
from app.core.policy import AgentPolicy, ActionOnViolation
from app.core.detection import scan_text, redact_text, RiskLevel
from app.core.config import settings
from app.core import audit

router = APIRouter(prefix="/v1/db", tags=["DB Proxy"])

_RISK_ORDER = {RiskLevel.NONE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
               RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}


class QueryRequest(BaseModel):
    table: str
    columns: list[str] | None = None  # None = SELECT *
    limit: int = 50


def _extract_table_name(table: str) -> str:
    # Простая защита от SQL-инъекций в имени таблицы для прототипа.
    # В проде — параметризация на уровне query builder, никогда не строка.
    if not table.replace("_", "").isalnum():
        raise HTTPException(400, "Недопустимое имя таблицы")
    return table


@router.post("/query")
async def proxy_query(
    body: QueryRequest,
    policy: AgentPolicy = Depends(get_agent_policy),
):
    table = _extract_table_name(body.table)

    # ШАГ 1 — проверка allowed_tables (это уровень "Канал доступа" из Matrix)
    if table not in policy.allowed_tables:
        audit.log_event(
            agent_id=policy.agent_id, agent_name=policy.agent_name,
            channel="db", direction="inbound_from_db", decision="block",
            risk_level=RiskLevel.CRITICAL.value,
            entities_found={"unauthorized_table_access": 1},
            excerpt=f"Попытка доступа к таблице '{table}'", target=table,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "AIGuard: таблица не входит в Access Policy агента",
                "agent": policy.agent_name,
                "requested_table": table,
                "allowed_tables": policy.allowed_tables,
            },
        )

    # ШАГ 2 — выполняем запрос к демо-БД
    conn = sqlite3.connect(settings.protected_db_path)
    conn.row_factory = sqlite3.Row
    try:
        cols_sql = "*" if not body.columns else ", ".join(
            c for c in body.columns if c.replace("_", "").isalnum()
        )
        rows = conn.execute(
            f"SELECT {cols_sql} FROM {table} LIMIT ?", (body.limit,)
        ).fetchall()
    except sqlite3.OperationalError as e:
        raise HTTPException(400, f"Ошибка запроса: {e}")
    finally:
        conn.close()

    result_rows = [dict(r) for r in rows]

    # ШАГ 3 — вычищаем denied_columns (column-level policy)
    stripped_fields: set[str] = set()
    for row in result_rows:
        for denied_col in policy.denied_columns:
            if denied_col in row:
                row[denied_col] = "[FIELD BLOCKED BY POLICY]"
                stripped_fields.add(denied_col)

    # ШАГ 4 — сканируем то, что осталось, на PII (defense in depth —
    # ловит случаи, когда чувствительные данные оказались в "разрешённом" поле,
    # например имя инвестора с прицепленным номером карты в свободном тексте)
    serialized = str(result_rows)
    scan = scan_text(serialized)
    risk = scan.highest_risk
    exceeds_policy = _RISK_ORDER[risk] > _RISK_ORDER[policy.max_risk_from_db]

    if exceeds_policy and policy.action_on_db_violation == ActionOnViolation.BLOCK:
        audit.log_event(
            agent_id=policy.agent_id, agent_name=policy.agent_name,
            channel="db", direction="inbound_from_db", decision="block",
            risk_level=risk.value, entities_found=scan.entity_summary,
            excerpt=serialized, target=table,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "AIGuard: результат запроса превышает допустимый риск для агента",
                "risk_level": risk.value,
                "entities_found": scan.entity_summary,
            },
        )

    decision = "allow"
    if stripped_fields:
        decision = "redact"
    if exceeds_policy and policy.action_on_db_violation == ActionOnViolation.REDACT:
        decision = "redact"
        for row in result_rows:
            row_text = str(row)
            row_scan = scan_text(row_text)
            if row_scan.entities:
                # Точечно маскируем найденные сущности в строковых полях
                for key, value in list(row.items()):
                    if isinstance(value, str):
                        field_scan = scan_text(value)
                        if field_scan.entities:
                            row[key] = redact_text(value, field_scan.entities)

    audit.log_event(
        agent_id=policy.agent_id, agent_name=policy.agent_name,
        channel="db", direction="inbound_from_db", decision=decision,
        risk_level=risk.value, entities_found=scan.entity_summary,
        excerpt=str(result_rows), target=table,
    )

    return {
        "table": table,
        "row_count": len(result_rows),
        "rows": result_rows,
        "aiguard_meta": {
            "decision": decision,
            "stripped_fields": list(stripped_fields),
            "risk_detected": risk.value,
            "entities_found": scan.entity_summary,
        },
    }
