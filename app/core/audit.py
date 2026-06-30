"""
Audit Log — то самое логирование, отсутствие которого было главным
"Высоким" риском в Access Policy Matrix для Crowd 1.0 (чат-бот без
ограничения scope) и "Критическим" для coding assistant.

Здесь логирование не опционально: gateway физически не может
пропустить запрос, не записав его.
"""
import sqlite3
import json
import time
import uuid
from pathlib import Path
from dataclasses import dataclass, asdict

from app.core.config import settings


def _ensure_db():
    Path(settings.audit_db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.audit_db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            agent_id TEXT,
            agent_name TEXT,
            channel TEXT,             -- 'llm' | 'db'
            direction TEXT,           -- 'outbound_to_llm' | 'inbound_from_db'
            decision TEXT,            -- 'allow' | 'redact' | 'block'
            risk_level TEXT,
            entities_found TEXT,      -- JSON
            raw_excerpt TEXT,         -- первые 200 символов для контекста (уже после редактирования, если был redact)
            target TEXT               -- модель/таблица, к которой шёл запрос
        )
        """
    )
    conn.commit()
    conn.close()


_ensure_db()


@dataclass
class AuditEntry:
    id: str
    timestamp: float
    agent_id: str
    agent_name: str
    channel: str
    direction: str
    decision: str
    risk_level: str
    entities_found: dict
    raw_excerpt: str
    target: str


def log_event(
    agent_id: str,
    agent_name: str,
    channel: str,
    direction: str,
    decision: str,
    risk_level: str,
    entities_found: dict,
    excerpt: str,
    target: str,
) -> AuditEntry:
    entry = AuditEntry(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        agent_id=agent_id,
        agent_name=agent_name,
        channel=channel,
        direction=direction,
        decision=decision,
        risk_level=risk_level,
        entities_found=entities_found,
        raw_excerpt=excerpt[:200],
        target=target,
    )
    conn = sqlite3.connect(settings.audit_db_path)
    conn.execute(
        """INSERT INTO audit_log
           (id, timestamp, agent_id, agent_name, channel, direction, decision,
            risk_level, entities_found, raw_excerpt, target)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            entry.id, entry.timestamp, entry.agent_id, entry.agent_name,
            entry.channel, entry.direction, entry.decision, entry.risk_level,
            json.dumps(entry.entities_found, ensure_ascii=False),
            entry.raw_excerpt, entry.target,
        ),
    )
    conn.commit()
    conn.close()
    return entry


def get_recent_events(limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(settings.audit_db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["entities_found"] = json.loads(d["entities_found"])
        result.append(d)
    return result


def get_stats() -> dict:
    conn = sqlite3.connect(settings.audit_db_path)
    total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    by_decision = dict(
        conn.execute(
            "SELECT decision, COUNT(*) FROM audit_log GROUP BY decision"
        ).fetchall()
    )
    by_risk = dict(
        conn.execute(
            "SELECT risk_level, COUNT(*) FROM audit_log GROUP BY risk_level"
        ).fetchall()
    )
    by_agent = dict(
        conn.execute(
            "SELECT agent_name, COUNT(*) FROM audit_log GROUP BY agent_name"
        ).fetchall()
    )
    conn.close()
    return {
        "total_requests": total,
        "by_decision": by_decision,
        "by_risk_level": by_risk,
        "by_agent": by_agent,
    }
