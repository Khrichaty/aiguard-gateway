"""
Audit Dashboard — минимальный обзор того, что gateway заблокировал/пропустил.
Это техническая замена ручного просмотра Access Policy Matrix в Notion:
теперь видно реальные решения в реальном времени, а не то, что аудитор
записал постфактум.
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.core import audit

router = APIRouter(prefix="/v1/audit", tags=["Audit Dashboard"])


@router.get("/events")
async def list_events(limit: int = 50):
    return {"events": audit.get_recent_events(limit=limit)}


@router.get("/stats")
async def stats():
    return audit.get_stats()


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    events = audit.get_recent_events(limit=100)
    stats_data = audit.get_stats()

    decision_color = {"allow": "#10B981", "redact": "#F59E0B", "block": "#EF4444"}
    risk_color = {
        "critical": "#EF4444", "high": "#F97316", "medium": "#F59E0B",
        "low": "#10B981", "none": "#94A3B8",
    }

    rows_html = ""
    for e in events:
        dcolor = decision_color.get(e["decision"], "#94A3B8")
        rcolor = risk_color.get(e["risk_level"], "#94A3B8")
        entities = ", ".join(f"{k}×{v}" for k, v in e["entities_found"].items()) or "—"
        rows_html += f"""
        <tr>
            <td>{e['agent_name']}</td>
            <td>{e['channel']}</td>
            <td><span style="color:{dcolor};font-weight:600">{e['decision'].upper()}</span></td>
            <td><span style="color:{rcolor};font-weight:600">{e['risk_level'].upper()}</span></td>
            <td style="font-size:12px;color:#94A3B8">{entities}</td>
            <td style="font-size:12px;color:#94A3B8">{e['target']}</td>
        </tr>"""

    stat_cards = ""
    for label, val in [
        ("Всего запросов", stats_data["total_requests"]),
        ("Заблокировано", stats_data["by_decision"].get("block", 0)),
        ("Отредактировано", stats_data["by_decision"].get("redact", 0)),
        ("Пропущено чисто", stats_data["by_decision"].get("allow", 0)),
    ]:
        stat_cards += f"""
        <div style="background:#0F1E3C;border-radius:12px;padding:18px;flex:1">
            <div style="font-size:28px;font-weight:700;color:#5EEAD4">{val}</div>
            <div style="font-size:12px;color:#94A3B8;margin-top:4px">{label}</div>
        </div>"""

    html = f"""
    <html>
    <head>
        <title>AIGuard — Audit Dashboard</title>
        <style>
            body {{ background:#0B1120; color:#E2E8F0; font-family: -apple-system, Arial, sans-serif; padding:32px; }}
            h1 {{ color:#fff; }}
            table {{ width:100%; border-collapse: collapse; margin-top:20px; }}
            th {{ text-align:left; color:#5EEAD4; padding:10px; border-bottom:1px solid #1E3A5A; font-size:12px; text-transform:uppercase; }}
            td {{ padding:10px; border-bottom:1px solid #162444; font-size:13px; }}
        </style>
    </head>
    <body>
        <h1>🛡️ AIGuard Gateway — Audit Log</h1>
        <div style="display:flex; gap:16px; margin-top:20px;">{stat_cards}</div>
        <table>
            <tr><th>Агент</th><th>Канал</th><th>Решение</th><th>Риск</th><th>Найдено</th><th>Цель</th></tr>
            {rows_html if rows_html else '<tr><td colspan="6">Пока нет событий — отправьте тестовый запрос.</td></tr>'}
        </table>
    </body>
    </html>
    """
    return html
