# AIGuard Gateway — Level 3 прототип

Технический proof-of-concept middleware между AI-агентами и (1) внешними LLM API,
(2) production-базами данных. Автоматизированная реализация Access Policy Matrix
из AIGuard Audit Toolkit (Notion, Level 2) — то, что в Level 2 было ручной таблицей,
здесь применяется в реальном времени к каждому запросу.

Демо-сценарий построен на гипотетическом кейсе Crowd 1.0 (крауд-инвестинговая
платформа) — те же три агента и те же риски, что в Access Policy Matrix.

## Архитектура

```
AI-агент → AIGuard Gateway → [LLM API / Production БД]
              │
              ├── Detection Engine   (app/core/detection.py)  — находит PII/secrets/коммерческую тайну
              ├── Policy Engine      (app/core/policy.py)     — решает allow/redact/block по агенту
              └── Audit Log          (app/core/audit.py)      — пишет каждое решение, без исключений
```

Два прокси-маршрута:

- **`POST /v1/llm/chat/completions`** — перехватывает исходящий промпт ДО отправки
  во внешний LLM. Сканирует на credentials/PII, применяет политику агента.
- **`POST /v1/db/query`** — перехватывает запрос к БД. Проверяет `allowed_tables`,
  вычищает `denied_columns`, затем сканирует результат на PII (defense in depth).

Все решения пишутся в `/v1/audit/dashboard` — живой лог вместо постфактум-аудита.

## Демо-агенты (соответствуют строкам Access Policy Matrix)

| Token | Агент | Что разрешено |
|---|---|---|
| `tok_coding_assistant_demo` | Cursor / Coding Assistant | LLM: только LOW риск (BLOCK при превышении). БД: только `public_schema_docs` |
| `tok_scoring_agent_demo` | Scoring Agent | БД: `loan_applications`, но без `model_internal_params` и `passport_number` |
| `tok_support_chatbot_demo` | Investor Support Chatbot | БД: только `investor_balances_view` (агрегат, не сырые транзакции) |

## Запуск

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python -m app.core.seed_demo_db   # создаёт демо-БД с тестовыми данными
./venv/bin/uvicorn app.main:app --reload --port 8000
```

Дашборд: http://localhost:8000/v1/audit/dashboard
Swagger: http://localhost:8000/docs

## Тестовые сценарии

```bash
# 1. Coding assistant пытается слить credentials во внешний LLM → BLOCK
curl -X POST http://localhost:8000/v1/llm/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Gateway-Token: tok_coding_assistant_demo" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"postgres://admin:Secret@prod:5432/db sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"}]}'

# 2. Scoring agent читает заявки → редактирует passport_number и model_internal_params
curl -X POST http://localhost:8000/v1/db/query \
  -H "Content-Type: application/json" \
  -H "X-Gateway-Token: tok_scoring_agent_demo" \
  -d '{"table":"loan_applications"}'

# 3. Chatbot пытается читать таблицу investors напрямую → BLOCK (нет в allowed_tables)
curl -X POST http://localhost:8000/v1/db/query \
  -H "Content-Type: application/json" \
  -H "X-Gateway-Token: tok_support_chatbot_demo" \
  -d '{"table":"investors"}'

# 4. Chatbot читает investor_balances_view (разрешённый агрегат) → ALLOW
curl -X POST http://localhost:8000/v1/db/query \
  -H "Content-Type: application/json" \
  -H "X-Gateway-Token: tok_support_chatbot_demo" \
  -d '{"table":"investor_balances_view"}'
```

## Что это прототип, а не продукт

- Detection Engine — regex-based. В продакшене: NER-модель (spaCy/Presidio) или
  fine-tuned классификатор, плюс контрольные суммы для ИНН/СНИЛС/карт.
- LLM-прокси возвращает мок-ответ, не дёргает реальный OpenAI API (нужен платный ключ).
- DB-прокси работает на SQLite демо-данных, не на реальной Postgres клиента.
- Политики агентов захардкожены в `policy.py`. В проде — БД + админ-панель,
  куда выгружается финальная Access Policy Matrix из Notion-аудита.
- Нет аутентификации/TLS между gateway и upstream — для прототипа не критично,
  для прода обязательно.

## Путь к продакшену (соответствует Remediation Roadmap)

1. Заменить regex-детекцию на Presidio/NER + кастомные правила под регуляторику клиента
2. Подключить реальный SQL-парсер (sqlglot) вместо ограничения "только SELECT по таблице"
3. Вынести политики в БД с админ-панелью — прямой экспорт из Notion Access Policy Matrix
4. Добавить алертинг (Slack/email) при CRITICAL-блокировках в реальном времени
5. Контейнеризация + деплой как sidecar рядом с production-сервисами клиента
