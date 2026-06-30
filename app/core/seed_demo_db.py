"""
Создаёт демо-версию production БД Crowd 1.0 для прототипа.
Запускать один раз: python -m app.core.seed_demo_db
"""
import sqlite3
from pathlib import Path
from app.core.config import settings


def seed():
    db_path = Path(settings.protected_db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Таблица заявок малого бизнеса — содержит коммерческую тайну и финданные
    cur.execute(
        """
        CREATE TABLE loan_applications (
            id INTEGER PRIMARY KEY,
            company_name TEXT,
            revenue_annual TEXT,
            debt_total TEXT,
            passport_number TEXT,
            model_internal_params TEXT,   -- коммерческая тайна: веса скоринговой модели
            score_result TEXT
        )
        """
    )
    cur.executemany(
        "INSERT INTO loan_applications VALUES (?,?,?,?,?,?,?)",
        [
            (1, "ООО Ромашка", "45000000 руб", "12000000 руб", "45 12 678901",
             "weight_revenue=0.34;weight_debt_ratio=0.51;threshold=0.62", "approved"),
            (2, "ИП Сидоров", "8500000 руб", "1200000 руб", "46 08 112233",
             "weight_revenue=0.34;weight_debt_ratio=0.51;threshold=0.62", "review"),
        ],
    )

    # Таблица инвесторов — персональные + финансовые данные
    cur.execute(
        """
        CREATE TABLE investors (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            passport_number TEXT,
            balance TEXT,
            transaction_details TEXT
        )
        """
    )
    cur.executemany(
        "INSERT INTO investors VALUES (?,?,?,?,?,?,?)",
        [
            (1, "Иванов Иван Иванович", "ivanov@example.com", "+7 916 123 45 67",
             "45 03 556677", "1250000 руб",
             "2026-06-01: +500000 руб перевод с карты 4276 1234 5678 9012"),
            (2, "Петрова Анна Сергеевна", "petrova@example.com", "+7 925 765 43 21",
             "44 09 887766", "320000 руб",
             "2026-05-20: +100000 руб перевод"),
        ],
    )

    # Безопасное представление для чат-бота — только агрегаты, без чувствительных полей.
    # Это и есть техническая реализация рекомендации из Remediation Roadmap:
    # "Сузить scope чат-бота до агрегатов"
    cur.execute(
        """
        CREATE VIEW investor_balances_view AS
        SELECT id, full_name, balance FROM investors
        """
    )

    # "Документация схемы" — то немногое, что разрешено coding assistant
    cur.execute(
        """
        CREATE TABLE public_schema_docs (
            table_name TEXT,
            description TEXT
        )
        """
    )
    cur.executemany(
        "INSERT INTO public_schema_docs VALUES (?,?)",
        [
            ("loan_applications", "Заявки малого бизнеса на финансирование"),
            ("investors", "Инвесторы платформы (PII + финансовые данные, ограниченный доступ)"),
        ],
    )

    conn.commit()
    conn.close()
    print(f"Demo DB seeded at {db_path}")


if __name__ == "__main__":
    seed()
