"""
Detection Engine — классификатор чувствительных данных.

Это автоматизированная версия колонок "Тип данных" и "Уровень риска"
из Access Policy Matrix (Level 2). На вход — произвольный текст
(промпт к LLM или результат SQL-запроса), на выход — список найденных
сущностей с типом и уровнем риска.

Прототип использует regex + эвристики. В продакшене это место для
NER-модели (spaCy/Presidio) или fine-tuned классификатора, но для
демонстрации механики regex более чем достаточен и не требует
тяжёлых ML-зависимостей.
"""
import re
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class EntityType(str, Enum):
    # Credentials / secrets — всегда CRITICAL
    API_KEY = "api_key"
    DB_CONNECTION_STRING = "db_connection_string"
    PRIVATE_KEY = "private_key"
    AWS_SECRET = "aws_secret"
    JWT_TOKEN = "jwt_token"

    # Персональные данные (152-ФЗ / GDPR) — HIGH
    EMAIL = "email"
    PHONE_RU = "phone_ru"
    PASSPORT_RU = "passport_ru"
    SNILS = "snils"
    INN = "inn"
    CARD_NUMBER = "card_number"

    # Финансовые данные — HIGH/MEDIUM
    IBAN = "iban"
    AMOUNT_LARGE = "amount_large"

    NONE = "none"


# Уровень риска по типу сущности — это политика, аналог Access Policy Matrix
ENTITY_RISK_MAP: dict[EntityType, RiskLevel] = {
    EntityType.API_KEY: RiskLevel.CRITICAL,
    EntityType.DB_CONNECTION_STRING: RiskLevel.CRITICAL,
    EntityType.PRIVATE_KEY: RiskLevel.CRITICAL,
    EntityType.AWS_SECRET: RiskLevel.CRITICAL,
    EntityType.JWT_TOKEN: RiskLevel.CRITICAL,
    EntityType.PASSPORT_RU: RiskLevel.HIGH,
    EntityType.SNILS: RiskLevel.HIGH,
    EntityType.INN: RiskLevel.HIGH,
    EntityType.CARD_NUMBER: RiskLevel.HIGH,
    EntityType.IBAN: RiskLevel.HIGH,
    EntityType.EMAIL: RiskLevel.MEDIUM,
    EntityType.PHONE_RU: RiskLevel.MEDIUM,
    EntityType.AMOUNT_LARGE: RiskLevel.LOW,
}

# Регулярки. Это прототип — для прода нужна валидация по контрольным суммам
# (особенно для ИНН/СНИЛС/карт), но для демонстрации паттерна этого достаточно.
PATTERNS: dict[EntityType, re.Pattern] = {
    EntityType.API_KEY: re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b"),
    EntityType.AWS_SECRET: re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    EntityType.JWT_TOKEN: re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"),
    EntityType.PRIVATE_KEY: re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    EntityType.DB_CONNECTION_STRING: re.compile(
        r"\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+\b"
    ),
    EntityType.EMAIL: re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    EntityType.PHONE_RU: re.compile(r"\b(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b"),
    EntityType.PASSPORT_RU: re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b"),
    EntityType.SNILS: re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b"),
    EntityType.INN: re.compile(r"\b\d{10}\b|\b\d{12}\b"),
    EntityType.CARD_NUMBER: re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    EntityType.IBAN: re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    EntityType.AMOUNT_LARGE: re.compile(r"\b\d{7,}(?:[.,]\d{2})?\s?(?:руб|₽|USD|\$)\b"),
}


@dataclass
class DetectedEntity:
    entity_type: EntityType
    risk_level: RiskLevel
    matched_text: str
    start: int
    end: int


@dataclass
class ScanResult:
    text: str
    entities: list[DetectedEntity] = field(default_factory=list)

    @property
    def highest_risk(self) -> RiskLevel:
        if not self.entities:
            return RiskLevel.NONE
        order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
        for level in order:
            if any(e.risk_level == level for e in self.entities):
                return level
        return RiskLevel.NONE

    @property
    def entity_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for e in self.entities:
            summary[e.entity_type.value] = summary.get(e.entity_type.value, 0) + 1
        return summary


def scan_text(text: str) -> ScanResult:
    """Сканирует текст и возвращает все найденные чувствительные сущности."""
    entities: list[DetectedEntity] = []
    for entity_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            # ИНН и суммы дают много ложных срабатываний на случайных числах —
            # для прототипа это ожидаемо, в проде здесь нужна доп. валидация
            entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    risk_level=ENTITY_RISK_MAP.get(entity_type, RiskLevel.LOW),
                    matched_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return ScanResult(text=text, entities=entities)


def redact_text(text: str, entities: list[DetectedEntity]) -> str:
    """Заменяет найденные сущности на маски вида [REDACTED:TYPE]."""
    if not entities:
        return text
    # Сортируем с конца, чтобы индексы не съезжали при замене
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
    result = text
    for e in sorted_entities:
        mask = f"[REDACTED:{e.entity_type.value.upper()}]"
        result = result[: e.start] + mask + result[e.end :]
    return result
