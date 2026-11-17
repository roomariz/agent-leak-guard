"""Presidio integration plus an explicitly limited offline demonstration adapter."""
import re
from typing import Protocol


class Redactor(Protocol):
    def redact(self, text: str) -> str: ...


class PresidioRedactor:
    """Uses Presidio's analyzer + anonymizer. Requires spaCy en_core_web_sm."""

    def __init__(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
        except ImportError as exc:
            raise RuntimeError(
                "Presidio is unavailable. Install requirements.txt and run "
                "'python -m spacy download en_core_web_sm'. "
                "Use --redactor regex-demo ONLY for an offline illustrative run."
            ) from exc
        try:
            self._analyzer = AnalyzerEngine()
            self._anonymizer = AnonymizerEngine()
        except Exception as exc:
            raise RuntimeError(
                "Could not initialise Presidio. Install its supported spaCy model "
                "with 'python -m spacy download en_core_web_sm'."
            ) from exc

    def redact(self, text: str) -> str:
        from presidio_anonymizer.entities import OperatorConfig
        findings = self._analyzer.analyze(text=text, language="en")
        return self._anonymizer.anonymize(
            text=text,
            analyzer_results=findings,
            operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                       "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL_ADDRESS]"})},
        ).text


class RegexDemoRedactor:
    """Offline smoke test ONLY; recognises simple email addresses, not general PII."""

    _email = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    def redact(self, text: str) -> str:
        return self._email.sub("[EMAIL_ADDRESS]", text)
