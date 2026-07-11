import pytest

from tests.fixtures.samples import (
    PII_NEGATIVES,
    PII_POSITIVES,
    SECRET_NEGATIVES,
    SECRET_POSITIVES,
)
from tracewarden.detectors._text import luhn_valid, shannon_entropy
from tracewarden.detectors.base import ScanContext
from tracewarden.detectors.pii import PiiDetector
from tracewarden.detectors.secrets import SecretDetector
from tracewarden.schema import EventType, Surface


def ctx(text: str, surface: Surface = Surface.COMPLETION) -> ScanContext:
    return ScanContext(surface=surface, text=text)


@pytest.mark.parametrize(("label", "text"), SECRET_POSITIVES, ids=[s[0] for s in SECRET_POSITIVES])
def test_secret_positives(label: str, text: str) -> None:
    events = SecretDetector().scan(ctx(text))
    assert events, f"{label} should be detected"
    assert all(e.type is EventType.SECRET_LEAK for e in events)
    rules = {e.rule for e in events}
    assert label in rules
    # evidence is always redacted — never the raw secret
    for event in events:
        assert "len=" in event.evidence


@pytest.mark.parametrize("text", SECRET_NEGATIVES)
def test_secret_negatives(text: str) -> None:
    assert SecretDetector().scan(ctx(text)) == []


@pytest.mark.parametrize(("label", "text"), PII_POSITIVES, ids=[s[0] for s in PII_POSITIVES])
def test_pii_positives(label: str, text: str) -> None:
    events = PiiDetector().scan(ctx(text))
    assert any(e.rule == label for e in events), f"{label} should be detected"
    assert all(e.type is EventType.PII_LEAK for e in events)


@pytest.mark.parametrize("text", PII_NEGATIVES)
def test_pii_negatives_no_high_severity(text: str) -> None:
    # low-signal negatives may match a low-confidence phone rule; the point is
    # no high-severity false positive (card/ssn) fires
    events = PiiDetector().scan(ctx(text))
    assert all(e.rule not in {"credit_card", "us_ssn"} for e in events)


def test_luhn_gate() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("1234567890123456")


def test_entropy_gate_orders_random_above_words() -> None:
    assert shannon_entropy("aaaaaa") < shannon_entropy("Xq7#Lm2$Pv9!")


def test_redaction_never_contains_full_secret() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    events = SecretDetector().scan(ctx(f"key {secret}"))
    assert events
    assert all(secret not in e.evidence for e in events)
