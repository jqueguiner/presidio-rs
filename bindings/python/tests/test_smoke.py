"""Smoke tests for the presidio_rs extension module (run after `maturin develop`)."""
import presidio_rs


def test_analyze_credit_card():
    out = presidio_rs.analyze("card 4095-2609-9393-4932")
    assert any(r["entity_type"] == "CREDIT_CARD" and r["score"] == 1.0 for r in out)


def test_anonymize_redact():
    assert presidio_rs.anonymize("hi a@b.com", operator="redact") == "hi "


def test_anonymize_mask():
    assert presidio_rs.anonymize(
        "4095260993934932",
        operator="mask",
        masking_char="#",
    ).endswith("#")


def test_supported_entities():
    ents = presidio_rs.supported_entities()
    assert "EMAIL_ADDRESS" in ents
    assert "CREDIT_CARD" in ents


def test_version():
    assert isinstance(presidio_rs.__version__, str)
