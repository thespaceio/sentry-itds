import pytest

from itds.config import PrivacyConfig
from itds.privacy import CollectionPolicy, Pseudonymizer, RevealDenied

REASON = "Investigating case 4417, bulk restricted-file access during notice period"


def test_pseudonyms_are_stable():
    p = Pseudonymizer()
    assert p.pseudonym("falabi") == p.pseudonym("falabi")


def test_different_users_get_different_pseudonyms():
    p = Pseudonymizer()
    assert p.pseudonym("alice") != p.pseudonym("bob")


def test_salt_changes_the_mapping():
    a = Pseudonymizer(PrivacyConfig(pseudonym_salt="salt-a"))
    b = Pseudonymizer(PrivacyConfig(pseudonym_salt="salt-b"))
    assert a.pseudonym("alice") != b.pseudonym("alice")


def test_reveal_requires_a_substantive_reason():
    p = Pseudonymizer()
    pseud = p.pseudonym("alice")
    with pytest.raises(RevealDenied):
        p.reveal(pseud, requested_by="analyst1", reason="", approved_by="lead")
    with pytest.raises(RevealDenied):
        p.reveal(pseud, requested_by="analyst1", reason="because", approved_by="lead")


def test_reveal_requires_a_second_approver():
    p = Pseudonymizer()
    pseud = p.pseudonym("alice")
    with pytest.raises(RevealDenied):
        p.reveal(pseud, requested_by="analyst1", reason=REASON)


def test_approver_cannot_be_the_requester():
    p = Pseudonymizer()
    pseud = p.pseudonym("alice")
    with pytest.raises(RevealDenied):
        p.reveal(pseud, requested_by="analyst1", reason=REASON, approved_by="analyst1")


def test_valid_reveal_is_audited():
    p = Pseudonymizer()
    pseud = p.pseudonym("alice")
    assert p.reveal(pseud, requested_by="analyst1", reason=REASON, approved_by="lead") == "alice"
    assert len(p.audit_log) == 1
    assert p.audit_log[0].reason == REASON
    assert p.audit_log[0].approved_by == "lead"


def test_audit_log_cannot_be_mutated_from_outside():
    p = Pseudonymizer()
    pseud = p.pseudonym("alice")
    p.reveal(pseud, requested_by="a1", reason=REASON, approved_by="lead")
    p.audit_log.clear()
    assert len(p.audit_log) == 1


def test_forbidden_fields_are_stripped_at_ingest():
    policy = CollectionPolicy()
    clean, removed = policy.scrub(
        {"actor_id": "u1", "action": "file_read", "file_content": "...", "keystrokes": "..."}
    )
    assert "file_content" not in clean
    assert "keystrokes" not in clean
    assert clean["actor_id"] == "u1"
    assert set(removed) == {"file_content", "keystrokes"}


def test_scrubbing_keeps_the_behavioural_signal():
    """Stripping content must not drop the event."""
    clean, _ = CollectionPolicy().scrub(
        {"actor_id": "u1", "bytes": 5000, "message_body": "secret"}
    )
    assert clean["bytes"] == 5000
