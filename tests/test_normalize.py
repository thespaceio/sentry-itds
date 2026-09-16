from itds.normalize.normalizer import (
    IdentityResolver,
    Normalizer,
    classify_sensitivity,
    is_personal_cloud,
)
from itds.schema import Sensitivity


def test_identifier_variants_collapse_to_one_actor():
    r = IdentityResolver()
    r.register("faith.alabi", "falabi", "CORP\\falabi", "faith.alabi@corp.example")
    for variant in ("falabi", "CORP\\falabi", "faith.alabi@corp.example", "Faith.Alabi"):
        assert r.resolve(variant) == "faith.alabi"


def test_unregistered_variants_still_canonicalize_together():
    r = IdentityResolver()
    assert r.resolve("j.doe@corp.example") == r.resolve("CORP\\jdoe")


def test_sensitivity_from_path():
    assert classify_sensitivity("/hr/personnel/contract.pdf") is Sensitivity.RESTRICTED
    assert classify_sensitivity("/finance/ledgers/q1.xlsx") is Sensitivity.CONFIDENTIAL
    assert classify_sensitivity("/public/logo.png") is Sensitivity.PUBLIC
    assert classify_sensitivity(None) is Sensitivity.INTERNAL


def test_personal_cloud_detection():
    assert is_personal_cloud("files.dropbox.com")
    assert is_personal_cloud("drive.google.com/upload")
    assert not is_personal_cloud("intranet.corp")
    assert not is_personal_cloud(None)


def test_cert_row_maps_to_event():
    n = Normalizer()
    event = n.map_cert(
        {
            "_cert_source": "logon.csv",
            "user": "DTAA/ABC0174",
            "date": "01/15/2011 08:31:22",
            "pc": "PC-1234",
            "activity": "Logon",
        }
    )
    assert event is not None
    assert event.action == "logon_success"
    assert event.host == "PC-1234"


def test_unparseable_row_is_dropped_not_raised():
    assert Normalizer().map_cert({"_cert_source": "logon.csv"}) is None


def test_normalizer_strips_and_counts_forbidden_fields():
    n = Normalizer()
    rows = [
        {
            "_cert_source": "file.csv",
            "user": "u1",
            "date": "01/15/2011 08:31:22",
            "filename": "/hr/x.doc",
            "keystrokes": "should never be stored",
        }
    ]
    events = list(n.normalize_many(rows, n.map_cert))
    assert len(events) == 1
    assert n.dropped_fields["keystrokes"] == 1
