"""CERT evaluation plumbing, on a tiny fake dataset in CERT's file formats.

The real benchmark runs in the Accuracy (CERT) workflow; this checks that the
loaders, answer key and rolling windows fit together.
"""

import csv
import random
from datetime import datetime, timedelta

from itds.config import Config
from itds.evaluation import load_cert_identities, load_cert_insiders, rolling_evaluate
from itds.ingest.sources import import_files

START = datetime(2010, 1, 4)
DAYS = 120
INSIDER = "ZZZ0001"
BAD_FROM = START + timedelta(days=96)


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def make_fake_cert(root):
    rng = random.Random(5)
    users = [INSIDER] + [f"AAA{n:04d}" for n in range(1, 24)]
    logon, device, files, email = [], [], [], []
    n = 0
    for d in range(DAYS):
        day = START + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for u in users:
            pc = f"PC-{users.index(u):04d}"
            t = day + timedelta(hours=8, minutes=rng.randint(0, 50))
            n += 1
            logon.append([f"{{L{n}}}", t.strftime("%m/%d/%Y %H:%M:%S"), f"DTAA/{u}", pc, "Logon"])
            for k in range(rng.randint(3, 8)):
                n += 1
                te = t + timedelta(minutes=30 * k + 5)
                email.append([f"{{E{n}}}", te.strftime("%m/%d/%Y %H:%M:%S"), f"DTAA/{u}", pc,
                              "colleague@dtaa.com", "", "", f"{u.lower()}@dtaa.com",
                              rng.randint(20000, 60000), 0, "body text never stored"])
            bad = u == INSIDER and day >= BAD_FROM
            if bad:
                for k in range(12):
                    n += 1
                    tn = day + timedelta(hours=23, minutes=4 * k)
                    logon.append([f"{{L{n}}}", tn.strftime("%m/%d/%Y %H:%M:%S"), f"DTAA/{u}",
                                  pc, "Logon"])
                    device.append([f"{{D{n}}}", tn.strftime("%m/%d/%Y %H:%M:%S"), f"DTAA/{u}",
                                   pc, "Connect"])
                for k in range(300):
                    n += 1
                    tf = day + timedelta(hours=23, minutes=k % 50)
                    files.append([f"{{F{n}}}", tf.strftime("%m/%d/%Y %H:%M:%S"), f"DTAA/{u}", pc,
                                  f"R:\\HR\\personnel\\file_{k}.doc", "content never stored"])
                for k in range(25):
                    n += 1
                    te = day + timedelta(hours=22, minutes=k)
                    email.append([f"{{E{n}}}", te.strftime("%m/%d/%Y %H:%M:%S"), f"DTAA/{u}", pc,
                                  "someone@competitor.com", "", "", f"{u.lower()}@dtaa.com",
                                  4_000_000, 2, "never stored"])
    _write(root / "logon.csv", ["id", "date", "user", "pc", "activity"], logon)
    _write(root / "device.csv", ["id", "date", "user", "pc", "activity"], device)
    _write(root / "file.csv", ["id", "date", "user", "pc", "filename", "content"], files)
    _write(root / "email.csv", ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size",
                                "attachments", "content"], email)
    ldap = root / "LDAP"
    ldap.mkdir()
    for m in range(1, 5):
        present = users if m < 4 else users[1:]  # the insider leaves after month 3
        _write(ldap / f"2010-{m:02d}.csv",
               ["employee_name", "user_id", "email", "role", "business_unit",
                "functional_unit", "department", "team", "supervisor"],
               [[f"Person {u}", u, f"{u.lower()}@dtaa.com", "Salesman", "1",
                 "Sales And Marketing", "Sales", "1", ""] for u in present])
    answers = root / "answers"
    answers.mkdir()
    end = START + timedelta(days=DAYS - 1)
    _write(answers / "insiders.csv", ["dataset", "scenario", "details", "user", "start", "end"],
           [["4.2", 1, "r4.2-1-ZZZ0001.csv", INSIDER, BAD_FROM.strftime("%m/%d/%Y %H:%M:%S"),
             end.strftime("%m/%d/%Y %H:%M:%S")],
            ["5.2", 1, "other-release.csv", "AAA0001", "01/01/2010 00:00:00",
             "01/02/2010 00:00:00"]])
    return root


def test_cert_loaders(tmp_path):
    root = make_fake_cert(tmp_path)
    events, report = import_files("cert", [root])
    assert report["forbidden fields removed"]["content"] > 0
    assert all(e.actor_id == e.actor_id.lower() for e in events)
    insiders = load_cert_insiders(root / "answers", "4.2")
    assert [i.actor_id for i in insiders] == ["zzz0001"]
    ids = load_cert_identities(root / "LDAP")
    assert ids["zzz0001"].last_day_on is not None
    assert ids["aaa0001"].last_day_on is None
    assert load_cert_identities(root / "LDAP", departure_context=False)["zzz0001"].last_day_on is None


def test_rolling_evaluation_finds_the_insider(tmp_path):
    root = make_fake_cert(tmp_path)
    events, _ = import_files("cert", [root])
    res = rolling_evaluate(events, load_cert_identities(root / "LDAP", departure_context=False),
                           load_cert_insiders(root / "answers", "4.2"), config=Config(),
                           window_days=14, train_days=60)
    assert res["windows"] >= 4
    assert res["insiders_evaluable"] == 1
    assert res["insiders_detected"] == 1
    assert res["recall"] == 1.0
    assert res["case_precision"] is not None
