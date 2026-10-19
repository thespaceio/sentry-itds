"""Synthetic dataset generator.

Real insider threat data is scarce, sensitive and never labelled, so Sentry
ships a generator that produces an organization with realistic routine noise
and a small number of planted scenarios with known ground truth.

The scenarios are chosen to break naive systems, not to flatter this one:

Threats (must be found):
* ``departing_exfil``     resigned, then bulk-reads files, uploads gigabytes
                          to personal cloud storage and copies to USB.
* ``data_hoarder``        not leaving; reads restricted material from other
                          departments late at night, a little more each week.
* ``compromised_account`` a stolen credential: logons from two countries in a
                          day, failed logons, many hosts, privileged commands.

Careless but innocent (must not outrank the threats):
* ``negligent_sharer``    a salesperson who emails large attachments and uses
                          WeTransfer every day, as they always have.
* ``negligent_usb``       backs files up to a USB stick every week.

Plus traps with no label at all: people who resign and behave normally, a new
joiner with almost no history, weekend workers, travellers and the odd
personal Dropbox upload.
"""

from __future__ import annotations

import math
import random
from datetime import UTC, date, datetime, timedelta

from ..normalize.normalizer import classify_sensitivity
from ..schema import Category, Event, Identity

START = datetime(2026, 7, 1, tzinfo=UTC)

DEPARTMENTS: dict[str, dict] = {
    # reads: mean daily file reads; ext: mean daily external emails
    "engineering": {"prefix": "/eng/src", "ext": ".py", "reads": 45, "ext_mail": 1, "share": 0.25,
                    "roles": ["Software engineer", "Senior engineer", "QA engineer"]},
    "finance": {"prefix": "/finance/ledgers", "ext": ".xlsx", "reads": 35, "ext_mail": 4,
                "share": 0.13, "roles": ["Accountant", "Financial analyst"]},
    "hr": {"prefix": "/hr/personnel", "ext": ".pdf", "reads": 22, "ext_mail": 3, "share": 0.08,
           "roles": ["HR officer", "Recruiter"]},
    "sales": {"prefix": "/sales/customers", "ext": ".pptx", "reads": 25, "ext_mail": 14,
              "share": 0.2, "roles": ["Account executive", "Sales manager"]},
    "operations": {"prefix": "/ops/reports", "ext": ".docx", "reads": 30, "ext_mail": 3,
                   "share": 0.17, "roles": ["Operations analyst", "Ops coordinator"]},
    "it": {"prefix": "/it/configs", "ext": ".conf", "reads": 28, "ext_mail": 1, "share": 0.1,
           "roles": ["Systems administrator", "IT support"]},
    "legal": {"prefix": "/legal/contracts", "ext": ".pdf", "reads": 18, "ext_mail": 5,
              "share": 0.07, "roles": ["Legal counsel", "Paralegal"]},
}

# Restricted material outside a finance user's normal area: the hoarder's target.
FOREIGN_RESTRICTED = [
    "/hr/personnel/salary_review_{k}.xlsx",
    "/legal/merger_due_diligence/{k}.pdf",
    "/exec/board/minutes_{k}.docx",
    "/hr/disciplinary/case_{k}.pdf",
]

FIRST = ["Adaeze", "Tunde", "Ngozi", "Emeka", "Funmi", "Ibrahim", "Chioma", "Segun", "Aisha",
         "Kelechi", "Bola", "Musa", "Zainab", "Femi", "Amaka", "Yusuf", "Halima", "Uche",
         "Kemi", "Daniel", "Grace", "Samuel", "Esther", "David", "Ruth", "Joseph", "Mary",
         "Peter", "Sarah", "John"]
LAST = ["Okafor", "Adeyemi", "Bello", "Eze", "Ogunleye", "Abubakar", "Nwosu", "Balogun",
        "Okonkwo", "Lawal", "Ibe", "Danjuma", "Ajayi", "Obi", "Salami", "Umeh", "Garba",
        "Akande", "Nnadi", "Yakubu"]


class SyntheticGenerator:
    def __init__(self, n_users: int = 60, days: int = 60, seed: int = 42,
                 start: datetime = START) -> None:
        if n_users < 20:
            raise ValueError("need at least 20 users to plant every scenario")
        if days < 30:
            raise ValueError("need at least 30 days: history to learn from, then a window")
        self.n_users = n_users
        self.days = days
        self.seed = seed
        self.start = start
        self.rng = random.Random(seed)

    # -- helpers --------------------------------------------------------

    def _poisson(self, lam: float) -> int:
        if lam <= 0:
            return 0
        if lam > 30:
            return max(0, round(self.rng.gauss(lam, math.sqrt(lam))))
        L, k, p = math.exp(-lam), 0, 1.0
        while True:
            p *= self.rng.random()
            if p <= L:
                return k
            k += 1

    def _ts(self, day: date, hour_lo: float, hour_hi: float) -> datetime:
        h = self.rng.uniform(hour_lo, hour_hi)
        base = datetime(day.year, day.month, day.day, tzinfo=UTC)
        return base + timedelta(hours=h)

    def _file_event(self, actor, ts, path, host, action="file_read", size=None) -> Event:
        return Event(
            timestamp=ts, actor_id=actor, category=Category.FILE, action=action,
            host=host, object_name=path, object_sensitivity=classify_sensitivity(path),
            bytes=size if size is not None else int(self.rng.lognormvariate(12.5, 0.9)),
            source_system="synthetic",
        )

    # -- population -----------------------------------------------------

    def _build_population(self) -> list[dict]:
        names = list(DEPARTMENTS)
        weights = [DEPARTMENTS[d]["share"] for d in names]
        people = []
        # Guarantee every department has members, then fill by weight.
        depts = names + self.rng.choices(names, weights=weights, k=self.n_users - len(names))
        self.rng.shuffle(depts)
        used_names: set[str] = set()
        for i, dept in enumerate(depts, start=1):
            while True:
                name = f"{self.rng.choice(FIRST)} {self.rng.choice(LAST)}"
                if name not in used_names:
                    used_names.add(name)
                    break
            cfg = DEPARTMENTS[dept]
            people.append({
                "actor": f"u{i:03d}",
                "name": name,
                "dept": dept,
                "role": self.rng.choice(cfg["roles"]),
                "start_hour": min(10.0, max(7.0, self.rng.gauss(8.5, 0.7))),
                "length": self.rng.uniform(7.5, 9.5),
                "volume": self.rng.lognormvariate(0, 0.3),
                "weekend_worker": self.rng.random() < 0.08,
                "late_worker": self.rng.random() < 0.06,
                "dropbox_habit": self.rng.random() < 0.06,
                "host": f"WS-{1000 + i}",
                "files": [f"{cfg['prefix']}/{dept}_{k:04d}{cfg['ext']}" for k in range(250)],
            })
        return people

    def _assign_scenarios(self, people: list[dict]) -> dict[str, str]:
        by_dept: dict[str, list[dict]] = {}
        for p in people:
            by_dept.setdefault(p["dept"], []).append(p)

        def pick(dept: str, fallback: str) -> dict:
            pool = [p for p in by_dept.get(dept, []) if "scenario" not in p]
            if not pool:
                pool = [p for p in people if "scenario" not in p and p["dept"] == fallback]
            if not pool:
                pool = [p for p in people if "scenario" not in p]
            p = self.rng.choice(pool)
            return p

        plan = [
            ("departing_exfil", "engineering", "sales"),
            ("data_hoarder", "finance", "operations"),
            ("compromised_account", "operations", "finance"),
            ("negligent_sharer", "sales", "sales"),
            ("negligent_usb", "operations", "finance"),
            ("_clean_departer", "sales", "engineering"),
            ("_clean_departer", "finance", "operations"),
            ("_new_joiner", "engineering", "operations"),
        ]
        labels = {}
        for scenario, dept, fallback in plan:
            p = pick(dept, fallback)
            p["scenario"] = scenario
            # Planted people get none of the random habits, so ground truth is clean.
            p["dropbox_habit"] = scenario == "negligent_sharer"
            p["late_worker"] = False
            p["weekend_worker"] = False
            if not scenario.startswith("_"):
                labels[p["actor"]] = scenario
        return labels

    # -- routine --------------------------------------------------------

    def _routine_day(self, p: dict, day: date, events: list[Event], scale: float = 1.0) -> None:
        cfg = DEPARTMENTS[p["dept"]]
        actor, host = p["actor"], p["host"]
        weekend = day.weekday() >= 5
        if weekend:
            if not (p["weekend_worker"] and self.rng.random() < 0.5):
                return
            scale *= 0.4
        if self.rng.random() < 0.04:  # leave, sick days
            return
        lo = p["start_hour"] + self.rng.uniform(-0.4, 0.4)
        hi = lo + p["length"]

        # Authentication
        for _ in range(1 + self._poisson(0.8)):
            events.append(Event(timestamp=self._ts(day, lo - 0.2, lo + 0.3), actor_id=actor,
                                category=Category.AUTHENTICATION, action="logon_success",
                                host=host, country=p.get("country", "NG"),
                                source_system="synthetic"))
        if self.rng.random() < 0.08:
            events.append(Event(timestamp=self._ts(day, lo - 0.2, lo), actor_id=actor,
                                category=Category.AUTHENTICATION, action="logon_failure",
                                host=host, country="NG", source_system="synthetic"))

        # Files
        reads = self._poisson(cfg["reads"] * p["volume"] * scale)
        for _ in range(reads):
            path = self.rng.choice(p["files"])
            if self.rng.random() < 0.05:
                path = f"/shared/general/notice_{self.rng.randint(1, 80)}.docx"
            events.append(self._file_event(actor, self._ts(day, lo, hi), path, host))
        for _ in range(self._poisson(reads / 6)):
            events.append(self._file_event(actor, self._ts(day, lo, hi),
                                           self.rng.choice(p["files"]), host, "file_write"))

        # Email
        for _ in range(self._poisson(9 * scale)):
            events.append(Event(timestamp=self._ts(day, lo, hi), actor_id=actor,
                                category=Category.EMAIL, action="email_send",
                                destination="corp.example",
                                bytes=int(self.rng.lognormvariate(10.5, 1.0)),
                                source_system="synthetic"))
        for _ in range(self._poisson(cfg["ext_mail"] * scale)):
            events.append(Event(timestamp=self._ts(day, lo, hi), actor_id=actor,
                                category=Category.EMAIL, action="email_send_external",
                                destination="partner.example",
                                bytes=int(self.rng.lognormvariate(12.0, 1.2)),
                                extra={"external": True}, source_system="synthetic"))

        # Corporate uploads (allowed) and the occasional personal habit
        if self.rng.random() < 0.3:
            events.append(Event(timestamp=self._ts(day, lo, hi), actor_id=actor,
                                category=Category.NETWORK, action="upload",
                                destination="sharepoint.corp.example/sites/team",
                                bytes=int(self.rng.lognormvariate(15.5, 1.0)),
                                source_system="synthetic"))
        if p["dropbox_habit"] and self.rng.random() < 0.15:
            events.append(Event(timestamp=self._ts(day, lo, hi), actor_id=actor,
                                category=Category.NETWORK, action="upload",
                                destination="www.dropbox.com/upload",
                                bytes=int(self.rng.lognormvariate(16.5, 0.8)),
                                source_system="synthetic"))

        # IT administrators run privileged commands across several hosts
        if p["dept"] == "it":
            for _ in range(self._poisson(7 * scale)):
                events.append(Event(timestamp=self._ts(day, lo, hi), actor_id=actor,
                                    category=Category.PROCESS, action="privileged_command",
                                    host=f"SRV-{self.rng.randint(1, 12):02d}",
                                    source_system="synthetic"))

        # A late session now and then for people who work that way
        if p["late_worker"] and self.rng.random() < 0.3:
            for _ in range(self._poisson(6)):
                events.append(self._file_event(actor, self._ts(day, 20.5, 23.5),
                                               self.rng.choice(p["files"]), host))

    # -- scenarios ------------------------------------------------------

    def _departing_exfil(self, p, day, i_from_end, events):
        """Window: reads in bulk, personal cloud uploads, one USB copy."""
        actor, host = p["actor"], p["host"]
        if i_from_end in (9, 7, 4, 2):
            n = self.rng.randint(300, 700)
            pool = p["files"] + [f"/eng/design/architecture_{k}.pdf" for k in range(60)] + [
                f"/sales/customers/pricing_{k}.xlsx" for k in range(80)]
            for _ in range(n):
                events.append(self._file_event(actor, self._ts(day, 17.5, 21.0),
                                               self.rng.choice(pool), host, "file_copy"))
        if i_from_end in (7, 4, 2):
            for _ in range(self.rng.randint(3, 6)):
                events.append(Event(timestamp=self._ts(day, 19.0, 21.5), actor_id=actor,
                                    category=Category.NETWORK, action="upload",
                                    destination=self.rng.choice(
                                        ["www.dropbox.com/upload", "mega.nz/upload"]),
                                    bytes=self.rng.randint(400_000_000, 1_200_000_000),
                                    source_system="synthetic"))
        if i_from_end == 4:
            events.append(Event(timestamp=self._ts(day, 20.0, 20.2), actor_id=actor,
                                category=Category.REMOVABLE_MEDIA, action="usb_connect",
                                host=host, source_system="synthetic"))
            events.append(Event(timestamp=self._ts(day, 20.2, 21.0), actor_id=actor,
                                category=Category.REMOVABLE_MEDIA, action="usb_write",
                                host=host, bytes=self.rng.randint(2_000_000_000, 3_500_000_000),
                                source_system="synthetic"))

    def _data_hoarder(self, p, day, i_from_end, events):
        """Window: late-night reads of other departments' restricted files,
        a little more each time."""
        actor, host = p["actor"], p["host"]
        if day.weekday() >= 5 or i_from_end > 11:
            return
        step = 11 - i_from_end  # 0 .. 11, escalating
        n = 60 + step * 18 + self.rng.randint(0, 25)
        for _ in range(n):
            path = self.rng.choice(FOREIGN_RESTRICTED).format(k=self.rng.randint(1, 400))
            # 22:00 to 02:00
            events.append(self._file_event(actor, self._ts(day, 22.0, 23.99), path, host))

    def _compromised(self, p, day, i_from_end, events):
        """Window: a stolen credential in use for three days."""
        actor = p["actor"]
        if i_from_end not in (5, 4, 3):
            return
        foreign = self.rng.choice(["RU", "CN", "BR"])
        for _ in range(self.rng.randint(6, 15)):
            events.append(Event(timestamp=self._ts(day, 1.0, 3.5), actor_id=actor,
                                category=Category.AUTHENTICATION, action="logon_failure",
                                host="VPN-GW", country=foreign, source_ip="185.220.101.7",
                                source_system="synthetic"))
        for _ in range(self.rng.randint(3, 6)):
            events.append(Event(timestamp=self._ts(day, 1.5, 4.0), actor_id=actor,
                                category=Category.AUTHENTICATION, action="logon_success",
                                host="VPN-GW", country=foreign, source_ip="185.220.101.7",
                                source_system="synthetic"))
        for _ in range(self.rng.randint(20, 45)):
            events.append(Event(timestamp=self._ts(day, 1.5, 4.5), actor_id=actor,
                                category=Category.PROCESS, action="privileged_command",
                                host=f"SRV-{self.rng.randint(1, 30):02d}",
                                extra={"command": self.rng.choice(
                                    ["net user /domain", "whoami /all", "nltest /dclist",
                                     "Get-ADUser -Filter *", "net group \"Domain Admins\""])},
                                source_system="synthetic"))
        for _ in range(self.rng.randint(40, 90)):
            path = f"/finance/ledgers/finance_{self.rng.randint(0, 249):04d}.xlsx"
            events.append(self._file_event(actor, self._ts(day, 2.0, 4.5), path,
                                           f"SRV-{self.rng.randint(1, 30):02d}"))

    def _negligent_sharer(self, p, day, events):
        """Every working day, start to finish: big attachments and WeTransfer."""
        if day.weekday() >= 5:
            return
        actor = p["actor"]
        lo = p["start_hour"]
        for _ in range(self.rng.randint(30, 50)):
            events.append(Event(timestamp=self._ts(day, lo, lo + 8), actor_id=actor,
                                category=Category.EMAIL, action="email_send_external",
                                destination=self.rng.choice(
                                    ["client-a.example", "client-b.example", "gmail.com"]),
                                bytes=self.rng.randint(4_000_000, 12_000_000),
                                extra={"external": True, "attachments": 1},
                                source_system="synthetic"))
        if self.rng.random() < 0.6:
            events.append(Event(timestamp=self._ts(day, lo, lo + 8), actor_id=actor,
                                category=Category.NETWORK, action="upload",
                                destination="wetransfer.com/upload",
                                bytes=self.rng.randint(150_000_000, 900_000_000),
                                source_system="synthetic"))

    def _negligent_usb(self, p, day, events):
        """Weekly backup of their own files to a USB stick, every Friday."""
        if day.weekday() != 4:
            return
        actor, host = p["actor"], p["host"]
        events.append(Event(timestamp=self._ts(day, 16.0, 16.2), actor_id=actor,
                            category=Category.REMOVABLE_MEDIA, action="usb_connect",
                            host=host, source_system="synthetic"))
        events.append(Event(timestamp=self._ts(day, 16.2, 17.0), actor_id=actor,
                            category=Category.REMOVABLE_MEDIA, action="usb_write", host=host,
                            bytes=self.rng.randint(1_100_000_000, 2_000_000_000),
                            source_system="synthetic"))

    # -- main -----------------------------------------------------------

    def generate(self) -> tuple[list[Event], dict[str, Identity], dict[str, str]]:
        people = self._build_population()
        labels = self._assign_scenarios(people)
        end_day = (self.start + timedelta(days=self.days - 1)).date()

        identities: dict[str, Identity] = {}
        for p in people:
            ident = Identity(
                actor_id=p["actor"], display_name=p["name"], department=p["dept"],
                role=p["role"], is_privileged=p["dept"] == "it",
                joined_on=self.start - timedelta(days=self.rng.randint(200, 2500)),
            )
            scenario = p.get("scenario")
            if scenario == "departing_exfil":
                ident.departure_notice_on = self.start + timedelta(days=self.days - 16)
                ident.last_day_on = self.start + timedelta(days=self.days + 7)
            elif scenario == "_clean_departer":
                ident.departure_notice_on = self.start + timedelta(
                    days=self.days - self.rng.randint(10, 20))
                ident.last_day_on = ident.departure_notice_on + timedelta(days=30)
            elif scenario == "_new_joiner":
                ident.joined_on = self.start + timedelta(days=self.days - 9)
            identities[p["actor"]] = ident

        events: list[Event] = []
        for offset in range(self.days):
            day = (self.start + timedelta(days=offset)).date()
            i_from_end = (end_day - day).days
            for p in people:
                scenario = p.get("scenario")
                if scenario == "_new_joiner":
                    joined = identities[p["actor"]].joined_on.date()
                    if day < joined:
                        continue
                self._routine_day(p, day, events)
                if scenario == "departing_exfil":
                    self._departing_exfil(p, day, i_from_end, events)
                elif scenario == "data_hoarder":
                    self._data_hoarder(p, day, i_from_end, events)
                elif scenario == "compromised_account":
                    self._compromised(p, day, i_from_end, events)
                elif scenario == "negligent_sharer":
                    self._negligent_sharer(p, day, events)
                elif scenario == "negligent_usb":
                    self._negligent_usb(p, day, events)

        events.sort(key=lambda e: (e.timestamp, e.actor_id))
        return events, identities, labels
