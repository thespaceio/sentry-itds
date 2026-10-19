"""MITRE ATT&CK mapping.

Every detection carries the ATT&CK techniques it is evidence of, so an analyst
(or a SIEM) can reason about a case in the vocabulary the rest of the security
team already uses. Rules declare their techniques in YAML; the statistical and
ML engines map from the features that drove them.

Only techniques Sentry can genuinely observe from metadata are listed. Mapping
a detection to a technique is a claim, and over-claiming is how dashboards end
up full of red tiles that mean nothing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "tactic": self.tactic, "url": self.url}


CATALOGUE: dict[str, Technique] = {
    t.id: t
    for t in (
        Technique("T1005", "Data from Local System", "Collection"),
        Technique("T1039", "Data from Network Shared Drive", "Collection"),
        Technique("T1074", "Data Staged", "Collection"),
        Technique("T1114.003", "Email Forwarding Rule", "Collection"),
        Technique("T1213", "Data from Information Repositories", "Collection"),
        Technique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        Technique("T1052.001", "Exfiltration over USB", "Exfiltration"),
        Technique("T1567", "Exfiltration Over Web Service", "Exfiltration"),
        Technique("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration"),
        Technique("T1078", "Valid Accounts", "Initial Access"),
        Technique("T1110", "Brute Force", "Credential Access"),
        Technique("T1021", "Remote Services", "Lateral Movement"),
        Technique("T1087", "Account Discovery", "Discovery"),
        Technique("T1083", "File and Directory Discovery", "Discovery"),
        Technique("T1098", "Account Manipulation", "Persistence"),
        Technique("T1070", "Indicator Removal", "Defense Evasion"),
        Technique("T1059", "Command and Scripting Interpreter", "Execution"),
    )
}

# Feature -> techniques, used by the statistical and ML engines.
FEATURE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "file_read_count": ("T1039", "T1005"),
    "distinct_files": ("T1083", "T1039"),
    "restricted_file_count": ("T1213", "T1039"),
    "confidential_file_count": ("T1213",),
    "file_write_count": ("T1074",),
    "total_bytes": ("T1074",),
    "upload_bytes": ("T1048",),
    "personal_cloud_bytes": ("T1567.002",),
    "external_email_count": ("T1048",),
    "external_email_bytes": ("T1048",),
    "external_share_count": ("T1567",),
    "removable_media_count": ("T1052.001",),
    "removable_media_bytes": ("T1052.001",),
    "failed_logon_count": ("T1110",),
    "distinct_hosts": ("T1021",),
    "distinct_countries": ("T1078",),
    "privileged_action_count": ("T1059", "T1087"),
}


def techniques_for_features(features: list[str] | tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for f in features:
        for t in FEATURE_TECHNIQUES.get(f, ()):
            if t not in out:
                out.append(t)
    return out


def describe(ids: list[str]) -> list[dict]:
    """Expand technique ids to name, tactic and link for display."""
    return [CATALOGUE[i].to_dict() for i in ids if i in CATALOGUE]


def validate(ids: list[str]) -> list[str]:
    """Return any ids not in the catalogue (used to lint rule files)."""
    return [i for i in ids if i not in CATALOGUE]
