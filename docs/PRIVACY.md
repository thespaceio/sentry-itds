# Privacy and governance

Insider threat monitoring watches employees. Done carelessly it is surveillance that erodes trust, invites bias and creates a database of everyone's behaviour that is itself a target. Sentry builds the controls into the code, so that using the system well is the default and misusing it takes deliberate, recorded effort.

This is engineering guidance, not legal advice. Involve your data protection officer and legal counsel before deploying any monitoring.

## Controls that run in the code

| Control | Where | What it does |
|---|---|---|
| Metadata only | `privacy.CollectionPolicy` | Message bodies, file contents, keystrokes, screenshots, webcam, microphone, clipboard and passwords are stripped at ingest. The event is kept; the intrusive field is not. |
| Pseudonymous triage | `privacy.Pseudonymizer` | Analysts see `EMP-6131ba`, a salted HMAC of the real id. Investigation happens on behaviour, not on who the person is. |
| Two-person reveal | API `/api/reveals`, CLI `reveal` | Re-identification needs a written reason (15 characters or more) and approval by a lead who is not the requester. Only those two people see the identity. |
| Audit of the watchers | `audit.AuditLog` | Every sign in, case view, verdict, reveal request and decision is written to a hash chain. Editing or deleting an entry is detectable. |
| Retention | `python -m itds purge` | Raw events are deleted after 90 days and closed cases after 365 by default (`ITDS_EVENT_RETENTION_DAYS`, `ITDS_CASE_RETENTION_DAYS`). The audit log is kept. |
| Separation of duties | `auth.PERMISSIONS` | Admins manage accounts but cannot read cases or approve reveals. |
| Privacy-safe alerts | `alerts.case_payload` | Chat and email alerts carry the pseudonym, score and findings, never a name or department. |
| Time-limited exceptions | `feedback.add_suppression` | Suppressions expire (maximum 180 days) so a past false alarm cannot permanently hide a person. |

## Before you deploy

1. **Change the pseudonym salt.** `ITDS_PSEUDONYM_SALT` must be a long random secret. A default salt means anyone can compute pseudonyms.
2. **Serve over HTTPS** and set `ITDS_COOKIE_SECURE=1`.
3. **Create named accounts** for every analyst and lead. Never share accounts: the audit log is only as good as the identities in it.
4. **Export the audit head regularly** (`python -m itds audit head`) to a system the database administrators cannot change, so a rewritten chain is detectable.
5. **Restrict network access** to the dashboard to the security team.
6. **Decide retention** with legal and set it in configuration.
7. **Feed real classification labels** if you have a DLP or labelling system; path heuristics misclassify.

## Nigeria Data Protection Act 2023 (NDPA)

For organisations in Nigeria, monitoring employees is processing personal data under the NDPA. Points that bear directly on Sentry:

* **Principles (section 24).** Purpose limitation, data minimisation, storage limitation and security. Metadata-only collection, retention and pseudonymisation are how Sentry supports these.
* **Lawful basis.** Employee monitoring for security normally relies on legitimate interests or legal obligation rather than consent, which is rarely freely given in employment. Record the balancing test.
* **Data privacy impact assessment (section 28).** Systematic monitoring of employees is the kind of high-risk processing that calls for a DPIA before you start. An outline is below.
* **Security of processing (section 39).** Encryption in transit, access control, audit logging and breach procedures for the Sentry database itself.
* **Automated decisions.** Sentry ranks people for human review; it must never be the sole basis for disciplinary action. Keep a human decision, documented in the case, between a score and any consequence.
* **Transparency.** Tell employees that monitoring happens, what is collected, why, how long it is kept and how to exercise their rights.

The same principles apply under the GDPR and most other modern data protection laws.

## DPIA outline

1. **Purpose.** Detect data theft, account compromise and misuse of privileged access.
2. **Necessity and proportionality.** Why less intrusive measures (access control, DLP) are not enough on their own; why metadata suffices.
3. **Data.** Event types, sources, fields collected and fields explicitly excluded.
4. **People affected.** Employees, contractors, service accounts.
5. **Risks to individuals.** Chilling effect, biased investigation, false accusation, breach of the monitoring database.
6. **Measures.** Pseudonymisation, two-person reveal, audit chain, retention, role separation, human review before any action.
7. **Residual risk and sign-off** by the data protection officer.

## Employee notice (template)

> To protect company and customer information, we monitor activity on company systems for signs of data theft and account misuse. We record metadata such as logons, file access, data transfers and administrative commands. We do not record the contents of your messages or files, your keystrokes or your screen. Monitoring results are reviewed under a pseudonym; identifying a person requires a documented reason and approval by a second reviewer, and every review is logged. Records are kept for 90 days unless they are part of an open investigation. No action is taken against anyone on the basis of an automated score alone. Contact [data protection officer] with questions or to exercise your rights.
