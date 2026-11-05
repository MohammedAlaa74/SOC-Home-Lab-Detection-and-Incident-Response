# SOC Home Lab — Detection & Incident Response

A hands-on Security Operations Center (SOC) lab focused on endpoint telemetry, SIEM alert triage, threat investigation, detection validation, incident documentation, and controlled response.

> **Project status:** Active development. Detection and response claims are separated and reported according to available evidence. Items marked *pending validation* are not presented as completed capabilities.

## Objectives

- Centralize endpoint and network security telemetry.
- Investigate Windows process and authentication activity using Sysmon, Windows Security logs, and Wazuh.
- Ingest network security telemetry from Suricata.
- Validate detections with controlled lab scenarios.
- Map observed behavior to MITRE ATT&CK where supported.
- Document triage, investigation findings, evidence, and response decisions.
- Maintain sanitized, reproducible lab documentation.

## Lab components

| Component | Role |
|---|---|
| Wazuh | SIEM, endpoint monitoring, alerting, correlation, and investigation |
| Active Directory | Windows domain identity and policy environment |
| DC01 | Domain controller and Windows telemetry endpoint |
| PC01 | Windows endpoint and controlled detection testing |
| Sysmon | Windows process and system activity telemetry |
| Suricata | Network threat detection and EVE JSON telemetry |
| Atomic Red Team | Controlled adversary-technique simulation |
| MITRE ATT&CK | Technique classification and reporting framework |

The lab uses an isolated private network. Host addresses and account names in the documentation are lab-only examples; sensitive values and credentials must never be committed.

## Documented investigations

### INC-001 — PowerShell encoded command execution

A controlled Atomic Red Team T1059.001 Test 17 was executed locally on PC01. Wazuh generated built-in rule **92057** (Level 12), supported by Sysmon Event ID 1.

- **Detection:** Observed.
- **Response:** No containment is claimed.
- [Incident report](incidents/INC-001-PowerShell-Encoded-Command/incident-report.md)

### INC-002 — Repeated Windows network logon failures

Wazuh correlated five Windows Security Event ID 4625 failures from source 192.168.50.40 against PC01. Custom rule **110503** (Level 10) matched the configured five-event / 120-second threshold.

- **Assessment:** Possible brute force; the observed failures do not establish successful authentication or compromise.
- [Incident report](incidents/INC-002-SMB-Brute-Force/incident-report.md)

### INC-003 — PostgreSQL port scan

Suricata generated the PostgreSQL port-scan signature, Wazuh rule **110501** matched the event, and correlation rule **110502** (Level 10) correlated three same-source events within 60 seconds.

- **Assessment:** Repeated service probing detected; successful database access or compromise is not established.
- [Incident report](incidents/INC-003-PostgreSQL-Port-Scan/incident-report.md)

## Detection coverage

The [Detection Coverage Matrix](docs/detection-coverage-matrix.md) is the evidence-based baseline. It identifies custom rules, parent-rule dependencies, incident mappings, response evidence, and items still pending technical validation.

## Active Response

The [Active Response documentation](active-response/README.md) separates manager-side Linux execution evidence from Windows endpoint firewall-state observations. Windows firewall rules were observed present and later absent on DC01 and PC01; exact endpoint execution attribution remains separately identified as an evidence limitation.

## Repository map

| Path | Purpose |
|---|---|
| `docs/` | Architecture, topology, lab environment, and detection coverage |
| `incidents/` | Incident reports, evidence manifests, and supporting artifacts |
| `active-response/` | Response scripts, sanitized configuration, validation notes, and evidence manifest |
| `reports/` | Test results and project validation register |

## Evidence and safety

- Screenshots should show relevant alert/event fields and be redacted before publication.
- Exported logs and configuration files must be reviewed for usernames, hostnames, internal addresses, tokens, passwords, API keys, and other sensitive information.
- Never publish credentials, private keys, authentication tokens, Slack webhook URLs, or unredacted raw logs.
- A detection is marked runtime evidenced only when corresponding alert/event evidence is available.
- Built-in Wazuh rules are identified as built-in; they are not represented as custom rules.
- A detection alert does not by itself prove compromise.
- An Active Response configuration does not by itself prove endpoint containment.

## Current status

- [x] INC-001 encoded PowerShell detection documented.
- [x] INC-002 Windows failed-logon correlation documented.
- [x] INC-003 PostgreSQL scan detection and correlation documented.
- [x] Evidence-based Detection Coverage Matrix published.
- [x] Linux Active Response ADD / DELETE lifecycle observed.
- [x] Windows firewall block state and subsequent removal observed on DC01 and PC01.
- [ ] Validate custom rule 100421 against its installed parent rule and event data.
- [ ] Obtain independent runtime evidence for custom rule 110504.
- [ ] Validate HTTP URL field matching for rules 110510 and 110520.
- [ ] Review and assign a justified ATT&CK mapping for rule 110520.
- [ ] Record installed parent-rule definitions and `wazuh-analysisd -t` output.
- [ ] Complete Windows Active Response execution attribution with endpoint logs.

## Author

**Mohammed Alaa Mokhtar**  
GitHub: [@MohammedAlaa74](https://github.com/MohammedAlaa74)

---

*This repository is a learning and portfolio project. All security testing is performed in an authorized, isolated lab environment.*


### Additional evidence reviewed (2026-11-05)

Four screenshots were reviewed for INC-002 and Active Response: Wazuh rule 110503 Discover results, Windows Firewall before/after queries, and Ubuntu ADD/DELETE logs. Their original filenames and evidence descriptions are recorded in [the test results register](reports/test-results.md) and [the Detection Coverage Matrix](docs/detection-coverage-matrix.md). The screenshot binaries are intentionally left for the repository owner to upload. See [Final Project Review](reports/project-final-review.md) for the final evidence inventory, repository structure, and outstanding technical validation items.


## Final project review

See [reports/project-final-review.md](reports/project-final-review.md) for the consolidated review, evidence boundaries, and screenshot upload checklist.
