# SOC Home Lab — Detection & Incident Response

A hands-on Security Operations Center (SOC) lab focused on endpoint and network telemetry, SIEM alert triage, detection correlation, incident investigation, evidence handling, and controlled Active Response.

> **Portfolio baseline:** This repository presents only detections supported by recorded runtime evidence. Detection claims and response evidence are documented separately.

## Project objectives

- Centralize endpoint and network security telemetry.
- Investigate Windows process and authentication activity using Sysmon, Windows Security logs, and Wazuh.
- Ingest network telemetry from Suricata.
- Correlate security events and investigate alerts.
- Map observed behavior to MITRE ATT&CK where supported.
- Document incident timelines, evidence, assessment, and response decisions.
- Demonstrate controlled Linux and Windows firewall response behavior.

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

The lab uses an isolated private network. Host addresses and account names in the documentation are lab-only examples. Credentials and secrets must never be committed.

## Confirmed investigations

### INC-001 — Encoded PowerShell execution

A controlled Atomic Red Team T1059.001 Test 17 was executed locally on PC01. Sysmon Event ID 1 and built-in Wazuh rule **92057** (Level 12) recorded the activity.

- **Detection:** Runtime evidenced.
- **Response:** No containment is claimed.
- [Incident report](incidents/INC-001-PowerShell-Encoded-Command/incident-report.md)

### INC-002 — Windows network logon failures / possible brute force

On 2026-11-01, five Windows Security Event ID 4625 failures from `192.168.50.40` (`KALI-ATTACKER`) were recorded against PC01 (agent 002) within approximately 13 seconds. Custom Wazuh rule **110503** (Level 10) correlated five failures from the same source within its configured 120-second window.

- **Logon type:** 3 (Network); the evidence does not independently establish SMB as the protocol.
- **Target account:** `soc_invalid_user`; SubStatus `0xc0000064` indicates an unknown user name.
- **Assessment:** Possible brute-force activity / repeated failed network authentication. Successful authentication, valid-account password guessing, and compromise are not established.
- [Incident report](incidents/INC-002-SMB-Brute-Force/incident-report.md)

### INC-003 — PostgreSQL port scan

Suricata generated the PostgreSQL port-scan signature. Custom Wazuh rule **110501** matched the event, and correlation rule **110502** (Level 10) correlated three same-source events within 60 seconds.

- **Assessment:** Repeated service probing detected. Successful database access or compromise is not established.
- [Incident report](incidents/INC-003-PostgreSQL-Port-Scan/incident-report.md)

## Detection coverage

The [Detection Coverage Matrix](docs/detection-coverage-matrix.md) is the portfolio baseline. It includes the three custom rules with runtime evidence (110501, 110502, and 110503) and the built-in Wazuh rule 92057 used in INC-001.

## Active Response

The [Active Response documentation](active-response/README.md) records the Linux manager-side ADD/DELETE lifecycle and the Windows endpoint firewall-state observations separately.

- Linux manager: ADD/BLOCKED and DELETE/UNBLOCKED lifecycle observed for the test source.
- Linux firewall: matching DROP state observed while active.
- DC01 and PC01: inbound/outbound Windows Firewall block rules observed present and later absent.
- Exact Wazuh-to-Windows endpoint execution attribution is not claimed without endpoint-side execution logs.

## Repository structure

| Path | Purpose |
|---|---|
| `docs/` | Architecture, lab environment, network topology, and confirmed detection coverage |
| `incidents/` | Three incident reports, event records, rule artifacts, screenshots, and evidence manifests |
| `active-response/` | Response script, sanitized configuration, validation notes, and evidence manifest |
| `reports/` | Consolidated test results and final project review |

## Evidence and safety

- Screenshots and logs should be redacted before publication.
- Never publish credentials, private keys, authentication tokens, Slack webhook URLs, or unredacted sensitive logs.
- A detection is described as runtime evidenced only when a corresponding alert/event and supporting evidence are available.
- Built-in Wazuh rules are identified as built-in, not custom.
- An alert does not by itself prove compromise.
- Active Response configuration does not by itself prove containment.
- Linux manager logs, Linux firewall state, and Windows endpoint firewall state are separate evidence sources.

## Project status

- [x] INC-001 encoded PowerShell detection documented.
- [x] INC-002 Windows network logon failures / possible-brute-force detection documented with five-event correlation evidence.
- [x] INC-003 PostgreSQL scan detection and correlation documented.
- [x] Evidence-based Detection Coverage Matrix limited to runtime-evidenced detections.
- [x] Linux Active Response ADD / DELETE lifecycle observed.
- [x] Linux firewall DROP state observed while active.
- [x] Windows firewall block state and later removal observed on DC01 and PC01.
- [x] Incident reports, evidence manifests, and repository navigation organized.
- [ ] Upload the four reviewed November 5 screenshots to the paths listed in [the final review](reports/project-final-review.md).

## Author

**Mohammed Alaa Mokhtar**  
GitHub: [@MohammedAlaa74](https://github.com/MohammedAlaa74)

---

*This repository is a learning and portfolio project. All security testing is performed in an authorized, isolated lab environment.*
