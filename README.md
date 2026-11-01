# SOC Home Lab — Detection & Incident Response

A hands-on Security Operations Center (SOC) lab focused on endpoint telemetry, SIEM alert triage, threat investigation, detection validation, and incident documentation.

> **Project status:** Active development. The repository documents only scenarios that have been tested and supported by collected evidence. Items marked *planned* or *pending validation* are not presented as completed capabilities.

## Objectives

- Centralize endpoint and network security telemetry.
- Investigate suspicious Windows process activity using Sysmon and Wazuh.
- Validate detections with controlled Atomic Red Team simulations.
- Map observed behavior to MITRE ATT&CK.
- Document triage, investigation findings, evidence, and response decisions.
- Maintain sanitized, reproducible lab documentation.

## Lab components

| Component | Role |
|---|---|
| Wazuh | SIEM, endpoint monitoring, alerting, and investigation |
| Active Directory | Windows domain identity and policy environment |
| Windows endpoint (PC01) | Endpoint telemetry and controlled detection testing |
| Sysmon | Windows process and system activity telemetry |
| Suricata | Network threat detection (coverage documented as validated) |
| Atomic Red Team | Controlled adversary-technique simulation |
| MITRE ATT&CK | Technique classification and reporting framework |

The lab uses an isolated private network. Host addresses and account names in the documentation are lab-only examples; sensitive values and credentials must never be committed.

## Validated investigation

### INC-001 — PowerShell encoded command execution

A controlled Atomic Red Team test (T1059.001, PowerShell) was executed on PC01. Wazuh generated alert **92057** (Level **12**) for encoded PowerShell command execution. The alert was associated with Wazuh agent **002** at **192.168.50.20** and Sysmon **Event ID 1**.

- **Execution context:** local endpoint execution; no remote source IP is applicable.
- **MITRE ATT&CK:** T1059.001 — PowerShell.
- **Detection source:** Wazuh rule 92057.
- **Response status:** investigation evidence documented; containment is not claimed for this scenario.

See [INC-001 incident report](incidents/INC-001-PowerShell-Encoded-Command/incident-report.md).

## Repository map

| Path | Purpose |
|---|---|
| `docs/` | Architecture, topology, and lab environment |
| `incidents/` | Incident reports and evidence manifests |
| `detections/` | Sanitized detection rules and telemetry configuration |
| `evidence/screenshots/` | Redacted screenshots grouped by incident |
| `evidence/sanitized-logs/` | Sanitized supporting event data |
| `reports/` | Test results and detection coverage |

## Evidence and safety

- Screenshots should show the relevant alert/event fields and be redacted before publication.
- Exported logs and configuration files must be reviewed for usernames, hostnames, internal addresses, tokens, passwords, API keys, and other sensitive information.
- Never publish credentials, private keys, authentication tokens, or unredacted production data.
- A detection is marked validated only when the corresponding test result and supporting evidence are available.
- Built-in Wazuh rules are identified as built-in; they are not represented as custom rules.

## Current status

- [x] Wazuh alert observed for encoded PowerShell execution (INC-001).
- [x] Initial incident report and evidence manifest created.
- [ ] Add redacted screenshots PS-01 through PS-04.
- [ ] Add sanitized raw event excerpts for INC-001.
- [ ] Document remaining scenarios only after their tests and evidence are verified.
- [ ] Add reviewed custom rules and active-response configuration, if applicable.
- [ ] Complete architecture diagram and detection coverage matrix.

## Author

**Mohammed Alaa Mokhtar**  
GitHub: [@MohammedAlaa74](https://github.com/MohammedAlaa74)

---

*This repository is a learning and portfolio project. All security testing is performed in an authorized, isolated lab environment.*
