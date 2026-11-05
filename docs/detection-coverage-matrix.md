# Detection Coverage Matrix

**Version:** 1.1  
**Baseline date:** 2026-11-05  
**Scope:** Only detections with runtime evidence retained in this baseline.

This matrix records confirmed detection coverage from the committed incident evidence. Active Response is documented separately and is not treated as proof of detection.

## 1. Confirmed detection coverage

| Rule ID | Detection | Source / parent | Level | ATT&CK | Evidence | Result |
|---|---|---|---:|---|---|---|
| 92057 | Encoded PowerShell execution | Sysmon Event ID 1; built-in Wazuh rule | 12 | T1059.001 | INC-001: Wazuh alert and Sysmon process-creation event | Runtime evidenced — built-in rule |
| 110501 | Suricata PostgreSQL port-scan signature | Parent 86601; Suricata EVE JSON | 8 | T1046 | INC-003: Suricata event and Wazuh alert | Runtime evidenced — custom rule |
| 110502 | Correlated PostgreSQL scan | 110501; 3 events / 60 seconds / same `src_ip` | 10 | T1046 | INC-003: correlation alert with two prior matching events and current event | Runtime evidenced — custom rule |
| 110503 | Windows network logon failures / possible brute force | Parent 60122; 5 Windows Event ID 4625 failures / 120 seconds / same source IP | 10 | T1110 | INC-002: 5 matching failures in 13 seconds; PC01 agent 002; source 192.168.50.40 | Runtime evidenced — custom rule |

### INC-002 analyst qualification

Rule 110503 detects repeated failed **network logons**. The observed Windows Logon Type is 3, which identifies a network logon but does not, by itself, establish SMB as the transport/protocol. The target account was `soc_invalid_user`; SubStatus `0xc0000064` indicates an unknown user name. Therefore the defensible finding is **possible brute-force activity / repeated failed network authentication**, not confirmed password guessing against a valid account or confirmed compromise.

## 2. Coverage boundary

- Rule 92057 is a built-in Wazuh rule. It is not represented as a custom rule.
- Rules 110501, 110502, and 110503 are the custom detections retained in this portfolio baseline because runtime evidence is available.
- This baseline intentionally excludes custom rules without sufficient runtime evidence. Their omission from this portfolio does not imply that they were removed from the live Wazuh manager configuration.
- No detection alert alone proves successful compromise.

## 3. Incident-to-detection mapping

| Incident | Observed behavior | Detection path | Evidence-backed conclusion |
|---|---|---|---|
| INC-001 | Controlled encoded PowerShell execution on PC01 | Sysmon Event ID 1 → built-in Wazuh 92057 | Controlled local execution was detected. No containment is claimed. |
| INC-002 | Five failed Windows network logons from 192.168.50.40 against PC01, targeting `soc_invalid_user` | Windows Security 4625 → parent 60122 → custom 110503 | Five failures were correlated in approximately 13 seconds. Possible brute-force activity is supported; valid-account password guessing, SMB-specific activity, and compromise are not established. |
| INC-003 | Repeated Suricata alerts for PostgreSQL TCP/5432 probing | Suricata → custom 110501 → correlation 110502 | Three same-source events were correlated within 60 seconds. Successful database access or compromise is not established. |

## 4. Active Response — separate from detection

| Component | Execution / observation | Evidence | Status |
|---|---|---|---|
| Linux manager | `soc-firewall-drop` ADD/BLOCKED and DELETE/UNBLOCKED for 192.168.50.40 | Manager active-response log; two observed cycles on 2026-11-05 of approximately 601.57 and 600.59 seconds | Manager-side lifecycle evidenced |
| Linux firewall | Script-owned IPv4 DROP entry observed while active | Earlier lab firewall-table output | Active firewall state observed |
| DC01 | Inbound and outbound Windows Firewall BLOCK rules present, then absent on a later query | Supplied PowerShell capture | Endpoint firewall-state transition observed |
| PC01 | Inbound and outbound Windows Firewall BLOCK rules present, then absent on a later query | Supplied PowerShell capture | Endpoint firewall-state transition observed |

The manager log demonstrates Linux script lifecycle. The firewall-table output demonstrates Linux firewall state. Windows PowerShell output demonstrates endpoint firewall state. These evidence types are distinct.

The Windows captures do not independently identify the exact Wazuh alert or endpoint process responsible for each firewall change. Do not claim exact Wazuh-to-Windows execution attribution without endpoint-side Active Response logs.

## 5. Configuration and validation notes

- The confirmed custom detection artifacts are stored with INC-002 and INC-003.
- Runtime evidence confirms that the relevant event path and correlation rules fired in the documented incidents.
- The repository does not include the complete live `ossec.conf` or a complete export of all installed Wazuh parent rules.
- The actual `wazuh-analysisd -t` output was not included in the reviewed evidence set. This does not negate the recorded runtime alerts, but it means a separate full-configuration syntax-validation result is not archived here.

## 6. Evidence integrity

- **Runtime evidenced** means a matching Wazuh alert/event and supporting incident evidence are recorded.
- **Lifecycle evidenced** means ADD/DELETE activity or corresponding firewall-state transitions were observed.
- **Attribution not established** means endpoint state is visible but the exact response process/trigger is not independently tied to it.
- No successful compromise, database access, exploitation, or containment is inferred without the corresponding telemetry.
