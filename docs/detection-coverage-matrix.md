# Detection Coverage Matrix

**Version:** 1.0  
**Baseline date:** 2026-11-05  
**Status:** Baseline published; four custom detections remain pending technical validation.

This matrix separates detection evidence from response evidence. A rule's presence in XML is configuration evidence, not proof of runtime detection.

## 1. Custom detection coverage

| Rule ID | Detection | Parent / source | Level | ATT&CK | Evidence status | Notes |
|---|---|---|---:|---|---|---|
| 100421 | Active Directory account/group enumeration via net.exe | Parent 92031; Windows command-line telemetry | 8 | T1087.002 | Configured; pending validation | Confirm parent-rule compatibility and observed commandLine field. |
| 110501 | Suricata PostgreSQL port-scan signature | Parent 86601; Suricata EVE JSON | 8 | T1046 | Runtime evidenced — INC-003 | Signature: ET SCAN Suspicious inbound to PostgreSQL port 5432. |
| 110502 | Correlated PostgreSQL scan | 110501; 3 events / 60 seconds / same src_ip | 10 | T1046 | Runtime evidenced — INC-003 | Correlation alert and previous_output establish three matching events. |
| 110503 | Windows failed network logon correlation | Parent 60122; 5 events / 120 seconds / same ipAddress | 10 | T1110 | Runtime evidenced — INC-002 | Five Event ID 4625 failures correlated; do not infer successful compromise. |
| 110504 | Password spraying correlation | Parent 60122; Logon Type 3; 5 events / 120 seconds / same source and different target accounts | 12 | T1110.003 | Configured; pending validation | No independent runtime alert evidence is recorded in the reviewed incident set. |
| 110510 | Possible SQL injection pattern in HTTP URL | Parent 86602; http.url | 8 | T1190 | Configured; pending validation | Confirm actual decoded event field and a matching alert before marking validated. |
| 110520 | Possible XSS pattern in HTTP URL | Parent 86602; http.url | 8 | Not assigned | Configured; pending validation | Existing T1189 mapping is not accepted as a generic XSS mapping; review before assigning ATT&CK. |

## 2. Incident-to-detection mapping

| Incident | Observed behavior | Detection | Evidence-backed conclusion |
|---|---|---|---|
| INC-001 | Encoded PowerShell execution on PC01 | Built-in Wazuh rule 92057, Level 12; Sysmon Event ID 1 | Local controlled execution was detected. This is not one of the custom rules above. |
| INC-002 | Repeated Windows network logon failures from 192.168.50.40 | Parent 60122 → custom rule 110503, Level 10 | Five failed logons were correlated within the configured 120-second window. |
| INC-003 | Repeated Suricata PostgreSQL port-scan alerts | Parent 86601 → 110501 → 110502, Levels 8 and 10 | Three same-source events were correlated within 60 seconds. |

## 3. Active Response coverage — kept separate from detection

| Trigger / path | Execution location | Observed evidence | Status |
|---|---|---|---|
| 110502 / 110503 | Ubuntu Wazuh Manager, `soc-firewall-drop` | Manager log shows ADD/BLOCKED and DELETE/UNBLOCKED for 192.168.50.40. On 2026-11-05, ADD at 19:04:23 and DELETE at 19:14:24 are approximately 600 seconds apart. | Lifecycle observed; 600-second cycle evidenced. |
| Windows firewall response | DC01 | Inbound and outbound block rules for 192.168.50.40 were present, then absent on a later check. | Endpoint firewall state lifecycle observed. |
| Windows firewall response | PC01 | Inbound and outbound block rules for 192.168.50.40 were present, then absent on a later check. | Endpoint firewall state lifecycle observed. |
| Windows response attribution | DC01 / PC01 | The supplied evidence does not include endpoint Active Response execution logs tying each firewall change to a specific Wazuh rule and executable. | Attribution not independently established. |

The Ubuntu manager log proves manager-side script activity. The Windows before/after firewall queries prove endpoint firewall state at the times observed. These are separate evidence sources; do not treat either as proof of the other's execution.

## 4. Parent-rule and configuration verification

The current host configuration supplied for review shows these dependencies:

- `100421` depends on parent `92031`.
- `110501` depends on parent `86601`.
- `110510` and `110520` depend on parent `86602`.
- `110503` and `110504` depend on parent `60122`.

The exact installed parent-rule definitions and the output of `/var/ossec/bin/wazuh-analysisd -t` have not yet been supplied for this review. Therefore, parent-rule compatibility and analysis-engine configuration validation remain open. Do not mark these checks as passed based only on the custom XML.

## 5. Validation status definitions

- **Runtime evidenced:** A matching Wazuh alert/event and supporting incident evidence are recorded.
- **Configured; pending validation:** The custom XML rule exists, but runtime detection evidence or required technical verification is missing.
- **Lifecycle observed:** ADD and DELETE activity or corresponding endpoint firewall states were observed.
- **Attribution not independently established:** Endpoint state is observed, but the precise Wazuh trigger/executable association is not demonstrated by endpoint execution logs.

## 6. Open actions

1. Obtain and review the installed definitions for parent rules 92031, 86601, 86602, and 60122.
2. Record the actual output of `sudo /var/ossec/bin/wazuh-analysisd -t`.
3. Validate rule 100421 against a real decoded Windows command-line event.
4. Obtain an independent 110504 password-spraying alert before marking it runtime evidenced.
5. Validate the actual `http.url` field and matching behavior for 110510 and 110520.
6. Correct or leave unassigned the ATT&CK mapping for 110520 until justified.
7. Add Windows endpoint response logs if exact Wazuh response attribution is required.

## 7. Evidence integrity

Only claims supported by the reviewed repository artifacts and supplied lab observations are marked evidenced. No successful compromise, database access, exploitation, or containment is inferred where the corresponding telemetry is absent.
