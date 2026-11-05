# SOC Home Lab — Final Project Review

**Review date:** 2026-11-05

## Executive assessment

The repository documents three evidence-backed detection investigations and a separate Active Response implementation.

| Incident | Detection path | Evidence-backed result | Limitation |
|---|---|---|---|
| INC-001 — Encoded PowerShell | Sysmon Event ID 1 → Wazuh built-in rule 92057, Level 12 | Controlled Atomic Red Team T1059.001 Test 17 observed on PC01 / agent 002. | No containment is claimed. |
| INC-002 — Repeated network logon failures | Windows Security Event ID 4625 → parent 60122 → custom rule 110503, Level 10 | Correlation alert observed. The Nov 5 Discover screenshot shows three indexed hits, including visible records from DC01 / agent 001 and PC01 / agent 002. | Failed logons do not establish successful authentication or compromise. |
| INC-003 — PostgreSQL port scan | Suricata SID 2010939 → Wazuh 110501 → correlation 110502 | Three same-source events correlated within 60 seconds. | Suricata action was allowed; no successful database access or containment is established. |

## Custom detection coverage

| Rule | Intended detection | Final disposition |
|---|---|---|
| 100421 | AD enumeration via net.exe; parent 92031; T1087.002 | XML observed; installed parent compatibility and matching runtime event remain unverified. |
| 110501 | Suricata PostgreSQL scan; parent 86601; T1046 | Runtime evidenced in INC-003. |
| 110502 | Three 110501 events / 60 seconds / same src_ip; T1046 | Runtime evidenced in INC-003. |
| 110503 | Five failed logons / 120 seconds / same source; T1110 | Runtime evidenced in INC-002. |
| 110504 | Password spraying; Logon Type 3; five distinct target accounts / 120 seconds; T1110.003 | XML observed; no independent 110504 alert is recorded. |
| 110510 | SQL injection URL pattern; parent 86602; T1190 | XML observed; actual event-field match and runtime alert remain unverified. |
| 110520 | XSS URL pattern; parent 86602 | XML observed; actual event-field match and runtime alert remain unverified. T1189 is not accepted as a generic XSS mapping. |

## Active Response evidence

### Linux manager

The supplied manager log records ADD/BLOCKED and DELETE/UNBLOCKED for 192.168.50.40. On 2026-11-05:
- 19:04:23.372201 to 19:14:24.942738: approximately 601.57 seconds.
- 19:16:13.850047 to 19:26:14.440197: approximately 600.59 seconds.

This supports the manager-side script lifecycle and approximately 600-second timeout behavior. Earlier lab evidence also showed the IPv4 DROP entry while active. Script logs and firewall-table state are separate evidence items.

### Windows endpoints

PowerShell captures show inbound and outbound BLOCK rules for 192.168.50.40 in an earlier query and no matching rules in a later query. The lab owner identified the two endpoint observations as DC01 and PC01.

These captures support endpoint firewall-state before/after observations. They do not independently identify the Wazuh alert or executable responsible for each change. Add endpoint response logs if exact execution attribution is required.

## Parent-rule and engine validation

The following checks were not present in the reviewed material:
- Installed parent-rule definitions 92031, 86601, 86602, and 60122.
- Actual output of `sudo /var/ossec/bin/wazuh-analysisd -t`.

The custom XML proves that the rules are present in the supplied configuration. It does not prove that the active analysis engine accepts the complete configuration or that every parent emits the fields expected by its child.

## Repository structure

| Path | Purpose |
|---|---|
| README.md | Project overview, incident summaries, status and safety notes |
| docs/ | Architecture, lab environment, topology and detection coverage |
| incidents/ | Three incident reports and supporting evidence |
| active-response/configuration/ | Sanitized manager and Windows response configuration |
| active-response/scripts/ | Custom Linux response script |
| active-response/docs/ | Response validation and test plan |
| active-response/evidence-manifest.csv | Response evidence inventory |
| reports/test-results.md | Consolidated scenario and response evidence |
| reports/project-final-review.md | This final review |

## Owner screenshot upload checklist

The four reviewed screenshots are intentionally left for the repository owner to upload.

| Suggested path | Content |
|---|---|
| active-response/evidence/AR-05-wazuh-rule-110503.png | Discover query for rule 110503; three hits and visible 4625 records. |
| active-response/evidence/AR-06-windows-firewall-endpoint-1.png | Inbound/outbound BLOCK rules present, then absent. Caption the correct endpoint. |
| active-response/evidence/AR-07-windows-firewall-endpoint-2.png | Inbound/outbound BLOCK rules present, then absent. Caption the correct endpoint. |
| active-response/evidence/AR-08-linux-active-response-lifecycle.png | Ubuntu ADD/BLOCKED and DELETE/UNBLOCKED log entries. |

Use exact endpoint names from the original captures. Redact credentials, tokens, webhook URLs, and unrelated personal paths.

## Remaining technical items

1. Record installed parent-rule definitions and the real `wazuh-analysisd -t` result.
2. Validate 100421 against the installed parent and a matching Windows command-line event.
3. Obtain a runtime alert for 110504 before claiming password-spraying detection is validated.
4. Verify the actual Suricata event field and matching alert for 110510 and 110520.
5. Add Windows endpoint response logs if exact Wazuh-to-Windows execution attribution is required.
6. Upload the four screenshots and update the evidence manifest with the actual committed paths.

No new attack tests are required to document the three existing incidents. Do not mark the open technical checks as passed without evidence.

## Final statement

The repository documentation and incident evidence are organized and ready for screenshot upload. The project must not be described as having 100% validated detection coverage until the outstanding technical checks above are supported by evidence. Never publish the full live ossec.conf, secrets, private keys, or unredacted raw logs.
