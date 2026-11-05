# SOC Home Lab — Final Project Review

**Review date:** 2026-11-05

## Executive assessment

The portfolio is organized around three documented incidents, a confirmed detection baseline, and a separate Active Response evidence set. Only detections with runtime evidence are included in the coverage matrix.

## Confirmed detection coverage

| Incident | Detection path | Evidence-backed result | Limitation |
|---|---|---|---|
| INC-001 — Encoded PowerShell | Sysmon Event ID 1 → built-in Wazuh rule 92057, Level 12 | Controlled Atomic Red Team T1059.001 Test 17 observed on PC01 / agent 002. | No containment is claimed. |
| INC-002 — Repeated network logon failures | Windows Security Event ID 4625 → parent 60122 → custom rule 110503, Level 10 | Correlation alert and supporting Windows event evidence recorded. | Failed logons do not establish successful authentication or compromise. |
| INC-003 — PostgreSQL port scan | Suricata SID 2010939 → Wazuh 110501 → correlation 110502 | Three same-source events correlated within 60 seconds. | Suricata action was allowed; no successful database access or containment is established. |

The custom detection baseline contains only rules 110501, 110502, and 110503 because runtime evidence is recorded for those rules. Built-in rule 92057 is documented separately and is not counted as a custom rule.

## Active Response evidence

### Linux manager

The supplied manager log records ADD/BLOCKED and DELETE/UNBLOCKED for 192.168.50.40. On 2026-11-05:
- 19:04:23.372201 to 19:14:24.942738: approximately 601.57 seconds.
- 19:16:13.850047 to 19:26:14.440197: approximately 600.59 seconds.

This supports the manager-side script lifecycle and approximately 600-second timeout behavior. Earlier lab evidence also showed the IPv4 DROP entry while active. Script logs and firewall-table state are separate evidence items.

### Windows endpoints

PowerShell captures show inbound and outbound BLOCK rules for 192.168.50.40 in an earlier query and no matching rules in a later query. The endpoint captures cover DC01 and PC01.

These captures support endpoint firewall-state before/after observations. They do not independently identify the Wazuh alert or executable responsible for each change. Exact Wazuh-to-Windows execution attribution is not claimed.

## Repository structure

| Path | Purpose |
|---|---|
| `README.md` | Project overview, confirmed incident summaries, status, and navigation |
| `docs/` | Architecture, lab environment, topology, and confirmed Detection Coverage Matrix |
| `incidents/` | Three incident reports and supporting evidence |
| `active-response/configuration/` | Sanitized manager and Windows response configuration |
| `active-response/scripts/` | Custom Linux response script |
| `active-response/docs/` | Response validation and test plan |
| `active-response/evidence-manifest.csv` | Response evidence inventory |
| `reports/test-results.md` | Consolidated scenario and response evidence |
| `reports/project-final-review.md` | This review |

## Screenshot upload checklist

The four reviewed November 5 screenshots are intentionally left for the repository owner to upload.

| Suggested path | Content |
|---|---|
| `active-response/evidence/AR-09-wazuh-rule-110503.png` | Discover query for rule 110503; three hits and visible Event ID 4625 records. |
| `active-response/evidence/AR-10-windows-firewall-endpoint-1.png` | Inbound/outbound BLOCK rules present, then absent. Use the correct endpoint label from the capture. |
| `active-response/evidence/AR-11-windows-firewall-endpoint-2.png` | Inbound/outbound BLOCK rules present, then absent. Use the correct endpoint label from the capture. |
| `active-response/evidence/AR-12-linux-active-response-lifecycle.png` | Ubuntu ADD/BLOCKED and DELETE/UNBLOCKED log entries. |

Redact credentials, tokens, webhook URLs, and unrelated personal paths before upload. Update the evidence manifest with the actual committed paths after upload.

## Validation boundary

- Runtime evidence is recorded for the three incidents and the four detections shown in the matrix (including built-in 92057).
- Linux Active Response ADD/DELETE lifecycle and Linux firewall DROP state were observed.
- Windows firewall block state and later removal were observed on DC01 and PC01.
- Endpoint-side Windows Active Response execution attribution is not established by the supplied PowerShell state queries.
- The actual `wazuh-analysisd -t` output was not included in the reviewed evidence set. The repository therefore does not claim that a separate full-configuration syntax-validation result is archived.

No new attack tests are required to document the existing evidence. Never publish the full live `ossec.conf`, secrets, private keys, or unredacted raw logs.

## Final statement

The GitHub portfolio now focuses on the three documented incidents and the detections that have runtime evidence. Unvalidated custom-rule entries are excluded from the published coverage baseline; their omission here does not modify the live Wazuh manager configuration.
