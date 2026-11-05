# SOC Home Lab — Final Project Review

**Review date:** 2026-11-05  
**Review perspective:** SOC Team Lead — detection quality, incident analysis, evidence integrity, response attribution, and portfolio readiness.

## Executive assessment

The portfolio contains three documented incidents, a runtime-evidenced detection baseline, and a separate Active Response evidence set. INC-002 (Windows network logon failures / possible brute force) is retained as a core incident and has been reviewed to distinguish actual telemetry from assumptions that the evidence does not support.

## Confirmed detection coverage

| Incident | Detection path | Evidence-backed result | Limitation |
|---|---|---|---|
| INC-001 — Encoded PowerShell | Sysmon Event ID 1 → built-in Wazuh rule 92057, Level 12 | Controlled Atomic Red Team T1059.001 Test 17 observed on PC01 / agent 002. | No containment is claimed. |
| INC-002 — Possible brute force | Windows Security Event ID 4625 → parent 60122 → custom rule 110503, Level 10 | Five same-source failed network logons correlated in approximately 13 seconds on PC01 / agent 002. | Target account was an unknown user; valid-account password guessing, SMB-specific activity, and compromise are not established. |
| INC-003 — PostgreSQL port scan | Suricata SID 2010939 → Wazuh 110501 → correlation 110502 | Three same-source events correlated within 60 seconds. | Suricata action was allowed; no successful database access or containment is established. |

The custom detection baseline contains rules 110501, 110502, and 110503 because runtime evidence is recorded for those rules. Built-in rule 92057 is documented separately and is not counted as a custom rule.

## SOC Team Lead review — INC-002

### Evidence reviewed

- Sanitized Wazuh correlation alert for rule `110503`.
- Rule artifact `rule-110503.xml`.
- Incident report and evidence manifest.
- Recorded Windows Security event details and Wazuh agent identity.

### Confirmed facts

- Endpoint: PC01 / Wazuh agent `002` / `192.168.50.20`.
- Source: `192.168.50.40` / `KALI-ATTACKER`.
- Five Windows Security Event ID `4625` failures were correlated within approximately 13 seconds.
- The events occurred inside the configured 120-second threshold.
- Logon Type `3` = Network.
- Target account: `soc_invalid_user`.
- Authentication: NTLM / `NtLmSsp`.
- Representative event: Record ID `82856`, source port `47074`.
- Status `0xc000006d`; SubStatus `0xc0000064` (unknown user name).
- Wazuh rule `110503`, Level `10`, frequency `5`, timeframe `120`, same field `win.eventdata.ipAddress`, MITRE `T1110`.

### Timeline

The five Windows events span approximately 2026-11-01 16:16:27–16:16:40 (UTC+02:00). The representative final Windows event occurred at 16:16:40.133 local time; Wazuh generated the correlation alert at 16:16:40.237 local time.

### Team Lead assessment

- **Detection verdict: PASS — runtime evidenced.** The parent-to-correlation path generated the documented 110503 alert after the configured same-source threshold was reached.
- **Incident classification: Possible brute-force activity / repeated failed network authentication.** The target username was unknown according to SubStatus `0xc0000064`. The evidence does not establish password guessing against a valid account.
- **Protocol attribution: SMB NOT ESTABLISHED.** Logon Type 3 identifies a network logon, not the application protocol. The historical directory name includes SMB, but the incident report and portfolio summary use the more accurate Windows network logon description.
- **Compromise verdict: NOT ESTABLISHED.** There is no evidence in this incident package of a successful authentication or post-authentication activity.
- **Response verdict: NOT ATTRIBUTED.** Firewall-state evidence elsewhere in the repository must not be attributed to this 110503 alert without matching endpoint-side Active Response execution evidence.

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
| `incidents/INC-001-PowerShell-Encoded-Command/` | PowerShell incident evidence and report |
| `incidents/INC-002-SMB-Brute-Force/` | Windows network logon / possible brute-force incident evidence and report (historical folder name retained) |
| `incidents/INC-003-PostgreSQL-Port-Scan/` | PostgreSQL scan incident evidence and rules |
| `active-response/` | Response scripts, sanitized configuration, validation notes, and evidence manifest |
| `reports/test-results.md` | Consolidated scenario and response evidence |
| `reports/project-final-review.md` | This review |

## Screenshot status

INC-002 has six screenshot binaries committed in its incident folder. Their exact semantic mapping remains pending visual classification in the incident evidence manifest. The separate November 5 Active Response screenshots are intentionally left for the repository owner to upload; suggested paths are recorded in the existing evidence manifest.

## Validation boundary

- Runtime evidence is recorded for the three incidents and four detections shown in the matrix (including built-in 92057).
- Linux Active Response ADD/DELETE lifecycle and Linux firewall DROP state were observed.
- Windows firewall block state and later removal were observed on DC01 and PC01.
- Endpoint-side Windows Active Response execution attribution is not established by the supplied PowerShell state queries.
- The actual `wazuh-analysisd -t` output was not included in the reviewed evidence set. The repository therefore does not claim that a separate full-configuration syntax-validation result is archived.

No new attack tests are required to document the existing evidence. Never publish the full live `ossec.conf`, secrets, private keys, or unredacted raw logs.

## Final statement

The portfolio retains INC-002 as a confirmed **detection** of repeated failed network logons / possible brute-force activity. It does not overstate the evidence as SMB-specific activity, valid-account password guessing, successful compromise, or proven containment. Detection, incident interpretation, and response attribution remain distinct conclusions.
