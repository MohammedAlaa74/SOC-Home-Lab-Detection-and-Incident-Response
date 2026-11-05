# Test Results Register

This register records only the three documented incident scenarios with supporting event and alert evidence. Detection validation and Active Response validation are kept separate.

## Detection scenarios

| Scenario | Test / event reference | Endpoint / source | Observed detection | Status |
|---|---|---|---|---|
| Encoded PowerShell execution | Atomic Red Team T1059.001 Test 17; Sysmon Event ID 1 | PC01 / agent 002 | Built-in Wazuh rule 92057, Level 12 | Runtime evidenced — INC-001 |
| Repeated Windows network logon failures | Windows Security Event ID 4625; Logon Type 3 | PC01 / source 192.168.50.40 | Custom Wazuh rule 110503, Level 10; five failures within 120 seconds | Runtime evidenced — INC-002 |
| PostgreSQL port scan | Suricata ET SCAN signature SID 2010939 | Suricata sensor / TCP 5432 | Custom Wazuh rule 110501, followed by correlation rule 110502; three same-source events within 60 seconds | Runtime evidenced — INC-003 |

The published custom detection baseline is limited to rules 110501, 110502, and 110503. Built-in rule 92057 is listed separately and is not a custom rule.

## Active Response observations

| Component | Observation | Status |
|---|---|---|
| Ubuntu Manager | ADD/BLOCKED and DELETE/UNBLOCKED for 192.168.50.40; 2026-11-05 19:04:23 to 19:14:24 and 19:16:13 to 19:26:14 | Manager-side lifecycle observed; both intervals approximately 600 seconds |
| Linux firewall | Matching script-owned DROP entry observed while active | Firewall state observed |
| DC01 | Inbound and outbound firewall block rules for 192.168.50.40 present, then absent in a later query | Endpoint firewall-state transition observed |
| PC01 | Inbound and outbound firewall block rules for 192.168.50.40 present, then absent in a later query | Endpoint firewall-state transition observed |

The Windows firewall queries demonstrate endpoint state at the observation times. They do not, by themselves, identify the exact Wazuh alert, response command, or endpoint process that created and removed the rules.

## Additional evidence reviewed on 2026-11-05

| Screenshot | Observation | Evidence classification |
|---|---|---|
| `Screenshot 2026-11-05 192446.png` | Wazuh Discover search for `rule.id:"110503"` returns 3 hits; visible Windows Security 4625 events include DC01 agent 001 and PC01 agent 002. | Detection evidence for INC-002 / 110503. |
| `Screenshot 2026-11-05 193108.png` | Inbound and outbound Windows Firewall BLOCK rules for 192.168.50.40 are present in the first query and absent in the later query. | Endpoint firewall-state observation. |
| `Screenshot 2026-11-05 193133.png` | Inbound and outbound Windows Firewall BLOCK rules for 192.168.50.40 are present in the first query and absent in the later query. | Endpoint firewall-state observation. |
| `Screenshot 2026-11-05 193355.png` | Ubuntu manager log shows ADD/BLOCKED and DELETE/UNBLOCKED. PC01-associated sequence: 19:04:23 to 19:14:24; DC01-associated sequence: 19:16:13 to 19:26:14. | Linux manager-side Active Response lifecycle; intervals are approximately 600 seconds. |

The screenshot binaries are intentionally left for the repository owner to upload. The evidence inventory and suggested repository paths are documented in [project-final-review.md](project-final-review.md).

## Evidence handling

- Keep detection evidence separate from Active Response evidence.
- Record exact rule IDs, event IDs, timestamps, agent IDs, and source/destination context from actual output.
- Do not infer detection from a test command alone.
- Do not claim containment unless endpoint or network control results are independently verified.
- Do not infer successful compromise from failed authentication or scan alerts.
