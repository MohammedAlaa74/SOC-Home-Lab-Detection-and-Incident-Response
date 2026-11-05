# Test Results Register

This register separates detection validation from response validation. A scenario is reported as evidenced only when its alert/event and supporting incident evidence are available.

## Detection scenarios

| Scenario | Test / event reference | Endpoint / source | Observed detection | Status |
|---|---|---|---|---|
| Encoded PowerShell execution | Atomic Red Team T1059.001 Test 17; Sysmon Event ID 1 | PC01 / agent 002 | Built-in Wazuh rule 92057, Level 12 | Detection evidenced — INC-001 |
| Repeated Windows network logon failures | Windows Security Event ID 4625; Logon Type 3 | PC01 / source 192.168.50.40 | Custom Wazuh rule 110503, Level 10; five failures within 120 seconds | Detection evidenced — INC-002 |
| PostgreSQL port scan | Suricata ET SCAN signature SID 2010939 | Suricata sensor / TCP 5432 | Custom Wazuh rule 110501, then correlation rule 110502; three same-source events within 60 seconds | Detection evidenced — INC-003 |

## Custom rules pending validation

| Rule ID | Detection | Missing evidence / verification |
|---|---|---|
| 100421 | AD enumeration via net.exe | Verify parent 92031 and matching Windows commandLine event |
| 110504 | Password spraying | Independent alert showing different target accounts from same source |
| 110510 | SQL injection pattern | Confirm actual Suricata `http.url` field and matching alert |
| 110520 | XSS pattern | Confirm actual Suricata `http.url` field, matching alert, and ATT&CK mapping review |

## Active Response observations

| Component | Observation | Status |
|---|---|---|
| Ubuntu Manager | ADD/BLOCKED and DELETE/UNBLOCKED for 192.168.50.40; 2026-11-05 19:04:23 to 19:14:24 | Lifecycle observed; approximately 600 seconds |
| DC01 | Inbound and outbound firewall block rules for 192.168.50.40 present, then absent in a later query | Endpoint firewall-state lifecycle observed |
| PC01 | Inbound and outbound firewall block rules for 192.168.50.40 present, then absent in a later query | Endpoint firewall-state lifecycle observed |

The Windows firewall queries demonstrate endpoint state at the observation times. They do not, by themselves, identify the exact Wazuh alert, response command, or endpoint process that created and removed the rules.

## Engine and parent-rule checks still required

- Record the installed definitions of parent rules 92031, 86601, 86602, and 60122.
- Record the actual output of `sudo /var/ossec/bin/wazuh-analysisd -t`.
- Do not infer successful configuration validation from the presence of custom XML alone.

## Reporting rules

- Keep pending scenarios clearly marked as pending.
- Do not infer detection from a test command alone.
- Record exact rule IDs, event IDs, timestamps, agent IDs, and ATT&CK mappings from actual output.
- Do not claim containment unless endpoint or network control results are independently verified.
- Keep detection evidence and Active Response evidence in separate records.


## Additional evidence reviewed on 2026-11-05

| Screenshot | Observation | Evidence classification |
|---|---|---|
| `Screenshot 2026-11-05 192446.png` | Wazuh Discover search for `rule.id:"110503"` returns 3 hits; visible Windows Security 4625 events include DC01 agent 001 and PC01 agent 002. | Detection evidence for INC-002 / 110503. |
| `Screenshot 2026-11-05 193108.png` | Inbound and outbound Windows Firewall BLOCK rules for 192.168.50.40 are present in the first query and absent in the later query. | Endpoint firewall-state observation. |
| `Screenshot 2026-11-05 193133.png` | Inbound and outbound Windows Firewall BLOCK rules for 192.168.50.40 are present in the first query and absent in the later query. | Endpoint firewall-state observation. |
| `Screenshot 2026-11-05 193355.png` | Ubuntu manager log shows ADD/BLOCKED and DELETE/UNBLOCKED. PC01-associated sequence: 19:04:23 to 19:14:24; DC01-associated sequence: 19:16:13 to 19:26:14. | Linux manager-side Active Response lifecycle; intervals are approximately 600 seconds. |

**Repository attachment status:** These four screenshot files were reviewed from the conversation but their binary files are not yet present in the Git repository. Do not treat the filenames in this register as repository image links.
