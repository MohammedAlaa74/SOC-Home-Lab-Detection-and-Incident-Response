# Test Results Register

This register tracks scenarios by evidence state. A scenario is not considered fully documented until its test execution, detection output, and supporting evidence are attached.

| Scenario | Test reference | Endpoint | Observed detection | Status |
|---|---|---|---|---|
| Encoded PowerShell | Atomic Red Team T1059.001 Test 17 | PC01 / 192.168.50.20 | Wazuh rule 92057, Level 12; Sysmon Event ID 1 | Detection observed; screenshots/log exports pending |
| PowerShell fileless execution | Atomic Red Team T1059.001 Test 10 | PC01 planned | Not confirmed in this register | Pending validation |
| Local account creation | Atomic Red Team T1136.001 Test 5 | PC01 planned | Event ID 4720 was not observed; User Account Management auditing was reported as disabled | Pending re-test / audit-policy validation |

## Reporting rules

- Keep pending scenarios clearly marked as pending.
- Do not infer detection from a test command alone.
- Record exact rule IDs, event IDs, timestamps, agent IDs, and ATT&CK mappings from actual output.
- Do not claim containment unless the endpoint or network control result is independently verified.
