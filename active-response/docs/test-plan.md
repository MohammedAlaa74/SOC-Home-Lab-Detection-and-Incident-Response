# Active Response Test Plan

Run only in the isolated, authorized home lab. Use the test source IP `192.168.50.40`; never target the Wazuh manager or protected/allowlisted lab assets.

| ID | Test | Expected evidence | Status |
|---|---|---|---|
| AR-LNX-01 | Trigger rule 110502 | Manager active-response log records add and source IP | Observed in supplied logs |
| AR-LNX-02 | Inspect manager firewall during timeout | Matching DROP rule with the script's unique comment | Pending firewall-state screenshot/output |
| AR-LNX-03 | Wait for 600-second timeout | Manager active-response log records delete | Observed in supplied logs |
| AR-LNX-04 | Inspect manager firewall after timeout | Matching DROP rule is absent | Pending firewall-state screenshot/output |
| AR-WIN-01 | Trigger Windows response | Endpoint active-response log records execution | Not verified |
| AR-WIN-02 | Inspect Windows Firewall during block | Matching inbound block rule exists on intended endpoint | Not verified |
| AR-WIN-03 | Wait for timeout | Endpoint log records delete and firewall rule is removed | Not verified |

## Acceptance criteria

1. The alert contains the intended rule ID and source IP.
2. The source IP is not in the configured whitelist.
3. The Linux response adds only the rule owned by this script.
4. The timeout/delete operation removes only the matching script-owned rule.
5. Windows tests are marked PASS only with endpoint-side logs and firewall-state evidence.
6. Retain timestamps, rule IDs, agent IDs, and source/destination context in screenshots.
