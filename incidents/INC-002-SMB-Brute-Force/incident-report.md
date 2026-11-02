# INC-002 — Repeated Network Logon Failures / Possible Brute Force

## Summary
Wazuh correlated five Windows Security Event ID 4625 failures from source `192.168.50.40` against target `PC01` within approximately 13 seconds. The custom correlation rule `110503` fired at Level 10 using a configured threshold of five matching failures within 120 seconds.

## Observed evidence
- **Target endpoint:** PC01 (Wazuh agent 002, `192.168.50.20`)
- **Source:** `192.168.50.40` (`KALI-ATTACKER`)
- **Event:** Windows Security 4625 — failed logon
- **Logon type:** 3 — Network
- **Target account:** `soc_invalid_user`
- **Authentication:** NTLM / `NtLmSsp`
- **Status:** `0xc000006d`
- **SubStatus:** `0xc0000064` (unknown user name)
- **Detection:** Wazuh rule `110503`, Level 10, frequency 5, timeframe 120 seconds
- **MITRE ATT&CK mapping:** T1110 — Brute Force (Credential Access)

## Correlation logic
Rule `110503` matches events from rule `60122`, groups by `win.eventdata.ipAddress`, and triggers after five matching events within 120 seconds. The supplied Wazuh alert records the correlation and includes the five-event frequency requirement.

## Assessment
The evidence supports repeated failed network authentication attempts and a Wazuh possible-brute-force detection. Because the observed account is an unknown username (`0xc0000064`), this evidence alone does not establish password guessing against a valid account or a successful compromise. The label remains **Possible Brute Force**, not confirmed compromise.

## Evidence files
- `correlation-alert-110503.json` — sanitized Wazuh correlation alert.
- `rule-110503.xml` — detection rule configuration.
- Screenshots will be added directly to this incident folder (no separate screenshots directory):
  - `Screenshot_01_Failed_Logons.png`
  - `Screenshot_02_Event_Details.png`
  - `Screenshot_03_Correlation_110503.png`
  - `Screenshot_04_Account_Context.png`

## Current status
Detection evidence and rule configuration are committed. Screenshot evidence and account-context evidence remain pending user upload. No claim of successful authentication or endpoint compromise is made.