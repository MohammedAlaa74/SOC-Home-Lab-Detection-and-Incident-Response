# INC-002 — Windows Network Logon Failures / Possible Brute Force

## Executive summary

On 2026-11-01, Wazuh correlated five failed Windows network logons (Security Event ID 4625) on **PC01** from the same source, `192.168.50.40` (`KALI-ATTACKER`). The five events occurred over approximately **13 seconds**, within the custom rule's configured **120-second** correlation window.

Custom Wazuh rule **110503** generated a **Level 10** alert. The alert is evidence of repeated failed network authentication and supports a **possible brute-force activity** classification. It does **not** prove a successful login, account compromise, or password guessing against a valid account.

## Incident classification

| Field | Value |
|---|---|
| Incident ID | INC-002 |
| Classification | Credential Access — possible brute-force activity |
| Affected endpoint | PC01 — `PC01.soclab.local` |
| Wazuh agent | PC01 / ID `002` / `192.168.50.20` |
| Source | `192.168.50.40` — `KALI-ATTACKER` |
| Windows event | Security Event ID `4625` — failed logon |
| Logon type | `3` — Network |
| Target account | `soc_invalid_user` |
| Authentication package | NTLM |
| Logon process | `NtLmSsp` |
| Status | `0xc000006d` — logon failure |
| SubStatus | `0xc0000064` — user name does not exist |
| Source port in representative event | `47074` |
| Detection rule | Wazuh custom rule `110503`, Level `10` |
| Correlation threshold | 5 events / 120 seconds / same `win.eventdata.ipAddress` |
| ATT&CK | T1110 — Brute Force |

## Timeline

All timestamps below are local time (UTC+02:00), unless explicitly marked UTC.

| Time | Event |
|---|---|
| 2026-11-01 16:16:27–16:16:40 | Five failed network logons recorded on PC01; Windows Event Record IDs span `82848–82856`. |
| 2026-11-01 16:16:40.133 | Representative final event, Record ID `82856`, recorded by Windows Security. |
| 2026-11-01 16:16:40.237 | Wazuh correlation alert `110503` generated on agent PC01 / `002`. |

The representative Windows event time is `2026-11-01T14:16:40.1331925Z` (UTC). The Wazuh alert time is `2026-11-01T16:16:40.237+0200`.

## Detection logic and validation evidence

Rule `110503` uses:
- Parent rule: `60122` (Windows failed-logon event path).
- `frequency="5"` and `timeframe="120"`.
- `same_field=win.eventdata.ipAddress`.
- Level `10`.
- MITRE technique `T1110`.

The committed correlation alert records:
- `matching_failed_logons: 5`.
- `observed_window_seconds: 13`.
- `configured_window_seconds: 120`.
- `same_source_ip: true`.
- Source `192.168.50.40`, target PC01 / agent `002`.

This is runtime evidence that the 110503 correlation rule fired for the documented event sequence. The rule artifact and sanitized alert are retained alongside this report.

## Analyst assessment

**What the evidence establishes**
1. PC01 recorded five failed network logons from one source IP.
2. The attempts targeted the account name `soc_invalid_user`.
3. Wazuh correlated the failures and generated rule `110503`.
4. The Windows status/substatus indicate a failed logon involving an unknown user name.

**What the evidence does not establish**
1. It does not prove a valid account was targeted; the observed username was reported as unknown.
2. It does not prove password guessing against a valid account.
3. It does not prove a successful authentication, lateral movement, or endpoint compromise.
4. Logon Type 3 means network logon; the supplied evidence does not independently prove that the traffic was specifically SMB. The historical folder name contains “SMB”, but the incident finding is deliberately described as **Windows network logon failures**.
5. It does not, by itself, prove Active Response execution or containment on the endpoint.

**Disposition:** Detection confirmed; malicious intent and compromise not confirmed. Retain as a controlled possible-brute-force detection case, not a confirmed account compromise.

## Active Response separation

Active Response firewall evidence is documented in the repository's separate Active Response section. Do not use firewall-state observations as proof that rule `110503` caused a specific endpoint response unless the matching endpoint-side response execution log is available.

## Evidence files

- `correlation-alert-110503.json` — sanitized Wazuh correlation alert, including agent, rule, event, and correlation metadata.
- `rule-110503.xml` — deployed custom correlation-rule artifact.
- `evidence-manifest.csv` — evidence inventory.
- Six committed screenshots:
  - `Screenshot 2026-11-01 204738.png`
  - `Screenshot 2026-11-02 133023.png`
  - `Screenshot 2026-11-02 133438.png`
  - `Screenshot 2026-11-02 133701.png`
  - `Screenshot 2026-11-02 134051.png`
  - `Screenshot 2026-11-02 134106.png`

The screenshot binaries are committed. Their exact one-to-one mapping to event details, failed-logon views, correlation, and account context remains unclassified in the manifest; no screenshot-specific claim is made until that mapping is visually confirmed.

## Final status

- **Detection:** Runtime evidenced — rule `110503` fired.
- **Incident interpretation:** Possible brute-force activity / repeated failed network authentication.
- **Compromise:** Not established.
- **SMB-specific attribution:** Not established.
- **Active Response attribution to this alert:** Not established by the incident evidence supplied.
