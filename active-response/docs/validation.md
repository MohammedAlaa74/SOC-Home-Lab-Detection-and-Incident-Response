# Active Response Validation

## Scope and verdict

This record distinguishes manager-side script execution, Linux firewall state, and Windows endpoint firewall state. These evidence types are not interchangeable.

## Linux manager-side execution

The supplied `/var/ossec/logs/active-responses.log` excerpts show this lifecycle for source `192.168.50.40`:

- `RECEIVED: command='add'`
- `SOURCE: 192.168.50.40`
- `BLOCKED: 192.168.50.40`
- `RECEIVED: command='delete'`
- `SOURCE: 192.168.50.40`
- `UNBLOCKED: 192.168.50.40`

On 2026-11-05, observed add-to-delete intervals were approximately 601.57 seconds (19:04:23.372201–19:14:24.942738) and 600.59 seconds (19:16:13.850047–19:26:14.440197). This supports the manager script ADD/DELETE lifecycle and approximately 600-second timeout behavior.

Earlier lab evidence showed the IPv4 DROP rule for `192.168.50.40` while active. Keep the log excerpt and firewall-table observation as distinct evidence items.

## Windows firewall-state observations

The supplied PowerShell captures show inbound and outbound BLOCK rules for `192.168.50.40` in an earlier query and no matching rule in a later query. The lab owner identified the endpoint captures as DC01 and PC01.

This supports firewall-state observations before and after the response window. It does not, by itself, attribute each change to a specific Wazuh alert or executable. Endpoint-side Active Response logs are required for that stronger claim.

## Configuration and implementation notes

- Manager-side command: `soc-firewall-drop` / `soc-firewall-drop.py`.
- Rules configured for Linux manager response: 110502 and 110503.
- Timeout: 600 seconds.
- Windows `netsh` dispatch declarations are stored separately in `configuration/windows-netsh-config.xml`.
- A `netsh.exe` missing message on the Linux manager is about its local executable inventory; it does not establish Windows endpoint failure.
- The recorded deployed script SHA-256 is `951374b7dc8c4471769c9c619d6fbbe8a7941fc07009777381911a29b0807b91`. Re-hash the host file and compare it to the repository source before claiming byte-for-byte identity.

## Script review observations

- The script uses the Wazuh 4.x `add` / `delete` protocol and `check_keys` handshake.
- Recursive IP extraction should be narrowed to known source-IP fields before use outside the isolated lab.
- The firewall comment `WAZUH_AR_110502` is used for both rule 110502 and rule 110503. Consider a neutral comment in a separately tested revision; do not change the deployed script without validation.

## Final evidence status

| Evidence | Status |
|---|---|
| Manager ADD/BLOCKED and DELETE/UNBLOCKED logs | Observed |
| Approximately 600-second manager lifecycle | Observed |
| Linux IPv4 DROP state while active | Previously observed in lab |
| Windows firewall BLOCK state and later removal | Observed on DC01 and PC01 per endpoint identification |
| Exact Windows Wazuh-to-executable attribution | Not independently established |
| Deployed script hash matches repository source | Not independently established |

## Screenshot upload

The four 2026-11-05 screenshots are to be uploaded by the repository owner. Suggested paths and captions are documented in `reports/project-final-review.md`. After upload, update `evidence-manifest.csv` to reference the actual committed paths.

Never commit the full `ossec.conf`, Slack webhook URLs, tokens, passwords, private keys, or unredacted raw logs.
