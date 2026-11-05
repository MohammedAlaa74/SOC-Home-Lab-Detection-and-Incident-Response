# Wazuh Active Response

This section documents the Active Response implementation and separates manager-side execution from endpoint firewall-state observations.

## Manager-side configuration

- Custom command: `soc-firewall-drop`
- Executable: `soc-firewall-drop.py`
- Execution location: Wazuh manager (`server`)
- Triggering rules: `110502` and `110503`
- Timeout: 600 seconds
- Recorded deployed-script SHA-256: `951374b7dc8c4471769c9c619d6fbbe8a7941fc07009777381911a29b0807b91`

The recorded hash is a host observation. The repository source has not been independently re-hashed against the deployed host binary in this review; do not claim byte-for-byte provenance until compared.

## Linux manager-side execution evidence

The supplied `/var/ossec/logs/active-responses.log` excerpts show `RECEIVED add`, `SOURCE`, `BLOCKED`, then `RECEIVED delete`, `SOURCE`, and `UNBLOCKED` for `192.168.50.40`.

Observed 2026-11-05 cycles:
- 19:04:23.372201 to 19:14:24.942738 — approximately 601.57 seconds.
- 19:16:13.850047 to 19:26:14.440197 — approximately 600.59 seconds.

These entries support the manager script lifecycle and approximately 600-second timeout behavior. Earlier lab evidence also showed the script-owned IPv4 DROP entry while active. The manager log demonstrates script lifecycle; firewall-table output demonstrates kernel rule state. Keep these as separate evidence records.

## Windows firewall-state observations

PowerShell captures show inbound and outbound BLOCK rules for `192.168.50.40` in an earlier query and no matching rule in a later query. The lab owner identified the two endpoint observations as DC01 and PC01.

This establishes endpoint firewall state at the observed times. It does not independently prove which Wazuh alert, response executable, or endpoint-side process created and removed each rule. Add endpoint-side Active Response logs if exact execution attribution is required.

## Dispatch configuration versus execution evidence

The sanitized manager configuration declares:
- `netsh` response for DC01 (agent 001) on rule 110502.
- `netsh` response for PC01 (agent 002) on rule 110502.
- Local `netsh` response for rules 110503 and 110504.

These are configuration declarations, not proof of successful execution. A Linux manager message that `netsh.exe` is unavailable refers to the manager's local executable inventory; it does not prove that the Windows agent failed.

## Script review notes

- The script implements the Wazuh 4.x `add` / `delete` protocol and `check_keys` handshake on `add`.
- `find_source()` recursively accepts generic IP field names. Before use beyond this isolated lab, constrain extraction to the exact source-IP fields in the relevant alert formats.
- The firewall comment is `WAZUH_AR_110502` even though the command is attached to both rules 110502 and 110503. This is semantically misleading, though not by itself proof of a functional failure. Change it only in a separately reviewed and validated script revision.
- Do not modify the deployed script solely for cosmetic cleanup.

## Repository contents

- `configuration/command-config.xml`: sanitized command declaration.
- `configuration/active-response-config.xml`: manager-side response blocks.
- `configuration/windows-netsh-config.xml`: sanitized Windows dispatch declarations.
- `docs/validation.md`: observed outcomes and limitations.
- `docs/test-plan.md`: repeatable validation checklist.
- `evidence-manifest.csv`: evidence inventory.

## Evidence still open

1. Upload the reviewed 2026-11-05 screenshots under `evidence/` and update the manifest with exact filenames.
2. Add endpoint Active Response execution logs if precise Windows dispatch attribution is needed.
3. Reconfirm deployed-script SHA-256 against the repository source if provenance is claimed.

Never commit the full `ossec.conf`, Slack webhook URLs, tokens, passwords, private keys, or unredacted raw logs.
