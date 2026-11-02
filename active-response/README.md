# Wazuh Active Response

This section documents the Active Response implementation in the SOC home lab.

## Confirmed manager-side configuration

- Custom command: `soc-firewall-drop`
- Executable: `soc-firewall-drop.py`
- Manager-side location: `server`
- Triggering rules: `110502` and `110503`
- Timeout: 600 seconds
- Script SHA256 observed on the manager: `951374b7dc8c4471769c9c619d6fbbe8a7941fc07009777381911a29b0807b91`

## Lab-side observations

The manager's `active-responses.log` excerpts supplied during development show successful `add` / `BLOCKED` and `delete` / `UNBLOCKED` log sequences for source `192.168.50.40`.

This confirms the manager-side script flow was logged. For a stronger firewall-state claim, retain corresponding `iptables` / `ip6tables` inspection output captured while the block was active and after deletion.

## Windows response status

The manager configuration also defines `netsh` response entries for DC01 (agent 001), PC01 (agent 002), and local response for rule 110503. These are configuration entries, not proof that Windows Firewall was changed. Windows endpoint logs and before/after firewall-rule evidence are still required.

## Files

- `configuration/command-config.xml`: sanitized command declaration.
- `configuration/active-response-config.xml`: manager-side response blocks.
- `configuration/windows-netsh-config.xml`: Windows dispatch declarations.
- `docs/validation.md`: observed results and limitations.
- `docs/test-plan.md`: repeatable evidence checklist.
- `evidence-manifest.csv`: pending evidence inventory.

The complete Python script is intentionally not included in this commit because only its SHA256 and a partial code excerpt have been supplied in this conversation. Add the full file from the lab manager after review and hash verification.
