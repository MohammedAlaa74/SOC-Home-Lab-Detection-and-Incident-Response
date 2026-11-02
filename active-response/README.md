# Wazuh Active Response

This section documents the Active Response implementation in the SOC home lab. It separates manager-side execution evidence from endpoint-side containment claims.

## Confirmed manager-side configuration

- Custom command: `soc-firewall-drop`
- Executable: `soc-firewall-drop.py`
- Manager-side location: `server`
- Triggering rules: `110502` and `110503`
- Timeout: 600 seconds
- Script SHA256 observed on the manager: `951374b7dc8c4471769c9c619d6fbbe8a7941fc07009777381911a29b0807b91`

## Lab-side observations

The manager's `active-responses.log` excerpts show repeated `add` / `BLOCKED` and `delete` / `UNBLOCKED` log sequences for source `192.168.50.40`.

This supports the manager-side script execution and logging path. Firewall-state evidence from `iptables` / `ip6tables` during and after the timeout is still needed to independently verify kernel firewall state.

## Windows response status

The manager configuration defines `netsh` response entries for DC01 (agent 001), PC01 (agent 002), and a local response for rule 110503. These are dispatch declarations, not proof that Windows Firewall was changed.

The Linux manager logs include notices that `netsh.exe` is not present on the Linux manager. This is expected for a Windows executable on Linux and does not establish endpoint success or failure. Windows endpoint-side logs and before/after firewall-rule evidence are still required.

## Script source review

- `scripts/soc-firewall-drop.py` is now committed from the complete source pasted for review.
- The manager SHA256 recorded from the host remains `951374b7dc8c4471769c9c619d6fbbe8a7941fc07009777381911a29b0807b91`. The pasted chat text was not byte-for-byte hashed against the host file, so this repository commit must not be represented as cryptographically verified to match that host hash until `sha256sum` is checked again on the host.
- The script implements the Wazuh 4.x `add` / `delete` protocol and the `check_keys` handshake on `add`. Wazuh documentation confirms this handshake is required for stateful timeout/reversal.
- Review note: `find_source()` recursively accepts several generic IP field names, including `ipAddress`; before production use, narrow extraction to the actual Wazuh alert source-IP fields used by rules 110502/110503 so a destination or unrelated nested IP cannot be selected accidentally.
- Review note: `COMMENT` is fixed to `WAZUH_AR_110502` although the command is attached to both rules 110502 and 110503. This is not itself a failure, but the comment should be renamed to a neutral identifier (for example `WAZUH_AR_SOC_FIREWALL_DROP`) if you want firewall-state evidence to clearly identify blocks from both triggers.

## Repository contents

- `configuration/command-config.xml`: sanitized command declaration.
- `configuration/active-response-config.xml`: manager-side response blocks for rules 110502 and 110503.
- `configuration/windows-netsh-config.xml`: sanitized Windows dispatch declarations.
- `docs/validation.md`: observed results, script hash, and limitations.
- `docs/test-plan.md`: repeatable validation checklist.
- `evidence-manifest.csv`: evidence inventory and status.

## Remaining items

1. Re-run `sha256sum /var/ossec/active-response/bin/soc-firewall-drop.py` on the manager and compare it with the recorded hash above; then compare the deployed file with the committed source if byte-for-byte provenance is required.
2. Add Linux firewall-state evidence while blocked and after timeout.
3. Add PC01 and DC01 endpoint-side response logs and Windows Firewall before/after evidence.
4. Review screenshots and mark manifest entries PASS only when their contents support the claim.

Never commit the full `ossec.conf`, Slack webhook URLs, tokens, passwords, private keys, or unredacted raw logs.
