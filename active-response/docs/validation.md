# Active Response Validation

## Script identity

The complete custom script is committed at
[`scripts/soc-firewall-drop.py`](../scripts/soc-firewall-drop.py).

The Wazuh manager reported this SHA-256 for the deployed file
`/var/ossec/active-response/bin/soc-firewall-drop.py`:

```text
951374b7dc8c4471769c9c619d6fbbe8a7941fc07009777381911a29b0807b91
```

The repository copy was committed from the source supplied for review. The host hash is recorded as observed, but byte-for-byte identity must be reconfirmed by running `sha256sum` on the deployed host file and comparing it with a locally downloaded repository copy.

## Linux manager-side evidence

The supplied `/var/ossec/logs/active-responses.log` excerpts show repeated sequences for source `192.168.50.40`:

- `RECEIVED: command='add'`
- `SOURCE: 192.168.50.40`
- `BLOCKED: 192.168.50.40`
- `RECEIVED: command='delete'`
- `SOURCE: 192.168.50.40`
- `UNBLOCKED: 192.168.50.40`

This supports execution of the custom script and its logging path. It does not, by itself, prove the kernel firewall state. Capture the matching rule while blocked and confirm its absence after timeout using:

```bash
sudo iptables -S INPUT | grep 'WAZUH_AR_110502'
sudo ip6tables -S INPUT | grep 'WAZUH_AR_110502'
```

An empty result after timeout is expected. During the block, the IPv4 rule for `192.168.50.40` should be visible in the appropriate table.

## Stateful response protocol

The script accepts the Wazuh 4.x `add` / `delete` command values. On `add`, it sends a newline-terminated `check_keys` control message and proceeds only when execd replies with `continue`. The observed `abort` log entries are deduplication responses; the script correctly avoids applying the same response twice while a previous response is pending.

The script extracts candidate IP values recursively. Before using it beyond this isolated lab, narrow extraction to the exact source-IP field(s) present in the alert formats for rules 110502 and 110503. Generic nested fields such as `ipAddress` can otherwise match an unrelated address in a more complex alert.

The firewall comment is currently `WAZUH_AR_110502` for both rules 110502 and 110503. This is operationally functional but semantically misleading for the brute-force rule. Consider a neutral comment such as `WAZUH_AR_SOC_FIREWALL_DROP` in a separately tested script revision; do not change the deployed script without validating add, deduplication, and delete behavior.

## Windows endpoint status

The manager configuration defines `netsh` response entries for DC01 (agent 001), PC01 (agent 002), and a local response for rule 110503. These declarations show intended dispatch configuration, not successful Windows Firewall containment.

The manager log reports `active-response command not present: active-response/bin/netsh.exe` on the Linux manager. This message concerns the Linux manager's local executable inventory; it does not prove that the Windows agent failed. The supplied PC01 agent log excerpt contains a `netsh.exe` delete message, which supports that a delete task reached the PC01 agent. It is not sufficient to prove that the firewall rule was added or removed successfully.

Windows containment remains **not verified** until both PC01 and DC01 provide endpoint-side add/delete logs and Windows Firewall before/during/after state evidence.

## Evidence still required

1. Linux `iptables` state while blocked and after timeout.
2. PC01 endpoint active-response log showing add and delete.
3. PC01 Windows Firewall rule while blocked and after timeout.
4. DC01 endpoint active-response log showing add and delete, if that response is intentionally retained.
5. DC01 Windows Firewall rule while blocked and after timeout.

Never commit the full `ossec.conf`, Slack webhook URLs, tokens, passwords, private keys, or unredacted raw logs.
