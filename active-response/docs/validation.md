# Active Response Validation

## Script identity

The lab manager reported this SHA-256 for
`/var/ossec/active-response/bin/soc-firewall-drop.py`:

```text
951374b7dc8c4471769c9c619d6fbbe8a7941fc07009777381911a29b0807b91
```

The full source file has not yet been committed. The repository must not contain a reconstructed or guessed replacement. Copy the actual manager-side file into `active-response/scripts/`, then verify this hash before committing it.

## Linux manager-side evidence

The supplied `/var/ossec/logs/active-responses.log` excerpts show repeated sequences for source `192.168.50.40`:

- `RECEIVED: command='add'`
- `SOURCE: 192.168.50.40`
- `BLOCKED: 192.168.50.40`
- `RECEIVED: command='delete'`
- `SOURCE: 192.168.50.40`
- `UNBLOCKED: 192.168.50.40`

This supports execution of the custom script and its logging path. For a stronger firewall-state claim, capture `iptables -S INPUT` (and/or `ip6tables -S INPUT`) while blocked and after timeout, filtering for the script's unique comment.

## Windows endpoint status

The Wazuh manager configuration contains `netsh` response entries for DC01 (agent 001), PC01 (agent 002), and a local response for rule 110503.

The manager log also reports `active-response command not present: active-response/bin/netsh.exe` on the Linux manager. That message is expected for a Windows executable unavailable on Linux; it does not prove that the Windows agent failed to execute its own response.

Windows containment remains **not verified** until the endpoint-side `active-responses.log` and Windows Firewall before/after state are captured. Do not describe manager dispatch as successful endpoint blocking.
