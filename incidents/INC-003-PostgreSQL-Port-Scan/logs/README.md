# Log evidence

Place sanitized exports in this directory.

Expected files:
- `suricata-event.json`
- `wazuh-alert-110501.json`
- `wazuh-alert-110502.json` (only if rule 110502 fired)

## Export guidance

1. Export the complete relevant Suricata event from `eve.json`.
2. Export the complete matching Wazuh alert object for rule 110501.
3. Export the correlation alert for rule 110502 only if it exists.
4. Preserve timestamps, source/destination IPs, ports, protocol, signature/SID, rule IDs, and agent metadata.
5. Before committing, sanitize any credentials, tokens, public IPs, personal usernames, or sensitive internal naming.

Do not create synthetic alerts to fill a missing evidence slot. If a rule did not fire, state that in the report and manifest.
