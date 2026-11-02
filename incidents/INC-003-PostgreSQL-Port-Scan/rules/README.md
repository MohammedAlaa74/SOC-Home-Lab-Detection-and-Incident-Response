# Wazuh rule configuration

The following XML files were added from the rule definitions supplied for this lab:

- `110501.xml` — Suricata PostgreSQL scan detection, level 8.
- `110502.xml` — correlation rule, level 10; frequency 3 within 60 seconds, requiring the same dynamic `src_ip` field.

## Validation still required

These files represent the supplied configuration. They are **not yet proof that the rules are loaded or have fired successfully**.

Before marking them validated:
1. Confirm these exact rules are present in the active Wazuh manager configuration.
2. Confirm rule 86601 is the parent rule that matches the Suricata event in this environment.
3. Confirm the decoded alert contains `alert.signature`, `src_ip`, and `dest_ip` with the expected names and values.
4. Run Wazuh log testing with a representative Suricata event.
5. Generate at least three matching events from the same `src_ip` within 60 seconds and verify rule 110502.
6. Check the manager logs and `alerts.json` for actual rule matches.

## Important implementation note

The `same_field` condition works with a dynamic field. It must use the exact decoded field name. If the Suricata decoder exposes the source address under a different name (for example, a nested JSON field), adjust the rule only after inspecting the actual decoded event. Do not assume `src_ip` is correct without checking the event.

Rule 110502 carries the `active_response_trigger` group label. That label alone does **not** execute an active response. A matching active-response command and configuration must exist separately, and containment must be verified independently.
