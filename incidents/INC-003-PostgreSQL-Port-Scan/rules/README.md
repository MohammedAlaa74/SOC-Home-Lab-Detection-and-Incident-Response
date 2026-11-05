# Confirmed Wazuh rule artifacts

The XML files in this directory are the custom detection rules evidenced in INC-003:

- `110501.xml` — Suricata PostgreSQL port-scan detection, Level 8, matching the PostgreSQL signature from the Suricata event.
- `110502.xml` — correlation rule, Level 10; three matching events within 60 seconds, grouped by the same dynamic `src_ip`.

## Runtime evidence

- INC-003 includes the Suricata event, Wazuh alert for rule 110501, and correlation alert for rule 110502.
- The correlation alert's `previous_output` contains two prior matching events in addition to the current event.
- The three events share the same source address and fall within the configured 60-second window.
- This is runtime evidence that the documented Suricata event path exposed the fields required by these two rules.

## Scope

These rule artifacts and incident records demonstrate detection and correlation. They do not demonstrate successful PostgreSQL access, exploitation, compromise, or firewall containment.

The `active_response_trigger` group label on rule 110502 does not itself execute an Active Response command. Response configuration and execution evidence are documented separately under [Active Response](../../../active-response/README.md).
