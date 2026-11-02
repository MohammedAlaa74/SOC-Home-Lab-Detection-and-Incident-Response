# Log evidence

This directory contains reviewed, sanitized JSON evidence for INC-003.

## Files

- `suricata-event.json` — four Suricata EVE alert events matching the PostgreSQL port 5432 scan signature.
- `wazuh-alert-110501.json` — sanitized Wazuh level-8 single-event detection alert.
- `wazuh-correlation-110502.json` — sanitized Wazuh level-10 correlation alert, including two prior matching events in `previous_output`.

## Suricata event set

The four events are stored as one valid JSON array. Each retains its timestamp, flow ID, interface, source/destination ports, protocol, signature metadata, action, and flow counters.

Private lab IPs are replaced with RFC 5737 documentation addresses in the public repository:
- Source: `198.51.100.40`
- Destination: `203.0.113.20`

## Interpretation limits

- The recorded Suricata action is `allowed`; this file does not evidence packet blocking.
- The events support repeated probing matching the ET SCAN signature. They do not prove PostgreSQL authentication, successful access, exploitation, or compromise.
- Do not add synthetic events to fill evidence gaps.

## Review

Validate the JSON with `jq empty suricata-event.json` and compare timestamps and event fields with the related Wazuh alert records before using the evidence in a report.
