# INC-003 — PostgreSQL Port Scan

> **Status:** Detection and correlation evidenced; screenshots pending  
> **Detection:** Suricata → Wazuh  
> **Rules:** 110501 (single-event detection), 110502 (3 events / 60 seconds, same source IP)  
> **MITRE ATT&CK:** T1046 — Network Service Discovery

## Objective

Document repeated network traffic matching the Suricata ET SCAN signature for PostgreSQL port 5432, and preserve the corresponding Suricata events and Wazuh detection/correlation alerts.

## Evidence currently committed

- `logs/suricata-event.json` — valid JSON array containing four sanitized Suricata EVE alert events.
- `logs/wazuh-alert-110501.json` — sanitized Wazuh level-8 detection alert.
- `logs/wazuh-correlation-110502.json` — sanitized Wazuh level-10 correlation alert, with two prior events in `previous_output`.
- `rules/110501.xml` and `rules/110502.xml` — rule definitions supplied for this lab.

Private lab IPs were replaced with RFC 5737 documentation addresses in public JSON evidence. Original timestamps, source ports, destination port, protocol, flow IDs, signature metadata, and flow counters are retained.

## Key finding

The Wazuh correlation alert contains three matching events from the same source IP within approximately 3.44 seconds, satisfying the configured 3-event / 60-second condition. The standalone Suricata event export contains four matching alert records in total; the fourth is a separate event and is not counted as one of the three entries shown in that correlation alert's `previous_output`.

## Important scope

The Suricata events record action `allowed`. This is not evidence of blocking. The shown flow counters report no client-bound packets, but this does not independently prove that the destination service was unavailable.

A scan alert does not prove successful PostgreSQL access, authentication, exploitation, or compromise. The `active_response_trigger` group label does not by itself execute an active response.

## Remaining work

- [ ] Upload four screenshots and visually review them.
- [ ] Verify screenshots correspond to the committed JSON events.
- [ ] If containment is claimed, add active-response logs and independent firewall/host-state evidence.
- [ ] Confirm the deployed manager XML matches the committed rule files.

## Folder layout

- `incident-report.md` — analysis and incident narrative.
- `evidence-manifest.csv` — evidence inventory.
- `logs/` — sanitized Suricata and Wazuh events.
- `rules/` — Wazuh rule definitions.
