# SOC Lab Architecture

## Data flow

1. Windows endpoint activity is generated on monitored lab systems.
2. Sysmon records endpoint process and system events on PC01.
3. Wazuh agent forwards collected telemetry to the Wazuh manager.
4. Wazuh analyzes events with built-in and, where verified, custom detection rules.
5. The analyst reviews alerts, correlates process and host context, and documents the investigation.
6. Incident reports record the evidence, ATT&CK mapping, disposition, and any response action that is actually supported by evidence.

Suricata is part of the lab's network-detection stack. Specific network detections should be documented only when the corresponding test output and alert evidence are attached.

## Architecture principles

- Evidence-first reporting: do not claim a detection or response outcome without supporting telemetry.
- Separation of detection and response: an alert does not prove containment.
- Least exposure: redact sensitive values before publishing.
- Reproducibility: record test identifier, endpoint, timestamp, rule ID, and relevant event fields.
- Clear provenance: distinguish built-in Wazuh rules from custom rules authored for the lab.

## Known validated path

The INC-001 test demonstrated the following path:

`Atomic Red Team T1059.001 Test 17 → PowerShell process execution on PC01 → Sysmon Event ID 1 → Wazuh agent 002 → Wazuh rule 92057 (Level 12) → analyst investigation`

This is a controlled lab validation. It is not evidence of a production incident.
