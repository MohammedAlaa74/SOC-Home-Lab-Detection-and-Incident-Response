# INC-001 — PowerShell Encoded Command Execution

## Incident summary

| Field | Value |
|---|---|
| Incident ID | INC-001 |
| Scenario | Encoded PowerShell command execution |
| Validation method | Atomic Red Team — T1059.001, Test 17 |
| Affected endpoint | PC01 |
| Wazuh agent | 002 |
| Endpoint address | 192.168.50.20 |
| User context observed | SOCLAB\\Administrator |
| Source IP | Not applicable — command executed locally on PC01 |
| Detection | Wazuh rule 92057 |
| Alert severity | Level 12 |
| Endpoint telemetry | Sysmon Event ID 1 |
| MITRE ATT&CK | T1059.001 — PowerShell |
| Status | Detection observed; investigation documentation in progress |

## Executive summary

A controlled Atomic Red Team test executed an encoded PowerShell command locally on PC01. Wazuh generated alert **92057** (Level **12**) describing PowerShell spawning a PowerShell process that executed a Base64-encoded command. The alert was associated with Wazuh agent 002 (PC01, 192.168.50.20) and Sysmon Process Creation telemetry (Event ID 1).

This is a lab validation event, not evidence of a real-world compromise. The test demonstrates that the endpoint telemetry and Wazuh detection path observed the encoded PowerShell behavior.

## Detection evidence

| Attribute | Observed value |
|---|---|
| Wazuh rule ID | 92057 |
| Rule level | 12 |
| Rule description | Powershell.exe spawned a powershell process which executed a base64 encoded command |
| Agent | PC01 / 002 |
| Agent IP | 192.168.50.20 |
| Sysmon Event ID | 1 |
| Child process | powershell.exe |
| Child PID | 1500 |
| Parent process | cmd.exe |
| Parent PID | 9032 |
| Child process SHA-256 | 9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3 |
| ATT&CK tactic | Execution |
| ATT&CK technique | T1059.001 |

The recorded event timestamp was approximately 2026-11-01 16:38 local time (Sysmon event time approximately 14:37:46 UTC). Confirm the exact timestamp from the original exported alert before using it in a formal timeline.

## Investigation workflow

1. Review the Wazuh alert and confirm rule ID, level, agent, and event timestamp.
2. Inspect Sysmon Event ID 1 for the process image, command line, user, process GUID, parent image, parent PID, and parent process GUID.
3. Correlate the parent and child process records using process GUID fields and timestamps.
4. Decode the Base64 command line in a safe analysis environment; do not execute the decoded content.
5. Compare the activity with the documented Atomic Red Team test execution window.
6. Record the affected host and user context. Because execution was local, do not assign a remote source IP.

## Assessment

The alert and Sysmon process-creation evidence support the conclusion that encoded PowerShell execution occurred on PC01 during the controlled test. The presence of an encoded command is suspicious behavior, but the test context is essential to classify this event as authorized simulation rather than malicious activity.

## Response decision

**Disposition:** Authorized security validation / benign lab simulation.

**Containment:** No containment action is claimed for this incident. The observed test was executed locally as part of an authorized lab exercise. Do not describe firewall blocking, endpoint isolation, or successful remediation unless separate evidence proves those actions occurred.

## Evidence references

See [evidence-manifest.csv](evidence-manifest.csv) for the planned screenshot and log evidence identifiers.

| Evidence ID | Description | Collection state |
|---|---|---|
| PS-01 | Wazuh alert 92057 with full rule and agent details | Pending attachment |
| PS-02 | Parent cmd.exe process creation event | Pending attachment |
| PS-03 | Child powershell.exe event and encoded command line | Pending attachment |
| PS-04 | Parent/child process correlation using process GUIDs | Pending attachment |
| LOG-01 | Sanitized Wazuh alert JSON excerpt | Pending attachment |
| LOG-02 | Sanitized Sysmon Event ID 1 excerpt(s) | Pending attachment |

## Limitations

- Screenshot files have not yet been committed to this repository.
- Original JSON exports should be sanitized and attached before this report is considered fully evidenced.
- This report does not claim successful containment or eradication.
- The observed user context and process identifiers should be rechecked against the raw exported event before public release.

## Lessons and follow-up

- Retain process creation telemetry with command-line and parent-process context.
- Preserve process GUIDs to support reliable parent/child correlation.
- Keep simulation timestamps so analysts can distinguish authorized tests from unrelated activity.
- Add the redacted screenshots and sanitized event excerpts before marking evidence collection complete.
