# Sanitized Logs

Store only the minimum event excerpts needed to reproduce the investigation.

For INC-001, the planned files are:

- `LOG-01-wazuh-alert-92057.json`
- `LOG-02-sysmon-process-creation.json`

Before committing, remove secrets and unrelated personal data. Preserve the fields needed for analysis, such as timestamp, agent, rule ID, event ID, process image, command line (after assessing whether it contains sensitive data), process GUID, parent process details, and ATT&CK metadata.

Do not place full unfiltered `alerts.json`, `archives.json`, or raw event exports in a public repository.
