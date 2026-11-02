# INC-003 — PostgreSQL Port Scan

> **Status:** Preparation / evidence pending  
> **Detection:** Suricata → Wazuh  
> **Relevant rules:** 110501 (single scan detection), 110502 (correlation)  
> **MITRE ATT&CK:** T1046 — Network Service Discovery

## Objective

Document a suspected network scan involving PostgreSQL service port **5432**, preserve the source telemetry, and verify whether Wazuh detected and correlated the activity.

## Important scope

A scan alert is evidence of probing or service discovery. It does **not**, by itself, prove:
- a successful PostgreSQL connection;
- authentication success;
- exploitation;
- data access or compromise.

Use the wording **"suspected PostgreSQL port scan"** unless additional evidence proves a stronger conclusion.

## Folder layout

- `incident-report.md` — incident narrative and analysis.
- `evidence-manifest.csv` — evidence inventory and review status.
- `logs/` — sanitized Suricata and Wazuh event exports.
- `rules/` — exact Wazuh rules used in the lab.
- `screenshots/` — upload screenshots here, or keep them in this incident folder if using GitHub's web uploader.

## Evidence to add

1. Suricata event showing the PostgreSQL scan signature and destination port 5432.
2. Wazuh alert for rule 110501.
3. Wazuh correlation alert for rule 110502, if it fired.
4. Source/destination context showing the scanner and target.

## Before publishing

Sanitize usernames, public IPs, internal domain names, hostnames if sensitive, tokens, and unrelated personal data. Preserve timestamps, rule IDs, ports, protocol, and the fields needed to reproduce the analysis.

## Completion criteria

- [ ] Raw or minimally transformed Suricata event saved.
- [ ] Wazuh alert for 110501 saved.
- [ ] Correlation evidence for 110502 saved, or marked not triggered.
- [ ] Four screenshots uploaded and visually reviewed.
- [ ] Source and destination fields cross-checked.
- [ ] Incident conclusion supported by evidence.
- [ ] Manifest updated with actual filenames and review status.
