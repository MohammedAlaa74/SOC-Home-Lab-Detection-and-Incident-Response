# Wazuh rule configuration

Upload the **exact deployed XML** for:
- `110501.xml` — Suricata PostgreSQL scan detection.
- `110502.xml` — correlation rule, if deployed and used.

Do not copy a guessed rule definition from this template. Preserve the actual `if_sid` / `if_matched_sid`, field matching, frequency, timeframe, same-field logic, level, description, and MITRE mapping from the active configuration.

After uploading, verify that the XML here matches the live manager configuration. If the live rule differs, document the difference rather than silently editing the evidence.
