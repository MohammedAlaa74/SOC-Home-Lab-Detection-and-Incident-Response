# Incident Report — INC-003: PostgreSQL Port Scan

## 1. Incident summary

| Field | Value |
|---|---|
| Incident ID | INC-003 |
| Title | Suspected PostgreSQL Port Scan |
| Status | Detection and correlation evidenced; screenshots pending |
| Severity | Wazuh correlation alert level 10 |
| Detection source | Suricata integrated with Wazuh |
| Target service port | TCP/5432 |
| Suricata signature | ET SCAN Suspicious inbound to PostgreSQL port 5432 |
| Suricata signature ID | 2010939 |
| Wazuh detection rule | 110501 — level 8 |
| Wazuh correlation rule | 110502 — level 10, frequency 3, timeframe 60 seconds |
| MITRE ATT&CK | T1046 — Network Service Discovery |

## 2. Executive summary

Suricata generated an alert for traffic matching the ET SCAN signature **"Suspicious inbound to PostgreSQL port 5432"**. Wazuh ingested the event and generated rule 110501 (level 8). A separate Wazuh correlation alert shows rule 110502 (level 10) matching three events from the same source IP within the configured 60-second window.

The correlation alert's `previous_output` contains two earlier matching events, and the current event supplies the third. Their event timestamps span approximately **3.44 seconds** (2026-11-01 16:14:13.479520 to 16:14:16.919013, UTC+02:00).

**Assessment:** The evidence supports repeated network probing consistent with PostgreSQL service discovery / port scanning. It does not establish successful PostgreSQL access, authentication, exploitation, or compromise.

## 3. Scope and affected assets

The public evidence files replace the original private lab IPs with RFC 5737 documentation addresses:

| Role | Published value |
|---|---|
| Source IP | 198.51.100.40 (sanitized) |
| Destination IP | 203.0.113.20 (sanitized) |
| Destination port | TCP/5432 |
| Protocol | TCP |
| Sensor interface | ens33 |
| Wazuh agent | Manager / agent ID 000 |

The addresses above are publication placeholders, not the original live lab addresses.

## 4. Timeline

All event times below are in UTC+02:00 as provided in the source records.

| Time | Event | Evidence |
|---|---|---|
| 16:14:13.479520 | First prior matching Suricata alert shown in correlation history | LOG-02 |
| 16:14:13.579198 | Second prior matching Suricata alert shown in correlation history | LOG-02 |
| 16:14:16.919013 | Current matching event that triggered the correlation alert | LOG-02 |
| 16:14:17.019246 | Separate Suricata event ingested and matched by rule 110501 | LOG-01 / LOG-03 |
| 16:14:18.696 | Wazuh alert timestamp shown for the two supplied alert records | LOG-01 / LOG-02 |

The three events used by rule 110502 are within the 60-second timeframe. The separate 16:14:17.019246 event is not counted as one of the three prior/current entries shown in that correlation alert's `previous_output`.

## 5. Detection details

### 5.1 Suricata event

- Signature: `ET SCAN Suspicious inbound to PostgreSQL port 5432`
- Signature ID: `2010939`
- GID: `1`
- Revision: `3`
- Category: `Potentially Bad Traffic`
- Signature severity metadata: `Informational`
- Confidence metadata: `Medium`
- Destination port: `5432/TCP`
- Suricata action: `allowed`
- Packet counters for the shown flow: 1 packet to server, 0 packets to client
- Bytes for the shown flow: 60 bytes to server, 0 bytes to client

**Interpretation:** Suricata's `allowed` action means the observed traffic was not blocked by the Suricata action recorded in this event. The counters show no client-bound response packets in this particular flow record; this alone does not prove the service was unavailable or that no other response occurred.

### 5.2 Wazuh rule 110501

- Rule ID: `110501`
- Level: `8`
- Description: `SOC: Suricata detected PostgreSQL port scan ...`
- Rule `firedtimes` field: `5`
- Agent ID: `000` (manager)
- Source file: `/var/log/suricata/eve.json`
- Decoder: `json`

The alert confirms that the custom detection rule matched a Suricata event. The `firedtimes` value is recorded as alert metadata; it is not independently used here to infer five events from the same source within a specific timeframe.

### 5.3 Wazuh rule 110502 correlation

- Rule ID: `110502`
- Level: `10`
- Configured frequency: `3`
- Configured timeframe: `60 seconds`
- Same-field condition: `src_ip`
- Observed source consistency: all three shown events have the same sanitized source address.
- Correlation alert `frequency`: `3`
- `previous_output`: two prior matching events, in addition to the current event.

**Conclusion:** The supplied alert demonstrates that rule 110502 fired and correlated three matching Suricata detections from the same source within the configured window. This also provides runtime evidence that `src_ip` was available as the dynamic field used by the rule in this event path.

## 6. Analysis

The event chain supports:
1. Suricata identified traffic matching the ET SCAN PostgreSQL port 5432 signature.
2. Wazuh rule 110501 generated a level-8 alert from the Suricata event.
3. Wazuh rule 110502 generated a level-10 correlation alert after three matching events from the same source within 60 seconds.
4. The observed source and destination remained consistent across the three events shown in the correlation history.

The available records do **not** prove:
- that PostgreSQL accepted a connection;
- that authentication was attempted or succeeded;
- that a vulnerability was exploited;
- that data was accessed or exfiltrated;
- that the source was blocked.

## 7. MITRE ATT&CK mapping

**T1046 — Network Service Discovery**

The mapping is consistent with repeated probing of a network service port to identify an exposed service.

## 8. Response and containment

- Suricata action in the shown event: `allowed`.
- Wazuh active response: not evidenced by the supplied records.
- Firewall block: not evidenced.
- Destination service state: not established.
- Post-containment validation: pending.

The `active_response_trigger` group in rule 110502 is a classification label. It does not by itself prove that an active-response command executed.

## 9. Evidence references

- LOG-01 — sanitized Suricata event.
- LOG-02 — sanitized Wazuh rule 110502 correlation alert, including two prior matching events.
- LOG-03 — sanitized Wazuh rule 110501 alert.
- RULE-01 — supplied rule 110501 XML.
- RULE-02 — supplied rule 110502 XML.
- SS-01 to SS-04 — screenshots still pending upload and visual review.

See `evidence-manifest.csv` for the evidence inventory.

## 10. Final assessment

**Verdict:** Repeated PostgreSQL port probing / service discovery detected and correlated by Wazuh.

**Detection status:** Evidenced for rules 110501 and 110502.

**Compromise assessment:** No successful authentication, database access, exploitation, or data exfiltration is established by the supplied telemetry.

**Containment assessment:** No block or active-response execution is established by the supplied alerts.
