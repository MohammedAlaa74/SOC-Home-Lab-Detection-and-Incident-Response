# Incident Report — INC-003: PostgreSQL Port Scan

## 1. Incident summary

| Field | Value |
|---|---|
| Incident ID | INC-003 |
| Title | Suspected PostgreSQL Port Scan |
| Status | Evidence pending |
| Severity | To be determined from validated telemetry |
| Detection source | Suricata integrated with Wazuh |
| Target service port | TCP/5432 (confirm from event) |
| Wazuh detection rule | 110501 — level 8 (runtime validation pending) |
| Wazuh correlation rule | 110502 — level 10, frequency 3, timeframe 60 seconds (runtime validation pending) |
| MITRE ATT&CK | T1046 — Network Service Discovery |

## 2. Executive summary

A network event is being investigated as a suspected scan targeting PostgreSQL service port 5432. The incident will be confirmed only after reviewing the original Suricata event and the corresponding Wazuh alert. A correlation alert will be reported only if rule 110502 is present in the evidence.

**Current conclusion:** Pending evidence review. No claim of successful database access, authentication, exploitation, or compromise is made at this stage.

## 3. Scope and affected assets

| Role | Value |
|---|---|
| Source IP | PENDING — extract from event |
| Destination IP | PENDING — extract from event |
| Destination port | PENDING — verify 5432 |
| Protocol | PENDING |
| Target hostname | PENDING — sanitize before publication |
| Sensor / agent | PENDING |

## 4. Timeline

| Time (UTC) | Event | Evidence |
|---|---|---|
| PENDING | Suricata detected suspected PostgreSQL scan | LOG-01 |
| PENDING | Wazuh rule 110501 alert generated | LOG-02 |
| PENDING | Wazuh rule 110502 correlation generated, if applicable | LOG-03 |

Use timestamps from the source records. Do not infer missing times.

## 5. Detection details

### 5.1 Suricata

- Signature/message: PENDING
- Signature ID (SID): PENDING
- Event type: PENDING
- Source IP/port: PENDING
- Destination IP/port: PENDING
- Transport protocol: PENDING
- Timestamp: PENDING

### 5.2 Wazuh rule 110501

- Alert ID: PENDING
- Rule level: PENDING
- Rule description: PENDING
- Agent: PENDING
- Timestamp: PENDING
- Fields matched: PENDING

### 5.3 Wazuh rule 110502 correlation

- Did the rule fire? PENDING
- Frequency / timeframe: 3 matches within 60 seconds (from supplied rule; verify live behavior)
- Same-field condition: `src_ip` (from supplied rule; verify this exact decoded dynamic field exists)
- Number of matched events: PENDING — rule configuration specifies frequency 3
- Correlation window: PENDING

The supplied XML is stored in `rules/110501.xml` and `rules/110502.xml`. Runtime loading and event-field compatibility are not yet verified. The group label `active_response_trigger` is only a classification tag; it does not, by itself, execute an active response.

## 6. Analysis

Record only what the evidence demonstrates:

- Whether the traffic targeted TCP/5432.
- Whether Suricata classified the activity as scanning or service discovery.
- Whether Wazuh ingested the Suricata event.
- Whether rule 110501 matched.
- Whether rule 110502 correlated multiple events.
- Whether the destination responded, if response evidence exists.

A detection of probing does not prove that PostgreSQL accepted a connection or that credentials were tested.

## 7. MITRE ATT&CK mapping

**T1046 — Network Service Discovery**

Rationale: the observed activity may represent probing to identify network services. Confirm this mapping against the actual signature and packet/event context.

## 8. Response and containment

- Immediate action: PENDING
- Source blocked? PENDING — require firewall/active-response evidence.
- Destination service state: PENDING
- Validation after response: PENDING

Do not state that an IP was blocked unless a corresponding active-response log and host/firewall state confirm it.

## 9. Evidence references

See `evidence-manifest.csv` for the complete evidence inventory.

## 10. Final assessment

**Verdict:** PENDING — suspected PostgreSQL service scan.

**Compromise assessment:** No successful authentication, database access, exploitation, or data exfiltration is established by scan telemetry alone.

**Lessons learned / follow-up:** PENDING after evidence review.
