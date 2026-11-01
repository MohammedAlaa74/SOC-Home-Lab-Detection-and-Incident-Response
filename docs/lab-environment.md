# Lab Environment

## Scope

This document describes the isolated SOC home lab used for controlled detection and incident-response exercises. Values below are lab identifiers, not production infrastructure.

## Known systems

| System | Role | Address | Notes |
|---|---|---:|---|
| Wazuh | SIEM manager and monitoring server | Not stated here | Wazuh manager v4.14.9 was reported active after configuration correction |
| DC01 | Active Directory domain controller | 192.168.50.10 | Windows Server lab system |
| PC01 | Windows endpoint under monitoring | 192.168.50.20 | Wazuh agent ID 002; Windows 10; Sysmon telemetry |
| Monitoring host | Monitoring/supporting services | 192.168.50.30 | Monitoring only; exclude from attack simulation and containment tests |
| Kali | Authorized test workstation | 192.168.50.40 | Used for approved lab simulations where applicable |

## Network

- Lab subnet: 192.168.50.0/24.
- Domain names observed in lab notes include soclab.local and corp.local in separate configuration stages. Confirm the currently active domain before documenting domain-specific tests.
- Do not assume that every address above is currently online; verify the current VM/network state before running tests.

## Telemetry and tools

- Wazuh for centralized alerting and endpoint monitoring.
- Sysmon on PC01 for process and system telemetry.
- Active Directory for identity and domain policy scenarios.
- Suricata for network detection scenarios.
- Atomic Red Team for controlled ATT&CK-aligned test execution.

## Safety constraints

1. Perform tests only on systems owned by or explicitly authorized for this lab.
2. Do not target the monitoring host at 192.168.50.30.
3. Do not publish passwords, tokens, private keys, or unredacted account data.
4. Validate containment scope and allowlists before enabling any active response.
