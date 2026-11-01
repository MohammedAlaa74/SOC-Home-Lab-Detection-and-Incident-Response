# Network Topology

## Logical layout

The lab uses a private subnet, 192.168.50.0/24.

```text
                 Isolated SOC Lab Network
                       192.168.50.0/24

  +------------------+       +------------------+
  | DC01             |       | PC01             |
  | 192.168.50.10    |       | 192.168.50.20    |
  | Active Directory |       | Windows Endpoint |
  +------------------+       |                  |
                             +------------------+

 +------------------+
 | Wazuh Manager    |
 | 192.168.50.30    |
 | Monitoring Host  |  
 +------------------+         +------------------+
                              | Kali             |
                              | 192.168.50.40    |
                              | Authorized tests |
                              +------------------+
      

                
```

> The diagram is logical, not a verified physical network map. Confirm the Wazuh manager interface/address and current VM connectivity before replacing the placeholder.

## Security boundaries

- PC01 is the endpoint used for the documented INC-001 test.
- DC01 is the domain controller and must be protected from unapproved test actions.
- 192.168.50.30 is reserved for monitoring/support services and must not be included in attack or containment targets.
- Kali is used only for authorized lab validation.
