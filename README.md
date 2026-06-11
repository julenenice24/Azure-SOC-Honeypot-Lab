# Azure SOC Honeypot Lab

## Overview
Built a cloud-based honeynet in Microsoft Azure to attract and analyze 
real-world cyber attacks. Configured a deliberately vulnerable Windows VM, 
ingested logs into Microsoft Sentinel (SIEM), and used KQL queries to 
identify brute force attempts from malicious IPs globally.

## Architecture
Attacker → Open NSG (All Ports) → Honeypot VM → Log Analytics Workspace → Microsoft Sentinel

## Tools & Technologies
- Microsoft Azure (Virtual Machine, NSG, Network Watcher)
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- Microsoft Defender for Cloud
- KQL (Kusto Query Language)
- VirusTotal (Threat Intelligence)

## What I Built
- Deployed a Windows Server 2022 VM as a honeypot
- Configured NSG to allow all inbound traffic (deliberately vulnerable)
- Created Log Analytics Workspace to ingest security events
- Enabled Microsoft Defender for Cloud for EDR telemetry
- Connected Microsoft Sentinel for SIEM visualization
- Built a live world attack map showing real-time threats

## Attack Results
Within 24 hours of deployment, the honeypot attracted attacks from:

| Attacker IP | Country | Attack Count | Method |
|---|---|---|---|
| 45.142.193.166 | Russia | 132 | RDP Brute Force |
| 119.148.49.82 | China | 41 | RDP Brute Force |
| 88.214.25.123 | Europe | 2 | RDP Brute Force |
| 45.142.193.145 | Russia | 2 | RDP Brute Force |
| 80.94.95.83 | Unknown | 2 | RDP Brute Force |

### Usernames Attackers Tried
| Username | Count |
|---|---|
| honeypot | 41 |
| Veeam | 16 |
| backup | 16 |
| administrator | 14 |
| oracle | 16 |
| Test | 6 |

## KQL Queries Used

### Failed Login Attempts with Attacker IPs
```kusto
Event
| where EventID == 4625
| extend IpAddress = extract(@"Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)", 1, RenderedDescription)
| extend AccountName = extract(@"Account For Which Logon Failed:\s+Security ID:\s+\S+\s+Account Name:\s+(\S+)", 1, RenderedDescription)
| where IpAddress != "" and IpAddress != "-"
| summarize Count = count() by AccountName, IpAddress
| order by Count desc
```

### Attacker Leaderboard
```kusto
Event
| where EventID == 4625
| extend IpAddress = extract(@"Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)", 1, RenderedDescription)
| where IpAddress != "" and IpAddress != "-"
| summarize AttackCount = count() by IpAddress
| order by AttackCount desc
```

### World Attack Map (Microsoft Sentinel)
```kusto
Event
| where EventID == 4625
| extend IpAddress = extract(@"Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)", 1, RenderedDescription)
| where IpAddress != "" and IpAddress != "-"
| summarize AttackCount = count() by IpAddress
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend ['Latitude'] = todouble(GeoInfo.latitude)
| extend ['Longitude'] = todouble(GeoInfo.longitude)
| extend ['Country'] = tostring(GeoInfo.country)
| project IpAddress, AttackCount, ['Latitude'], ['Longitude'], ['Country']
```

## Screenshots
### World Attack Map
![World Attack Map](screenshots/world-attack-map.png)

### Attacker IP Leaderboard
![Attacker Leaderboard](screenshots/attacker-leaderboard.png)

### Brute Force Usernames
![Usernames](screenshots/brute-force-usernames.png)

## Key Takeaways
- An exposed RDP port attracts automated brute force attacks within hours
- Attackers target common service account names like Veeam, backup, oracle
- Threat intelligence tools like VirusTotal confirm malicious IP sources
- SIEM tools like Microsoft Sentinel enable real-time threat visualization

## Author
Arnold Jaoko
[LinkedIn](https://www.linkedin.com/in/arnold-jaoko/)
