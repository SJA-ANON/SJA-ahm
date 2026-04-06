# Syed Junaid Ahmed

Security Analyst | Detection Engineering | SIEM | Cloud Security

Working across SOC operations, detection engineering, and cloud security. Focused on understanding attacker behavior, building detections, and improving visibility in noisy environments.

---

## About

- Experience in monitoring and investigating security events across enterprise environments  
- Building and tuning detections using Splunk and Microsoft Sentinel  
- Interested in attacker techniques, log patterns, and breaking down real-world attack chains  
- Currently exploring DevSecOps and observability from a security perspective  

---

## What I Work On

- Detection engineering (KQL, SPL, correlation rules)  
- Threat hunting using MITRE ATT&CK  
- Log analysis across endpoint, network, and cloud  
- SIEM pipelines: ingestion → normalization → detection → response  
- Basic automation to reduce manual SOC effort  

---

## Projects

### SIEM Honeypot Lab
- Deployed exposed services to attract real attack traffic  
- Collected and analyzed logs in Microsoft Sentinel  
- Built detection queries for brute force, scanning, and suspicious activity  
- Visualized attacker behavior using dashboards  

https://github.com/SJA-ANON/SIEM-Honeypot-SOC  

---

### Malware Analysis Lab
- Static and dynamic malware analysis in controlled environment  
- Observed process behavior, persistence, and network activity  
- Extracted IOCs and mapped behavior to ATT&CK techniques  

https://github.com/SJA-ANON/Malware-Analysis-Lab  

---

### SOC Automation (SOAR)
- Built basic playbooks using Shuffle  
- Integrated alert ingestion with case management (TheHive)  
- Automated initial triage steps  

---

### External Recon / Attack Surface
- Asset discovery using Amass and theHarvester  
- Service and port analysis with Nmap  
- Data enrichment via VirusTotal, AbuseIPDB, Shodan  

---

## Sample Work

**KQL – Suspicious Sign-in Pattern (Example)**

```kql
SigninLogs
| where ResultType != 0
| summarize count() by IPAddress, UserPrincipalName
| where count_ > 5
| order by count_ desc
