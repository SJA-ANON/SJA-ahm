# Syed Junaid Ahmed

Security Analyst | Detection Engineering | SIEM | Cloud Security

Focused on detection engineering, log analysis, and understanding attacker behavior in real-world environments. Working across SOC operations, cloud telemetry, and security monitoring with an emphasis on building reliable detections and reducing noise in SIEM systems.

---

## About

I work on identifying malicious activity by analyzing logs, correlating events, and building detection logic that reflects real attacker behavior. My experience is centered around SOC environments where visibility, alert quality, and response time are critical.

I am particularly interested in:
- How attackers operate across identity, endpoint, and network layers  
- Building detections that are both accurate and maintainable  
- Understanding gaps in monitoring and improving coverage  
- Applying observability concepts to security telemetry  

---

## Technical Focus

### Detection Engineering
- Writing and tuning detection rules using KQL and SPL  
- Mapping detections to MITRE ATT&CK techniques  
- Reducing false positives through rule refinement and context enrichment  
- Building correlation logic across multiple log sources  

### Threat Hunting & Analysis
- Investigating suspicious patterns in authentication and network logs  
- Identifying anomalies in user behavior and system activity  
- IOC-based and behavior-based threat hunting  
- Log correlation across endpoint, identity, and cloud telemetry  

### SIEM & Monitoring
- Microsoft Sentinel, Splunk, Elastic  
- Log ingestion, normalization, and parsing  
- Alert triage and incident investigation workflows  
- Dashboarding and visualization for attack patterns  

### Cloud & Identity Security
- Azure, Azure AD (Entra ID), Azure Monitor  
- Authentication logs, conditional access, identity-based detections  
- Basic understanding of Defender for Cloud  

### Automation & DevSecOps (Exposure)
- Python scripting for basic automation  
- SOAR workflows using Shuffle  
- CI/CD security concepts using GitHub Actions (lab)  
- Familiarity with OpenTelemetry concepts  

### Networking & Systems
- TCP/IP, DNS, HTTP/S  
- Windows and Linux fundamentals  
- Active Directory basics  

---

## Projects

### SIEM Honeypot Lab (Azure)
- Designed a cloud-based honeypot environment to capture real attack traffic  
- Ingested logs into Microsoft Sentinel for centralized monitoring  
- Developed KQL-based detection rules for brute force, scanning, and suspicious login activity  
- Built dashboards to visualize attacker behavior and geolocation trends  
- Analyzed attack patterns to understand common tactics used against exposed services  

Repository:  
https://github.com/SJA-ANON/SIEM-Honeypot-SOC  

---

### Malware Analysis Lab
- Performed static and dynamic malware analysis in an isolated lab environment  
- Observed process execution, persistence mechanisms, and network behavior  
- Extracted indicators of compromise (IOCs)  
- Mapped observed behavior to MITRE ATT&CK techniques for detection use cases  

Repository:  
https://github.com/SJA-ANON/Malware-Analysis-Lab  

---

### SOC Automation (SOAR)
- Built basic automation workflows using Shuffle  
- Integrated alert handling with case management (TheHive)  
- Automated initial triage steps such as enrichment and classification  
- Reduced repetitive manual effort in SOC workflows  

---

### External Recon / Attack Surface Analysis
- Performed asset discovery using Amass and theHarvester  
- Conducted network and service enumeration using Nmap  
- Enriched findings using VirusTotal, AbuseIPDB, and Shodan  
- Identified exposed services and potential attack vectors  

---

## Detection Samples

### KQL – Suspicious Sign-in Activity

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName
| where FailedAttempts > 5
| order by FailedAttempts desc
