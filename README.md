<div align="center">

# 🛡️ THM: Enterprise Security & Incident Response Portfolio

**Practical Threat Analysis, Digital Forensics, and SOC Operations Documentation**

[![TryHackMe Rank](https://img.shields.io/badge/TryHackMe-Top_1%25-informational?style=for-the-badge&logo=tryhackme&logoColor=white&color=bd0000)](https://tryhackme.com/p/a.w.a.i.s)
<!--[![GitHub Stars](https://img.shields.io/github/stars/YOUR_USERNAME/THM?style=for-the-badge&color=eac54f)](https://github.com/YOUR_USERNAME/THM/stargazers)-->
[![Focus](https://img.shields.io/badge/Focus-Blue_Team_%7C_DFIR-informational?style=for-the-badge&color=005571)](#)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-Yes-success?style=for-the-badge&color=007f3f)](#)

> *"Transforming raw telemetry into actionable intelligence. This repository serves as a living record of my continuous evolution in cyber defense, threat hunting, and incident response."*

</div>

---

## 📌 Repository Overview

Welcome to my TryHackMe (THM) technical portfolio. This repository is specifically curated to showcase my proficiency in **Blue Team Operations, Security Information and Event Management (SIEM), and Digital Forensics and Incident Response (DFIR)**. 

Unlike traditional "CTF write-ups" that merely provide flags and answers, the documentation contained within this repository emphasizes **analytical methodologies, investigative workflows, and remediation strategies**. Every entry is treated as a post-incident report (PIR), detailing:
* How the threat was detected.
* The correlation of malicious artifacts.
* The operational impact of the compromise.
* Actionable defensive recommendations.

---

## 📂 Write-up Directory & Analytical Index

*Click on the link in the **Documentation** column to view the full investigative report.*

| 🔬 Lab / Room Name | 📑 Category | 🚦 Difficulty | 🔗 Documentation |
| :--- | :--- | :---: | :--- |
| **[Splunk: Boss of the SOC](https://tryhackme.com/room/investigatingwithsplunk)** | SIEM / Log Analysis | 🟠 Medium | [Read Report](https://github.com/awais1-cybersec/THM/blob/main/SOC%20Level%201/Splunk.md) |
| **[Investigating Windows](https://tryhackme.com/room/investigatingwindows)** | Endpoint Forensics | 🟢 Easy | [Read Report](https://github.com/awais1-cybersec/THM/blob/main/SOC%20Level%201/Investigating_Windows.md) |
| **[KAPE & Registry Analysis](https://tryhackme.com/room/kape)** | DFIR / Artifacts | 🔴 Hard | [Read Report](https://github.com/awais1-cybersec/THM/blob/main/SOC%20Level%201/KAPE.md) |
| **[Phishing Emails 101](https://tryhackme.com/room/phishingemails5fgjlzxc)** | Email / Malware Analysis | 🟢 Easy | [Read Report](https://github.com/awais1-cybersec/THM/blob/main/SOC%20Level%201/PhishingEmail.md) |
| **[Zeek & Suricata](https://tryhackme.com/room/zeekbroexercises)** | Network Traffic Analysis (NTA) | 🟠 Medium | [Read Report](https://github.com/awais1-cybersec/THM/blob/main/SOC%20Level%201/Zeek.md) |
| **[Brim & Wireshark](https://tryhackme.com/room/brim)** | PCAP Investigation | 🟠 Medium | [Read Report](https://github.com/awais1-cybersec/THM/blob/main/SOC%20Level%201/brim.md) |

*(Note: This index is continuously updated as new operational labs are completed.)*

---

## 🧠 My Analytical Methodology

When approaching a compromised environment or security event, I adhere to a structured, repeatable framework inspired by the **NIST Incident Response Lifecycle (SP 800-61)**:

1. **Preparation & Scoping (Reconnaissance):** Understanding the network topology, establishing baselines, and identifying the key assets involved in the scenario.
2. **Detection & Triage (Investigation):** Querying SIEM logs, analyzing PCAPs, and parsing endpoint artifacts to construct a timeline of the adversary's actions. I focus heavily on mapping findings to the **MITRE ATT&CK® Framework**.
3. **Eradication & Containment (Strategy):** Determining the necessary steps to isolate the threat. While THM labs are simulated, my reports conclude with hypothetical firewall rules, EDR isolation steps, or account suspensions.
4. **Post-Incident Reporting (Documentation):** Translating technical findings into business-readable intelligence, complete with IOCs (Indicators of Compromise) and long-term hardening recommendations.

---

## 🛠️ Tech Stack & Operational Tooling

Throughout these investigations, I actively utilize industry-standard tooling to parse, analyze, and visualize data.

### SIEM & Log Aggregation
![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat-square&logo=splunk&logoColor=white)
![Elastic](https://img.shields.io/badge/Elastic_Stack-005571?style=flat-square&logo=elastic&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-005571?style=flat-square&logo=kibana&logoColor=white)

### Network Traffic Analysis (NTA)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-777777?style=flat-square&logo=zeek&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?style=flat-square&logo=suricata&logoColor=white)

### Digital Forensics & Malware Triage
![Autopsy](https://img.shields.io/badge/Autopsy-000000?style=flat-square&logo=autopsy&logoColor=white)
![Volatility](https://img.shields.io/badge/Volatility-4B275F?style=flat-square&logo=python&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=flat-square&logo=virustotal&logoColor=white)

---

## ⚖️ Ethics & Disclaimer

**Strictly for Educational Purposes.** The documentation, scripts, and methodologies provided in this repository are intended solely for educational purposes, authorized security research, and the professional development of defensive cybersecurity skills. 

I strictly adhere to ethical hacking guidelines and responsible disclosure. None of the techniques documented here should be utilized against systems, networks, or infrastructure without explicit, written consent from the asset owner. 

---

## 🤝 Connect With Me

I am always open to discussing threat intelligence, SOC strategies, or potential career opportunities. Let's connect:

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/awais-asgher)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-View_Profile-bd0000?style=for-the-badge&logo=tryhackme&logoColor=white)](https://tryhackme.com/p/a.w.a.i.s)
<!--[![Email](https://img.shields.io/badge/Email-Reach_Out-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:YOUR_EMAIL@example.com)-->

<div align="center">
  <sub>Built with precision and passion for Cyber Defense.</sub>
</div>
