# Host-Based Forensic Analysis & Compromise Report

**Endpoint:** Unidentified Web Server
**Operating System:** Windows Server 2016
**Date of Investigation:** 05/02/2025
**Investigator:** SOC Tier 3 Analyst / Incident Responder

## Executive Summary

On **03/02/2019**, a targeted compromise was identified on a Windows Server 2016 endpoint. The threat actor gained initial access by uploading a malicious `.jsp` web shell, subsequently elevating privileges and establishing persistent C2 (Command and Control) communications with an external IP address (**76.32.97.132**). The forensic investigation uncovered widespread credential theft via **Mimikatz**, unauthorized privilege escalation of dormant accounts (`Jenny`, `Guest`), and the deployment of a PowerShell-based persistence mechanism masquerading as a routine system task. The endpoint is considered fully compromised, and immediate isolation and remediation procedures are required.

## Forensic Methodology & Triage

The investigation utilized a manual endpoint analysis methodology, prioritizing volatile data, Windows Event Logs (Security and System), and file system artifacts. The primary analytical focus included:

* **Event Log Triage:** Auditing Security Event Logs for anomalous Logon/Logoff activity (Event IDs 4624, 4625) and Special Privilege assignments (Event ID 4672).
* **Persistence Mechanisms:** Examining the Task Scheduler, Registry run keys, and Startup folders for unauthorized executions.
* **Network & Configuration Forensics:** Reviewing local DNS resolution (`hosts` file) and active listening ports to map attacker lateral movement and C2 infrastructure.

---

## Artifact Analysis & Investigation Log

### Initial Access & Execution

The threat actor breached the perimeter by exploiting the hosted web application, successfully uploading a malicious web shell with a **`.jsp`** extension. This granted the attacker a preliminary foothold to execute commands within the context of the web server service.

### Account & Logon Forensics

A review of the Security Event Logs revealed a timeline of malicious account manipulation and credential harvesting:

* **Credential Dumping:** Artifacts indicate the attacker executed **Mimikatz** to interact with the Local Security Authority Subsystem Service (LSASS) and extract plaintext credentials/hashes from memory.
* **Privilege Escalation:** On **03/02/2019 at 4:04:49 PM**, Windows Security Logs recorded the first assignment of special privileges to a new logon session (Event ID 4672), indicating successful administrative escalation.
* **Rogue Administrative Accounts:** The attacker maliciously added two accounts to the local Administrators group: **`Jenny`** and **`Guest`**. Forensic timeline analysis confirmed that the `Jenny` account has **never** logged on interactively, serving solely as a backdoor administrative account.
* **Valid Account Usage:** The **`Administrator`** account was the last recorded user to log in. Furthermore, the legitimate user **`John`** last authenticated to the system on **03/02/2019 at 5:48:32 PM**, placing his session within the active compromise window and rendering his credentials compromised.

### Execution & Persistence

To survive system reboots and maintain access, the attacker engineered a stealthy persistence mechanism:

* **Malicious Scheduled Task:** A Scheduled Task deceptively named **`Clean File System`** was created to execute daily.
* **Payload Analysis:** This task was configured to execute a PowerShell script named **`nc.ps1`**.
* **Local Bind Shell:** Upon execution, `nc.ps1` establishes a local listener on port **`1348`**, functioning as a persistent bind shell.
* **Startup Network Connections:** Further network analysis revealed that upon startup, the system initiates an anomalous outbound connection to **`10.34.2.3`**, indicating a secondary payload or internal lateral movement staging.

### Network Defense Evasion & Lateral Movement

The attacker actively manipulated host-level network configurations to bypass defenses and intercept traffic:

* **Firewall Modification:** The threat actor explicitly opened port **`1337`** on the local firewall, likely to allow ingress traffic for a secondary bind shell or C2 relay.
* **DNS Poisoning:** Inspection of the `C:\Windows\System32\drivers\etc\hosts` file revealed local DNS cache poisoning targeting **`google.com`**. This technique is frequently used to redirect legitimate outbound traffic to attacker-controlled infrastructure or to block security telemetry updates.
* **External C2:** The primary external Command and Control server was identified as **`76.32.97.132`**.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Context / Evidence |
| --- | --- | --- | --- |
| **Initial Access** | T1505.003 | Server Software Component: Web Shell | Attacker uploaded a `.jsp` web shell to the server. |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution of malicious `nc.ps1` script. |
| **Persistence** | T1053.005 | Scheduled Task/Job | Rogue task named `Clean File System` running daily. |
| **Persistence** | T1078.003 | Valid Accounts: Local Accounts | Rogue use of `Jenny` and `Guest` as Local Admins. |
| **Credential Access** | T1003.001 | OS Credential Dumping: LSASS Memory | Usage of `Mimikatz` to extract passwords. |
| **Defense Evasion** | T1562.004 | Impair Defenses: Disable/Modify System Firewall | Unauthorized opening of local port `1337`. |
| **Collection/Impact** | T1565.001 | Data Manipulation: Stored Data Manipulation | DNS poisoning of `google.com` in the local `hosts` file. |
| **Command & Control** | T1071.001 | Application Layer Protocol: Web Protocols | External C2 communication to `76.32.97.132`. |

---

## Indicators of Compromise (IOCs)

### Network Indicators

* **IPv4 (C2 Server):** `76.32.97.132`
* **IPv4 (Startup Connection):** `10.34.2.3`
* **Port (Malicious Listener):** `TCP/1348` (Associated with `nc.ps1`)
* **Port (Firewall Exception):** `TCP/1337` (Last port opened by attacker)
* **Domain (Poisoned):** `google.com` (via modified `hosts` file)

### Host-Based Artifacts

* **File:** `nc.ps1` (PowerShell Bind/Reverse Shell script)
* **File Extension:** `*.jsp` (Web shells located in the web application directories)
* **Scheduled Task:** `Clean File System`
* **Compromised/Rogue Accounts:** `Jenny` (Unauthorized Admin), `Guest` (Unauthorized Admin), `Administrator`, `John`

---

## Incident Disposition & Remediation

**Disposition:** True Positive. The Windows Server 2016 endpoint is fundamentally compromised at the SYSTEM level.

**Actionable Recommendations for Blue Team / IT Operations:**

1. **Containment:** Immediately isolate the affected Windows Server 2016 from the enterprise network to prevent lateral movement to `10.34.2.3` or further data exfiltration.
2. **Eradication:** Due to the execution of Mimikatz and the establishment of root-level persistence, the endpoint cannot be trusted. It must be wiped and rebuilt from a known good baseline.
3. **Credential Reset:** Force a global password reset for the `John` and `Administrator` accounts. If this server was part of an Active Directory domain, initiate a KRBTGT reset protocol, as Mimikatz execution presents a high risk of Golden/Silver Ticket generation.
4. **Account Auditing:** Demote/disable the `Jenny` and `Guest` accounts across the environment. Audit Group Policy Objects (GPOs) to ensure strict Local Administrator Password Solution (LAPS) enforcement.
5. **Web App Hardening:** Audit the web application that permitted the `.jsp` upload. Implement strict file extension validation and deploy a Web Application Firewall (WAF) to inspect inbound HTTP POST requests.
6. **Telemetry Enhancements:** Deploy and configure Sysmon (System Monitor) on the rebuilt server to log process creation (Event ID 1), network connections (Event ID 3), and file creation (Event ID 11) to accelerate future forensic triage.
