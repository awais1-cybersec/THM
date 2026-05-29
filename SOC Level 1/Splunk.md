# Security Incident Investigation Report: Malicious PowerShell Execution & WMI Backdoor Creation

**Investigator:** Muhammad Awais Asgher, SOC Analyst

**Date of Investigation:** 29/05/2026

**Status:** Closed – True Positive

**Target Index:** `main`

**Total Events Analyzed:** 12,256

---

## 1. Incident Overview

During routine proactive threat hunting, anomalous behavior was observed across several Windows endpoints. Initial telemetry indicated potential unauthorized access and the staging of a persistence mechanism. Logs were subsequently ingested into Splunk for deep-dive analysis. The investigation confirmed a successful compromise involving defense evasion via obfuscated PowerShell, remote lateral movement using Windows Management Instrumentation (WMI), and the creation of a typosquatted backdoor administrative account.

---

## 2. Investigation Timeline & SPL Analysis

### Finding 1: Identification of Unauthorized Account Creation (Persistence)

* **The Objective:** Identify newly created local user accounts to detect potential backdoor or persistence mechanisms.
* **The SPL Query:**
```splunk
index=main EventCode=4720

```


* **Query Logic:** Windows Event ID 4720 (`A user account was created`) is the definitive log source for tracking new account generation. In a mature environment, this event ID is typically heavily monitored for anomalous administrative activity.
* **The Finding:** A single anomalous account was created named `A1berto`. The adversary utilized "typosquatting"—substituting the letter 'l' with the number '1'—to impersonate the legitimate user account `Alberto` and evade superficial manual log review.

### Finding 2: Tracing Registry Modifications for the Backdoor Account

* **The Objective:** Trace underlying operating system modifications tied to the malicious profile creation.
* **The SPL Query:**
```splunk
index=main "A1berto" EventCode=13

```


* **Query Logic:** Leveraging Microsoft-Windows-Sysmon logs, Event ID 13 (`RegistryEvent (Value Set)`) was cross-referenced with the backdoor username to isolate exact registry hive modifications made by the system during the account provisioning.
* **The Finding:** The logs revealed a new subkey generated in the Security Account Manager (SAM) hive at the following path:
`HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

### Finding 3: Remote Execution and Lateral Movement Mechanisms

* **The Objective:** Determine the exact command execution methodology and origin point used to generate the backdoor account.
* **The SPL Query:**
```splunk
index=main "A1berto"

```


* **Query Logic:** A broad string search for the compromised identifier across the index to capture Process Creation (Event ID 1 / 4688) or command-line auditing artifacts.
* **The Finding:** The adversary utilized WMI to execute commands remotely across the network. The captured command line revealed the backdoor creation and the assigned password:
`"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"`

### Finding 4: Verification of Backdoor Utilization

* **The Objective:** Ascertain whether the adversary successfully authenticated to the environment using the newly provisioned backdoor credentials.
* **The SPL Query:**
```splunk
index=main User="A1berto" (EventCode=4624 OR EventCode=4625)

```


* **Query Logic:** Correlating the malicious username with Windows Security Event IDs 4624 (Successful Logon) and 4625 (Failed Logon).
* **The Finding:** `0` logon events were observed. The persistence mechanism was successfully staged by the adversary but had not yet been utilized for interactive logon prior to discovery.

### Finding 5: Defense Evasion & Obfuscated PowerShell Execution

* **The Objective:** Identify the execution of malicious scripts and capture the full operational footprint on the compromised endpoint (`James.browne`).
* **The SPL Query:**
```splunk
index=main host="James.browne" EventCode=4103

```


* **Query Logic:** Event ID 4103 (`Module Logging / Executing Pipeline`) records pipeline execution details as PowerShell executes. By filtering against the known infected host, we can capture the script blocks before they are flushed from memory.
* **The Finding:** The SIEM captured 79 PowerShell pipeline events. Telemetry revealed the execution of a heavily obfuscated PowerShell command utilizing the `-enc` (EncodedCommand) flag with a Base64 payload (`SQB...`).

### Finding 6: Payload Deobfuscation and C2 Extraction

* **The Objective:** Reverse engineer the encoded PowerShell payload to extract network indicators and determine the script's core objective.
* **Analysis Method:** Static analysis of the raw Base64 string was conducted offline via CyberChef (UTF-16LE decoding).
* **The Finding:** The initial decoded payload revealed an Antimalware Scan Interface (AMSI) bypass, allowing the script to execute without triggering local AV heuristics. Nested within this script was a secondary Base64 string that decoded directly to a Command and Control (C2) server. The script was instructed to initiate an external web request to fetch secondary tooling from: `hxxp[://]10[.]10[.]10[.]5/news[.]php`.

---

## 3. Kill Chain Reconstruction

1. **Execution & Defense Evasion:** The attacker executed a malicious, Base64-encoded PowerShell script on the endpoint `James.browne`. The script utilized an in-memory AMSI bypass to evade local endpoint protection.
2. **Command & Control (C2):** The executing script initiated an outbound HTTP request to a remote server (`10.10.10.5`) to pull down a secondary payload (`news.php`).
3. **Lateral Movement:** The adversary utilized Windows Management Instrumentation (`WMIC.exe`) to proxy command execution over the network to a secondary host (`WORKSTATION6`).
4. **Persistence:** Via WMI, the attacker successfully spawned a local administrative backdoor account (`A1berto`), deliberately mimicking the legitimate user `Alberto` to blend in with normal administrative traffic.
5. **Actions on Objectives:** Registry updates to the SAM hive were completed. The adversary successfully secured a persistent foothold, though immediate containment prevented them from authenticating with the new credentials.

---

## 4. Indicators of Compromise (IOCs)

| IOC Type | Indicator | Context / Description |
| --- | --- | --- |
| **IPv4 Address** | `10.10.10.5` | Command and Control (C2) IP address. |
| **URL** | `hxxp[://]10[.]10[.]10[.]5/news[.]php` | Endpoint hosting the secondary malicious payload. |
| **User Account** | `A1berto` | Typosquatted local backdoor account. |
| **Process / Command** | `WMIC.exe /node:WORKSTATION6` | WMI lateral movement execution string. |
| **Registry Path** | `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto` | SAM registry hive modification for the new user. |
| **Compromised Host** | `James.browne` | Patient Zero / Initial point of PowerShell execution. |

---

## 5. Incident Disposition & Remediation

**Classification:** True Positive (Confirmed Compromise)

**Actionable Blue Team Recommendations:**

1. **Host Containment:** Immediately isolate `James.browne` and `WORKSTATION6` from the production network to prevent further lateral movement.
2. **Network Blocking:** Implement egress firewall blocks and proxy blacklists for the C2 IP `10.10.10.5`.
3. **Account Remediation:** Delete the `A1berto` local account across all endpoints using centralized management (e.g., LAPS/Group Policy). Force a global password reset for the legitimate user `Alberto`.
4. **SIEM Rule Tuning:** * Implement alerting for Event Code `4720` (Account Creation) where the resulting username heavily mirrors existing administrative accounts (Levenshtein distance anomaly detection).
* Flag anomalous usage of `WMIC.exe` initiating `process call create` with `net user` commands.


5. **Forensic Follow-up:** Analyze the initial ingress vector on `James.browne`. Determine how the attacker originally obtained the ability to run the encoded PowerShell command (e.g., Phishing payload, exploited vulnerable public-facing service, or RDP brute force).
