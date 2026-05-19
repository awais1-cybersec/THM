# Vulnerability Assessment and Exploitation Report: CVE-2017-0144

## Executive Summary

A targeted vulnerability assessment was conducted against a Windows 7 asset to identify security deficiencies and evaluate the potential business impact of successful exploitation. The assessment revealed that the host is highly vulnerable to **CVE-2017-0144 (MS17-010)**, commonly known as EternalBlue. 

This vulnerability allows unauthenticated attackers to execute arbitrary code with `SYSTEM` privileges by sending specially crafted packets to a Server Message Block version 1.0 (SMBv1) server. If left unpatched in an enterprise environment, this vulnerability presents a critical risk. It facilitates unauthorized remote code execution (RCE), frictionless lateral movement, and complete host takeover, mirroring the attack paths utilized by devastating ransomware campaigns such as WannaCry and NotPetya. Immediate remediation is required to secure the infrastructure.

---

## Reconnaissance & Enumeration

The assessment began with a passive and active network discovery phase to map the target's attack surface. 

* **Port Scanning:** Nmap was utilized to conduct a comprehensive TCP SYN scan. The results indicated three open ports operating below the 1000 range, most notably port 445/TCP (SMB).
* **Vulnerability Scanning:** Subsequent enumeration utilizing Nmap's NSE (Nmap Scripting Engine) vulnerability scripts specifically targeted the SMB service. The scanning engine definitively flagged the target as vulnerable to `ms17-010`.

The presence of an exposed and unpatched SMBv1 service provided a direct vector for exploitation, bypassing the need for initial credential access or social engineering.

---

## Exploitation (The Attack Narrative)

To validate the vulnerability and demonstrate its impact, exploitation was executed using the Metasploit Framework.

**1. Delivery and Initial Access**
The exploit module `exploit/windows/smb/ms17_010_eternalblue` was configured with the target's IP address (`RHOSTS`). At a technical level, EternalBlue exploits a buffer overflow in how the legacy SMBv1 protocol handles `FEA` (File Extended Attributes) within `NT Transact` requests. By manipulating this buffer, an attacker can overwrite memory and execute arbitrary shellcode.

A non-staged payload (`windows/x64/shell/reverse_tcp`) was selected to establish an initial reverse shell back to the attack infrastructure. Upon execution, the payload successfully caught a standard DOS command shell.

**2. Tactical Escalation and Persistence**
A standard DOS shell lacks the robust capabilities required for advanced post-exploitation. To establish a more stable and capable foothold, the initial session was backgrounded and upgraded using the `post/multi/manage/shell_to_meterpreter` module.

Upon securing the Meterpreter session, execution context was verified using the `getsystem` and `whoami` commands, confirming the session was operating under `NT AUTHORITY\SYSTEM`—the highest level of local privilege. To ensure operational stability and evade basic process-level detection, the `ps` command was used to identify an existing, legitimate `SYSTEM` process. The session was then strategically migrated to this process ID (PID).

---

## Post-Exploitation & Hash Cracking

With full administrative control established, the objective shifted to credential harvesting and data exfiltration to demonstrate the potential for lateral movement.

* **Credential Extraction:** Operating within the elevated Meterpreter shell, the `hashdump` command was executed to extract the SAM (Security Account Manager) database.
* **Analysis:** The dump revealed an active, non-default user account named **Jon**.
* **Offline Cracking:** The NTLM hash for the user "Jon" was exfiltrated for offline cryptographic attack. Utilizing standard dictionary attacks and brute-force methodologies, the hash was rapidly cracked, revealing the plaintext password: `alqfna22`. 

**Proof of Compromise (PoC) Artifacts:**
To definitively prove unrestricted file system access, critical data markers (flags) were extracted from highly restricted directories across the host:
* **System Root:** `flag{access_the_machine}`
* **Windows Configuration Directory (SAM Location):** `flag{sam_database_elevated_access}`
* **Administrator Documents:** `flag{admin_documents_can_be_valuable}`

---

## Indicators of Compromise (IOCs)

To aid the Security Operations Center (SOC) and Blue Team in detecting similar attack vectors, the following IOCs and behavioral anomalies should be integrated into SIEM and EDR platforms:

| Detection Vector | Indicator / Anomaly |
| :--- | :--- |
| **Network Traffic** | Anomalous inbound traffic on Port 445 (SMB) originating from non-standard internal subnets or untrusted zones. |
| **IDS / IPS Signatures** | Alerts triggering on known MS17-010 signatures. Look for Snort rules detecting large `NT Transact` requests or specifically crafted `Multiplex ID` fields used in the EternalBlue exploit. |
| **Endpoint (Processes)** | Suspicious child processes spawning from `spoolsv.exe`, `lsass.exe`, or `services.exe` (e.g., `cmd.exe` or `powershell.exe` originating from these system binaries). |
| **Event Logs** | **Event ID 4688** (Process Creation) showing enumeration commands like `whoami` or `arp -a` executed by `SYSTEM`. |
| **Event Logs** | **Event ID 4624** (Successful Logon) utilizing Logon Type 3 (Network) with `ANONYMOUS LOGON` accessing the `IPC$` share immediately preceding anomalous process execution. |

---

## Remediation & Hardening

The exploitation of this system was trivial and absolute. To secure the enterprise environment against this vector, the following remediation strategies must be implemented immediately:

1.  **Patch Management (Critical):** Apply the Microsoft Security Bulletin **MS17-010** update to all affected Windows systems. This addresses the core buffer overflow vulnerability within the SMB service.
2.  **Deprecate SMBv1 (Strategic):** SMBv1 is a legacy protocol with inherent security flaws. It must be universally disabled across the domain via Group Policy Object (GPO). Ensure all systems utilize SMBv2 or SMBv3 with SMB Signing enforced.
3.  **Network Segmentation & Access Control:** * Block external access to ports 135, 139, and 445 at the perimeter firewall.
    * Implement internal network segmentation to isolate critical workstations from general user networks, severely limiting lateral movement via SMB.
4.  **Enforce Password Complexity:** The rapid cracking of the user "Jon" highlights a failure in password hygiene (`alqfna22`). Enforce a strict domain password policy requiring a minimum of 14 characters, combining alphanumeric characters and symbols, to defend against offline hash cracking.
