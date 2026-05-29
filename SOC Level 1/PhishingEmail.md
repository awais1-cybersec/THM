# Phishing Incident Triage & Investigation Report: "Transfer Reference 09674321"

**Analyst:** Awais Asgher | SOC Level 1 Analyst

**Date:** May 29, 2026

**Environment:** TryHackMe Virtual Machine, Ubuntu OS 24.04.01 LTS

## Incident Overview

A highly suspicious email was escalated to the Security Operations Center (SOC) for triage. The email utilized a financial urgency lure, leveraging the subject line **"Transfer Reference Number: 09674321"** to masquerade as an official invoice or wire transfer communication. The primary objective of this investigation is to parse the raw SMTP headers to identify spoofing techniques, evaluate domain authentication controls, safely extract and analyze the delivered payload, and establish actionable Indicators of Compromise (IOCs) for enterprise containment.

## Email Header & Authentication Analysis

### Sender Discrepancy & Spoofing

Analysis of the raw SMTP headers reveals a deliberate attempt to deceive the recipient through reply-chain manipulation.

* **Sender Display Name:** Mr. James Jackson
* **From Address:** `info@mutawamarine.com`
* **Reply-To Address:** `info.mutawamarine@mail.com`

**Finding:** The threat actor spoofed the legitimate `mutawamarine.com` domain in the *From* address to establish trust. However, the *Reply-To* header redirects any responses to a lookalike freemail drop inbox controlled by the attacker (`@mail.com`), bypassing the actual domain owner entirely.

### Originating Infrastructure

* **Originating IP (X-Originating-IP / First Hop):** `192.119.71.157`
* **IP Owner / ASN:** Hostwinds LLC

**Finding:** The email originated from infrastructure owned by Hostwinds LLC, a commercial hosting provider frequently abused by threat actors to spin up temporary, malicious SMTP relays.

### Authentication Checks

To determine why the email bypassed initial security controls, the domain's DNS TXT records were queried:

* **SPF Record:** `v=spf1 include:spf.protection.outlook.com -all`
* **DMARC Record:** `v=DMARC1; p=quarantine; fo=1`

**Finding:** The domain `mutawamarine.com` enforces a strict SPF policy (`-all`), authorizing only Outlook infrastructure to send on its behalf. Because the originating IP (`192.119.71.157`) is not authorized, the SPF check fails. Coupled with the DMARC `p=quarantine` policy, a properly configured Secure Email Gateway (SEG) should automatically flag this message and route it to the quarantine/junk folder rather than the user's inbox.

## Payload & OSINT Analysis

### Attachment Triage

The email delivered a malicious payload utilizing dual-extension masking to deceive the end-user:

* **Attachment Name:** `SWT_#09674321____PDF__.CAB`

The excessive use of underscores and the `.PDF__.CAB` naming convention is a classic defense evasion technique designed to hide the true executable nature of the file, tricking victims into believing they are opening a standard PDF document.

### Forensic Extraction & Identification

The payload was safely downloaded, defanged, and analyzed within an isolated Ubuntu 24.04.4 LTS forensic environment.

* **File Size:** 400.26 KB
* **SHA256 Hash:** `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`
* **True File Type:** RAR Archive

**Finding:** Despite the `.CAB` (Cabinet) file extension, file signature (magic byte) analysis reveals the attachment is actually a **RAR archive**. OSINT analysis via VirusTotal confirms this hash is highly malicious, operating as a RAR spreader designed to drop infostealing trojans (such as LokiBot/Agensla) that exfiltrate enterprise credentials and keystrokes upon execution.

## Indicators of Compromise (IOCs)

| Indicator Type | Value | Context |
| --- | --- | --- |
| **Sender Email (Spoofed)** | `info@mutawamarine.com` | Visible From Address |
| **Reply-To Email** | `info.mutawamarine@mail.com` | Threat Actor Drop Inbox |
| **Originating IP** | `192.119.71.157` | Malicious SMTP Relay (Hostwinds LLC) |
| **Attachment Name** | `SWT_#09674321____PDF__.CAB` | Malspam Payload Lure |
| **File Hash (SHA256)** | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` | Malicious RAR Archive Dropper |

## Containment & Remediation (SOC Actions)

To neutralize this threat, the Blue Team should execute the following response actions:

1. **Global Message Purge:** Execute a threat hunt across the Office 365/Google Workspace tenant. Hard-purge any messages matching the sender domain `info@mutawamarine.com`, the Reply-To address, or the subject line containing `09674321` from all user inboxes.
2. **Infrastructure Blocking:** Update the Secure Email Gateway (SEG) and enterprise perimeter firewalls to block inbound/outbound traffic to the originating IP (`192.119.71.157`) and the attacker's drop inbox (`info.mutawamarine@mail.com`).
3. **Endpoint Threat Hunting:** Ingest the SHA256 hash (`2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`) into the Endpoint Detection and Response (EDR) platform (e.g., Wazuh/Splunk) to verify that no endpoints have successfully executed the payload.
4. **User Remediation:** If telemetry indicates a user interacted with the payload, immediately isolate the affected workstation from the network, force a global credential reset for the compromised user, and initiate standard malware containment and imaging procedures.
