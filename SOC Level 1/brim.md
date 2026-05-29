# Network Threat Hunting & Packet Analysis Report

**Document ID:** NTA-BRIM-2026-001
**Analysis Type:** Post-Incident Network Triage
**Analyst:** Awais Asgher

**Disposition:** Confirmed Malicious Activity (True Positive)

---

## 1. Executive Summary

This report details the findings from a network traffic analysis (NTA) operation conducted on a captured PCAP dataset. The primary objective of this triage was to identify indicators of post-exploitation activity, isolate command and control (C2) beaconing, and extract malware delivery artifacts.

Analysis of the network telemetry revealed a multi-stage compromise involving **CobaltStrike** and **IcedID** malware families, followed by unauthorized cryptomining activity communicating over IRC. The threat actor successfully executed malicious payloads, established encrypted C2 channels, and initiated resource hijacking (MITRE ATT&CK: TA0040).

## 2. Toolset & Telemetry Overview

The packet capture was ingested and analyzed using **Brim Security**, leveraging its underlying powerful log parsing engines:

* **Zeek (formerly Bro):** Utilized for deep packet inspection, sessionization, and generating protocol-specific transaction logs (e.g., `conn`, `dns`, `files`, `http`).
* **Suricata:** Utilized as an Intrusion Detection System (IDS) to match network streams against known malicious signatures and generate actionable `alert` logs.
* **ZQL (Zeek Query Language):** Employed to filter, aggregate, and correlate telemetry data across millions of network events rapidly.

---

## 3. Threat Hunting Log & ZQL Analysis

### Finding A: Suspicious File Transfer & Privacy Violation

* **The Objective:** Identify anomalous file downloads and investigate triggered Suricata alerts related to corporate policy violations.
* **The ZQL Query:**
```zql
# Extracting suspicious file names from the files log
_path=="files" | filename!=null | cut filename | sort | uniq

# Investigating the specific Suricata privacy alert
event_type=="alert" | alert.category=="Potential Corporate Privacy Violation" | cut alert.signature_id

```


* **Query Logic:** The first query filters the Zeek `files` log to extract and deduplicate all observed filenames in the traffic. The second isolates Suricata alerts categorized as privacy violations to extract the unique signature ID for SIEM integration.
* **The Finding:** The telemetry revealed the transfer of a highly suspicious file named `cat01_with_hidden_text.gif`, suggesting potential steganography or data obfuscation. Concurrently, a Suricata alert was triggered for a privacy violation under the Signature ID **2012887**.

### Finding B: CobaltStrike & Secondary C2 Identification

* **The Objective:** Isolate advanced persistent threat (APT) activity, specifically looking for payload delivery and C2 beaconing patterns.
* **The ZQL Query:**
```zql
# Identifying the downloaded payload
_path=="files" | mime_type=="application/x-dosexec" | cut filename, rx_hosts, tx_hosts

# Quantifying encrypted C2 connections
_path=="conn" | id.resp_p==443 | count()

```


* **Query Logic:** The files query isolates Windows executables (`x-dosexec`) traversing the network to pinpoint the exact payload dropped. The connection query aggregates the total number of HTTPS/TLS connections on port 443 to gauge the volume of encrypted beaconing.
* **The Finding:** Traffic analysis confirmed the download of a malicious executable named `4564.exe`, attributed to a **CobaltStrike** deployment. Furthermore, the telemetry showed exactly **328** connections utilizing port 443, indicative of active CobaltStrike HTTPS beaconing. Deep packet inspection also revealed a concurrent secondary C2 channel established by the **IcedID** banking trojan infrastructure.

### Finding C: Resource Hijacking (Cryptomining)

* **The Objective:** Investigate anomalous outbound connections to non-standard ports indicative of cryptomining or rogue infrastructure communication.
* **The ZQL Query:**
```zql
# Analyzing unauthorized connections on non-standard ports
_path=="conn" | id.resp_p==19999 | count()

# Identifying the protocol masking on port 6666
_path=="conn" | id.resp_p==6666 | cut service | sort | uniq

# Calculating total data exfiltrated to the adversary IP
_path=="conn" | id.resp_h==101.201.172.235 and id.resp_p==8888 | put total_bytes := orig_bytes + resp_bytes | sum(total_bytes)

```


* **Query Logic:** These queries are designed to hunt for specific behavioral patterns associated with cryptojacking: counting connections to high-ephemeral ports (19999), determining the underlying application layer protocol on port 6666 via Zeek's protocol analyzers, and calculating the exact byte count transferred to a known malicious node.
* **The Finding:** The host initiated **22** anomalous connections over port 19999. Furthermore, port 6666 was identified as utilizing the **IRC (Internet Relay Chat)** service, a common protocol for coordinating botnets and cryptominers. The host successfully transferred exactly **3729 bytes** of data to the adversary-controlled IP `101.201.172.235` over port 8888. This aligns directly with MITRE ATT&CK Tactic **TA0040** (Impact / Resource Hijacking).

---

## 4. Malware & Payload Delivery Analysis

The observed network traffic illustrates a classic defense evasion and execution chain. Initial access or lateral movement likely resulted in the download of obfuscated or suspicious artifacts (e.g., `cat01_with_hidden_text.gif`). This was followed by a hard execution phase, dropping a CobaltStrike payload (`4564.exe`) which immediately began aggressive beaconing over port 443.

The presence of the **IcedID** banking trojan acting as a secondary C2 suggests a "malware-as-a-service" deployment model, where initial access brokers hand off the infected host to affiliate operators. Ultimately, the threat actors monetized the compromise by deploying cryptomining malware, utilizing legacy IRC channels for command execution and botnet synchronization.

---

## 5. Indicators of Compromise (IOCs)

| Indicator Type | Value | Context |
| --- | --- | --- |
| **File Name** | `4564.exe` | CobaltStrike Payload |
| **File Name** | `cat01_with_hidden_text.gif` | Suspected Steganography/Obfuscation |
| **Malware Family** | `IcedID` | Secondary C2 Channel |
| **Malware Family** | `CobaltStrike` | Primary Beaconing / Payload |
| **External IP** | `101.201.172.235` | Malicious node (Cryptomining/C2) |
| **Network Port** | `8888` | Data transfer to 101.201.172.235 |
| **Network Port** | `6666` | Malicious IRC Communications |
| **Network Port** | `19999` | Anomalous Outbound Connections |
| **Suricata SID** | `2012887` | Potential Corporate Privacy Violation |

---

## 6. Incident Disposition & SOC Recommendations

**Disposition:** True Positive - Multi-stage Malware Infection.

**Immediate Blue Team Actions:**

1. **Endpoint Isolation:** Immediately sever the affected internal host from the corporate network to halt CobaltStrike beaconing, IcedID communications, and IRC botnet synchronization.
2. **Perimeter Blocking:** Implement egress firewall rules to block all traffic to `101.201.172.235` and restrict outbound IRC traffic (port 6666) enterprise-wide.
3. **SIEM / IDS Updates:** Ingest Suricata Signature ID `2012887` into the primary SIEM (e.g., Wazuh/ELK) dashboard and configure high-priority alerting for future occurrences.
4. **Enterprise Threat Hunt:** Query EDR telemetry across all endpoints for the presence, execution, or file hashes associated with `4564.exe` and `cat01_with_hidden_text.gif`.
5. **DNS Sinkholing:** Review DNS logs corresponding to the encrypted 443 traffic to identify the specific CobaltStrike and IcedID domains, adding them to the corporate DNS sinkhole.
