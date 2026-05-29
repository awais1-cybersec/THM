# Network Threat Hunting & Zeek Log Triage Report

## Executive Summary

This report details a comprehensive network forensics investigation focusing on three distinct threat vectors: DNS Tunneling, Phishing infections, and Log4j (CVE-2021-44228) exploitation. By analyzing raw Packet Captures (PCAPs) generated from anomalous network traffic, the objective was to extract actionable threat intelligence, trace the attack chains, and isolate Indicators of Compromise (IOCs). The triage was conducted entirely via command-line log parsing to filter noise and identify malware beaconing, data exfiltration attempts, and post-exploitation activity.

---

## Telemetry Generation

Operating from a physically segmented lab environment running Ubuntu 24.04.4 LTS, raw PCAPs were ingested and processed using Zeek to generate structured, protocol-specific telemetry.

The standard initialization command utilized across the investigations was:

```bash
zeek -C -r <target_capture>.pcap 

```

*(Note: For the Log4j investigation, custom detection scripts were appended to the initialization: `zeek -C -r log4shell.pcapng detection-log4j.zeek`)*

This process yielded standardized, tab-separated log files (e.g., `conn.log`, `dns.log`, `http.log`, `files.log`), which were subsequently parsed using Unix utilities to extract forensic artifacts.

---

## Command-Line Analysis & Threat Hunting

### Phase 1: Anomalous DNS (DNS Tunneling)

**The Objective:** Identify signatures of DNS tunneling by analyzing query volume, connection durations, and anomalous record types used for potential data exfiltration.

**1. Identifying IPv6 DNS Records**

* **The CLI Query:**
```bash
cat dns.log | zeek-cut qtype_name | grep "AAAA" | wc -l
```


* **Query Logic:** Extracts the DNS query type field, filters exclusively for `AAAA` (IPv6) records, and counts the total lines.
* **The Finding:** Discovered **320** DNS records linked to IPv6 requests, indicating a high volume of specific record polling often used to bypass traditional IPv4 monitoring.

**2. Analyzing Connection Durations**

* **The CLI Query:**
```bash
cat conn.log | zeek-cut duration | grep -v "-" | sort -nr | head -n 1
```


* **Query Logic:** Extracts connection durations, removes null/empty values (`-`), sorts numerically in reverse (highest to lowest), and isolates the top result.
* **The Finding:** The longest connection duration recorded was **9.420791** seconds. Continuous, long-duration connections in a DNS context strongly suggest an established C2 tunnel rather than standard DNS resolution.

**3. Enumerating Unique Domain Queries**

* **The CLI Query:**
```bash
cat dns.log | zeek-cut query | sort | uniq | wc -l
```


* **Query Logic:** Isolates the exact queried domains, sorts them alphabetically, removes duplicates, and counts the unique entries.
* **The Finding:** Only **6** unique domain queries were made despite the massive volume of traffic, confirming repetitive querying to the same infrastructure.

**4. Isolating the Source Host**

* **The CLI Query:**

```bash
cat dns.log | zeek-cut id.orig_h query | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 1
```



* **Query Logic:** Extracts the originating IP and queried domains, counts occurrences per IP, sorts by highest volume, and returns the top talker.
* **The Finding:** The anomalous DNS traffic originated from **10.20.57.3**, confirming this internal host is attempting data exfiltration or C2 communication via DNS.

### Phase 2: Phishing Infection Chain

**The Objective:** Trace a phishing email payload execution, identify the malicious domains accessed, and extract the resulting malware binaries dropped on the network.

**1. Identifying the Suspicious Source**

* **The Finding:** An analysis of internal traffic anomalies pinpointed **10[.]6[.]27[.]102** as the compromised host initiating outbound malicious connections.

**2. Extracting Malicious Download Domains**

* **The CLI Query:** 

```bash
cat http.log | zeek-cut host uri | grep "." | sort | uniq
```



* **Query Logic:** Correlates HTTP host headers with requested URIs to map exactly where the compromised host navigated.
* **The Finding:** The initial malicious payload was downloaded from **smart-fax[.]com**.

**3. Payload & File Analysis**

* **The Finding:** Utilizing Zeek's `files.log` to extract file hashes and cross-referencing with VirusTotal, the initial vector was identified as a malicious **VBA** macro inside a document. This macro subsequently dropped an executable identified on VT as **PleaseWaitWindow.exe**.

**4. Post-Infection C2 Beaconing**

* **The Finding:** Further OSINT and log correlation revealed that the dropped executable attempted to establish outbound communication with **hopto[.]org**, a known dynamic DNS service often utilized for C2 infrastructure.
* **The Downloaded Executable:** The `http.log` parsing confirmed the malware was downloaded under the filename **knr.exe**.

### Phase 3: Log4J (CVE-2021-44228) Exploitation

**The Objective:** Detect active scanning for the Log4Shell vulnerability, identify the exploit delivery mechanism, and decode the executed commands.

**1. Signature Detection**

* **The CLI Query:**

```bash
cat signature.log | zeek-cut sig_id | grep "log4j" | wc -l
```

* **Query Logic:** Parses the custom Zeek signature log generated by the `detection-log4j.zeek` script and counts specific Log4j rule triggers.
* **The Finding:** Identified **3** definitive signature hits confirming active Log4Shell exploit attempts on the network.

**2. Identifying Scanning Infrastructure & Exploit Mechanics**

* **The CLI Query:**

```bash
cat http.log | zeek-cut user_agent uri | sort | uniq -c
```



* **Query Logic:** Aggregates HTTP User-Agents and requested URIs to identify automated scanning tools and payload extensions.
* **The Finding:** The threat actor utilized **NMAP** for initial reconnaissance and vulnerability scanning. The subsequent exploit payload utilized a **.class** file extension (standard Java compiled bytecode) for execution.

**3. Decoding the Payload**

* **The CLI Query:**

```bash
cat log4j.log | zeek-cut value | base64 -d
```


* **Query Logic:** Extracts the Base64-encoded JNDI strings captured in the custom `log4j.log` and pipes them into the native Linux `base64` decoding utility.
* **The Finding:** The decoded command revealed a local file creation action, specifically generating a file named **pwned**, confirming successful remote code execution (RCE).

---

## Network Artifact Analysis

* **DNS Tunneling:** The extreme ratio of requests to a limited set of 6 domains, combined with extended session durations, is a classic hallmark of DNS tunneling (e.g., Iodine or dnscat2). The threat actor leveraged the high-trust nature of DNS to sneak traffic past standard firewall rules.
* **Phishing Chain:** The attack followed a standard kill chain: Phishing Email -> VBA Macro Execution -> HTTP GET request to `smart-fax[.]com` -> Execution of `knr.exe` (PleaseWaitWindow.exe) -> C2 Beaconing to `hopto[.]org`.
* **Log4Shell:** The attacker mapped the attack surface using Nmap, injected a malicious JNDI string via HTTP headers, forced the vulnerable Java application to fetch a malicious `.class` file, and achieved RCE (evidenced by the creation of the `pwned` artifact).

---

## Indicators of Compromise (IOCs)

| IOC Type | Indicator | Threat Context |
| --- | --- | --- |
| **IP Address (Internal)** | 10.20.57.3 | Compromised host (DNS Tunneling Source) |
| **IP Address (Internal)** | 10[.]6[.]27[.]102 | Compromised host (Phishing Victim) |
| **Domain** | smart-fax[.]com | Malware Distribution Point |
| **Domain** | hopto[.]org | C2 Beaconing / Dynamic DNS |
| **Filename** | knr.exe | Initial payload downloaded via HTTP |
| **Filename** | PleaseWaitWindow.exe | VT identified malware executable |
| **File Type** | Malicious VBA | Initial access vector document |
| **File Extension** | .class | Log4j exploit payload |
| **Artifact** | pwned | File created via Log4j RCE |

---

## SOC Recommendations

1. **SIEM Rule Tuning:** Implement alerts within the SIEM (e.g., Wazuh/ELK) for excessive DNS queries originating from a single host over a short time window, specifically targeting TXT, NULL, and AAAA records.
2. **DNS Filtering & Sinkholing:** Block outbound resolution to known dynamic DNS providers (e.g., `hopto.org`) unless explicitly required by business operations. Enforce DNS over HTTPS (DoH) blocking if not managed by corporate IT to prevent bypasses.
3. **Vulnerability Management:** Immediately audit all internal Apache/Java applications for the Log4j vulnerability. Apply vendor patches and ensure Java versions are restricted from loading remote classes (`com.sun.jndi.ldap.object.trustURLCodebase=false`).
4. **Endpoint Defenses:** Hunt for the presence of `knr.exe`, `PleaseWaitWindow.exe`, and the file `pwned` across all endpoints. Ensure EDR policies are set to aggressively quarantine unsigned macros (VBA) executing child processes.
