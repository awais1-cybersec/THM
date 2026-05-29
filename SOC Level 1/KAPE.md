<h1 align="center">Forensic Triage and Artifact Analysis Report</h1>
<p align="center"><i>Insider Threat & AUP Violation</i></p>

<br>

## Executive Summary
This report details the rapid digital forensic triage and analysis of an endpoint suspected of violating the organization's Acceptable Use Policy (AUP). The scope of the investigation focused on determining unauthorized usage of removable media, connection to unapproved networks, and the execution of unvetted software from network shares. 

To ensure minimal disruption to business operations while maintaining evidentiary integrity, the **Kroll Artifact Parser and Extractor (KAPE)** was utilized. KAPE allowed for the rapid targeted collection and processing of critical Windows artifacts, successfully confirming multiple AUP violations, including unauthorized USB storage attachment, shadow IT software installations, and unapproved network bridging.

---

## Forensic Toolset Overview (KAPE)
The investigation leveraged KAPE to automate the collection and parsing of volatile and non-volatile artifacts. KAPE operates on a highly efficient, two-pronged architecture:
* **Targets (`.tkape`):** Define *what* to collect. Targets dictate the file paths, extensions, and specific forensic artifacts (e.g., Registry Hives, Event Logs, Prefetch) to be acquired from the live system or mounted image.
* **Modules (`.mkape`):** Define *how* to process the collected data. Modules execute secondary analytical binaries (such as Eric Zimmerman’s tools) against the collected Targets, parsing raw data into structured, human-readable formats (CSVs) for immediate timeline generation.

By segregating collection from processing, KAPE ensures that the forensic footprint remains minimal while accelerating the time-to-analysis.

---

## Data Collection (Triage Phase)
The initial triage phase was executed via an elevated command shell to bypass active OS file locks and ensure a comprehensive capture of system artifacts. 

The **`KapeTriage`** compound Target was deployed to acquire a broad spectrum of critical system data, including execution evidence (Prefetch, AmCache, RecentApps) and systemic configuration data (Registry Hives).

**Execution Parameters:**
* **Target Selection:** `KapeTriage` (Compound collection of essential Windows artifacts).
* **Collection Integrity:** Destination folders were appended with `%d` (Timestamp) and `%m` (Machine Name) variables to ensure strict evidence isolation and chain-of-custody tracking.
* **Execution Syntax (Standardized):** `kape.exe --tsource C: --target KapeTriage --tdest C:\Triage_Acquisition\%m_%d --tflush`

---

## Artifact Parsing & Timeline Creation
Following data acquisition, the raw artifacts were processed to extract actionable intelligence. The **`!EZParser`** compound Module was executed against the Target destination.

This module automates the execution of specialized parsers against the raw triage data, converting binary Registry hives and execution logs into structured `.csv` files. The resulting parsed data was then analyzed utilizing `EZViewer` to cross-reference timestamps, hardware serials, and execution paths, allowing for the rapid reconstruction of the user's activity timeline.

---

## Investigation Log & Findings

The forensic analysis of the parsed artifacts yielded concrete evidence of multiple policy violations. The key forensic discoveries are documented below:

### 1. Unauthorized Peripheral Devices (USBSTOR)
Analysis of the `SYSTEM` registry hive confirmed the attachment of unauthorized removable mass storage devices. 
* **Artifact Source:** `SYSTEM\CurrentControlSet\Enum\USBSTOR`
* **Discovery:** Two distinct USB mass storage devices were identified. 
    * Device 1 Serial Number: `0123456789ABCDE`
    * Device 2 Serial Number: `1C6F654E59A3B0C179D366AE`
* **Lateral Context:** Jump list analysis via the `AutomaticDestinations` artifact revealed that external executables (including the forensic toolset itself during testing) were staged and executed directly from the removable drive assigned to the **`E:\`** volume.

### 2. Unauthorized Software Execution & Network Drives
Analysis of the `NTUSER.DAT` hive revealed the execution of unvetted binaries from an unapproved mapped network location.
* **Artifact Source:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`
* **Discovery:** Multiple unapproved applications (7zip, Google Chrome, Mozilla Firefox) were installed directly from a remote share.
* **Staging Directory:** Applications were executed from the mapped network drive path: **`Z:\setups`**.
* **Execution Timestamp:** `CHROMESETUP.EXE` was executed on **11/25/2021 at 03:33**.

### 3. Suspicious Search Activity
Review of the user's Explorer search history indicated an attempt to locate and potentially execute an anomalous script.
* **Artifact Source:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`
* **Discovery:** The user explicitly searched the local file system for the script **`RunWallpaperSetup.cmd`**.

### 4. Unapproved Network Connections
The system's network profile history was reviewed to identify unauthorized external connections.
* **Artifact Source:** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` (Parsed via `KnownNetworks` module).
* **Discovery:** The endpoint successfully authenticated and connected to an unknown external network identified as **"Network 3"**. The initial connection was established on **11/30/2021 at 15:44**.

---

## SOC & Threat Hunting Integration

The granular artifacts recovered during this forensic triage provide immediate, high-fidelity indicators that must be operationalized to harden the enterprise's Blue Team defenses. 

To transition from reactive forensics to proactive defense, the following detection engineering and threat hunting initiatives are recommended:

* **SIEM Rule Development (Execution Anomalies):** Implement real-time monitoring and alerting for Windows Security Event ID 4688 (Process Creation). Rules should specifically flag execution originating from anomalous volume letters (e.g., `Z:\` or `E:\`) or paths matching `*\setups\*.exe` to immediately detect shadow IT deployments.
* **YARA / EDR Sweeps:** Deploy enterprise-wide hunts for the artifact `RunWallpaperSetup.cmd`. The presence of this script on other endpoints may indicate lateral movement or a wider persistence mechanism masquerading as a benign configuration file.
* **Policy Enforcement (GPO):** The extraction of unauthorized USB serials highlights a gap in peripheral device controls. Group Policy Objects (GPOs) or endpoint DLP solutions should be strictly enforced to block all generic USB mass storage devices, enforcing an allow-list-only architecture.
* **Anomaly Detection Baselines:** Integrating the frequency of new network profile generation and USB insertion events into a telemetry dataset can allow for the deployment of real-time machine learning models (such as LSTM autoencoders). This shifts the posture from manual forensic validation to automated anomaly detection, alerting the SOC the moment a deviation from the user's baseline behavior occurs.
