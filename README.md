<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<h1 align="center">Scenario 3: Suspected Data Exfiltration by Employee on PIP</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-00B388?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-PowerShell-2C5EA8?style=for-the-badge&logo=powershell&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Insider%20Threat%20Detection-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

##  Project Objective
> Investigate signs of data exfiltration from a potentially disgruntled employee (John Doe) placed on a performance improvement plan (PIP). Use MDE telemetry to examine compression, archiving, and suspicious PowerShell activities, with TTP mapping to MITRE ATT&CK.

---

##  Tools & Technologies
- **Platform:** Azure VM
- **OS:** Windows 10
- **Tools:** Microsoft Defender for Endpoint, PowerShell, Log Analytics
- **Languages/Scripts:** PowerShell, KQL

---

##  Skills Gained / Focus Areas
- Threat hunting using Microsoft Defender tables (`DeviceFileEvents`, `DeviceProcessEvents`)
- Anomaly detection in process behavior
- TTP mapping using MITRE ATT&CK
- Insider threat investigation methodology

---

##  Environment Setup
> Created a Windows 10 VM (`cavada-cyber-pc`) and simulated suspicious archiving behavior using PowerShell and 7-Zip.

> Employee under investigation: `John Doe`  
> Device: `cavada-cyber-pc`

---

##  Walkthrough

### ✅ Step 1: Preparation
> **Hypothesis:** John Doe may attempt to archive sensitive company files and exfiltrate them using cloud sync or removable drives.

---

### ✅ Step 2: Data Collection
> Searched for `.zip` file activity:
```kql
DeviceFileEvents
| where DeviceName == "cavada-cyber-pc"
| where FileName endswith ".zip"
| order by Timestamp desc
```

---

### ✅ Step 3: Data Analysis
> Focused on zip file timestamp: `2025-07-11T19:57:40.9253485Z`  
> Correlated with surrounding process activity:
```kql
let VMName = "cavada-cyber-pc";
let specificTime = datetime(2025-07-11T19:57:40.9253485Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

> ✅ Discovery: A PowerShell script silently installed 7-Zip (`msiexec.exe /quiet`) and used it to create archive files at regular intervals.

---

### ✅ Step 4: Investigation
- Detected periodic `.zip` file creation in backup folder.
- Identified PowerShell execution chaining with MSI installation and 7-Zip usage.
- Behavior aligns with several MITRE TTPs (see below).
- No immediate signs of external exfiltration (e.g., cloud storage, FTP, C2 traffic).

---

### ✅ Step 5: Response
- Reported findings to management.
- No current action recommended until further instructions are provided.
- Endpoint has not shown active exfiltration but should remain monitored.

---

### ✅ Step 6: Documentation
- Archived relevant logs and queries.
- Saved evidence of 7-Zip installation via PowerShell.
- Noted timing correlation between `.zip` creation and PowerShell activity.
- No exfiltration traffic confirmed; further review recommended.

---

### ✅ Step 7: Improvement
- Restrict PowerShell script execution for high-risk users.
- Block installation of unauthorized compression tools like 7-Zip.
- Monitor `.zip` creation combined with cloud upload or USB activity.
- Implement DLP policies for sensitive file movement.

---

##  Timeline Summary and Findings
- `.zip` files detected on `cavada-cyber-pc`, moved to backup folder.
- Installed 7-Zip silently via PowerShell script using `msiexec.exe`.
- Created zip archives at regular intervals.
- No exfiltration traffic observed, but activity matches staging behaviors.

---

##  MITRE ATT&CK TTP Mapping

| Tactic               | Technique ID & Name                                                                 | Description |
|----------------------|--------------------------------------------------------------------------------------|-------------|
| **Defense Evasion**  | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)            | PowerShell script was used to automate actions, including installing and executing 7-Zip. |
| **Defense Evasion**  | [T1218.005 – MSIExec](https://attack.mitre.org/techniques/T1218/005/)               | 7-Zip was silently installed using `msiexec.exe`, a trusted Windows utility. |
| **Collection**       | [T1560.001 – Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)   | Files were regularly compressed into `.zip` archives using 7-Zip. |
| **Command & Control** (potential) | [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)              | If 7-Zip or the script was downloaded remotely, this technique may apply. |
| **Exfiltration** (potential)     | [T1567.001 – Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/001/) <br> [T1048 – Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) | Although no exfil was confirmed, regular archiving behavior may indicate staging for future data transfer. |

>  **Note:** No direct evidence of exfiltration was found, but further review of outbound traffic, cloud sync usage, and PowerShell script origins is recommended.

---

## 📎 References
- [T1560.001 – Archive via Utility (MITRE)](https://attack.mitre.org/techniques/T1560/001/)
- [T1059.001 – PowerShell (MITRE)](https://attack.mitre.org/techniques/T1059/001/)
- [T1218.005 – MSIExec (MITRE)](https://attack.mitre.org/techniques/T1218/005/)
- [Microsoft Defender Advanced Hunting Docs](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)

