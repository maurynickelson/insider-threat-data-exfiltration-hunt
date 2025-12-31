# Threat Hunt: Insider Threat – Data Staging & Suspected Exfiltration

## Project Overview
This project documents a simulated insider threat investigation conducted using Microsoft Defender for Endpoint (MDE). The scenario focused on identifying potential data exfiltration activity by an employee with elevated privileges following behavioral risk indicators.

The objective was to determine whether sensitive company data was being staged and exfiltrated from a corporate Windows endpoint and to assess detection gaps and response effectiveness.

---

## Environment & Tools
- Endpoint: Windows 10 VM (`notengo`)
- Security Platform: Microsoft Defender for Endpoint (MDE)
- Data Sources:
  - DeviceProcessEvents
  - DeviceFileEvents
  - DeviceNetworkEvents
- Analysis Language: Kusto Query Language (KQL)

---

## Threat Scenario
An employee in a sensitive role (John Doe) was placed on a Performance Improvement Plan (PIP) and exhibited concerning behavior toward management. Due to the elevated risk of insider data theft, security leadership requested a proactive threat hunt to ensure no proprietary data was being removed.

Key risk factors:
- Local administrator privileges
- No application restrictions
- Access to sensitive employee data
- Potential motive for data theft

---

## Hypothesis
The user may attempt to:
- Compress or archive sensitive data
- Stage files locally
- Exfiltrate data using cloud storage or outbound HTTPS traffic

---

## Investigation Methodology
The investigation began with file-based detection of ZIP creation activity and pivoted to process and network telemetry using timestamp-based correlation.

---

### Step 1: Identify ZIP File Creation Activity
```kql
// Identify ZIP file creation activity on the device
DeviceFileEvents
| where DeviceName == "notengo"
| where FileName endswith ".zip"
| order by Timestamp desc
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
```
---

### Step 2: Correlate Process Activity Around ZIP Creation
After identifying ZIP file creation activity, I pivoted to process telemetry to determine what initiated the archive creation. I selected a specific ZIP creation timestamp and searched for any process activity occurring within a ±2 minute window.

```kql
// Correlate process activity +/- 2 minutes around ZIP creation
let specificTime = datetime(2025-12-26T20:53:09.8520073Z);
DeviceProcessEvents
| where DeviceName == "notengo"
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| order by Timestamp desc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```
![ZIP file creation evidence](images/Screenshot%202025-12-26%20131209.png)

Findings:
PowerShell activity was observed during this time window. The script bypassed execution policy restrictions, downloaded external content, silently installed 7-Zip, and invoked it to archive employee-related data.

### Step 2b: Correlate File System Activity in the Same Time Window
To confirm data staging behavior, I reviewed file system activity during the same timeframe

```kql
// Correlate file system activity in the same time window
let specificTime = datetime(2025-12-26T20:53:09.8520073Z);
DeviceFileEvents
| where DeviceName == "notengo"
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| order by Timestamp desc
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
```
![Investigation screenshot showing network activity](images/Screenshot%202025-12-30%20160543.png)

Finding:
Multiple ZIP files containing employee-related data were created and staged locally, consistent with data preparation for potential exfiltration.
---

### Step 3: Review Network Activity for Exfiltration
Next, I examined outbound network activity during the same time window to determine whether any data exfiltration occurred.
```kql
// Review outbound network activity for evidence of exfiltration
let specificTime = datetime(2025-12-26T20:53:09.8520073Z);
DeviceNetworkEvents
| where DeviceName == "notengo"
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol, ActionType
```
Finding:
Outbound traffic consisted of normal, short-lived HTTPS connections with ephemeral port usage. No evidence of sustained data transfer or bulk exfiltration was identified.
---

# MITRE ATT&CK Mapping
| Tactic              | Technique                                     | ID        | Evidence                                   | Assessment   |
| ------------------- | --------------------------------------------- | --------- | ------------------------------------------ | ------------ |
| Execution           | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell used to execute scripts         | Confirmed    |
| Command and Control | Ingress Tool Transfer                         | T1105     | Script downloaded from GitHub              | Confirmed    |
| Defense Evasion     | Modify Execution Policy                       | T1562.001 | Execution policy bypass                    | Confirmed    |
| Collection          | Archive Collected Data                        | T1560.001 | 7-Zip used to compress data                | Confirmed    |
| Collection          | Data Staged: Local Data Staging               | T1074.001 | ZIP files staged locally                   | Confirmed    |
| Defense Evasion     | Masquerading                                  | T1036     | Data placed in a “backup” directory        | Suspected    |
| Initial Access      | Valid Accounts                                | T1078     | Activity used legitimate admin credentials | Confirmed    |
| Exfiltration        | Exfiltration Over C2 Channel                  | T1041     | Network traffic reviewed                   | Not Observed |

---

## Incident Response (NIST-Aligned)

### Preparation
- Formed an initial hypothesis centered on potential insider data theft following employee behavioral concerns
- Verified telemetry availability across Microsoft Defender for Endpoint tables:
  - DeviceProcessEvents
  - DeviceFileEvents
  - DeviceNetworkEvents

### Detection and Analysis
- Identified PowerShell scripting activity executing with execution policy bypass
- Observed external script download and local execution
- Detected silent installation and execution of 7-Zip used to archive employee-related data
- Correlated process, file, and network telemetry within tight time windows
- Reviewed outbound network activity and found no sustained or abnormal data transfer indicative of successful exfiltration

### Containment
- Immediately isolated the endpoint to prevent further activity
- Escalated findings to management and HR
- Preserved logs and artifacts to support further review and potential disciplinary action

### Eradication
- No malware was detected on the endpoint
- Activity attributed to misuse of legitimate administrator credentials
- Unauthorized scripting and archiving behavior addressed through policy enforcement and access review

### Recovery
- Endpoint and associated user account placed under heightened monitoring
- No further suspicious activity observed following containment
- Next steps deferred to management and HR for administrative action
---

## Final Assessment
Although no data exfiltration was confirmed, the observed activity represented a credible insider threat. Sensitive employee-related data was staged locally using legitimate administrative credentials and commonly available tools, reducing detection visibility and increasing organizational risk. The use of PowerShell with execution policy bypass and silent installation of archive utilities indicates deliberate preparation for potential data removal. The response was proportional and appropriate, balancing technical containment with escalation to management and HR.

---

## Lessons Learned & Improvements

### Detection Enhancements
- Implement alerts for PowerShell execution with `ExecutionPolicy Bypass`
- Alert on silent installation or execution of archive and compression utilities
- Correlate scripting activity with mass file compression events to detect data staging earlier

### Insider Threat Controls
- Reduce unnecessary local administrator privileges where operationally feasible
- Monitor and restrict outbound access to cloud storage and external file-sharing services
- Leverage user behavior analytics (UBA) to identify anomalous scripting and file access patterns

### Hunting and Process Improvements
- Standardize time-based correlation workflows across process, file, and network telemetry
- Establish baselines for legitimate archive and backup behavior to reduce false positives
- Formalize insider threat escalation and coordination procedures with HR and Legal teams
---

## Key Takeaways
- Data staging activity can occur without confirmed data exfiltration
- Legitimate administrative credentials significantly reduce detection visibility
- File-based detection is an effective starting point for identifying insider threat behavior
- Time-based correlation across process, file, and network telemetry is critical for accurate investigation
- The use of common administrative tools can indicate malicious intent when combined with behavioral risk factors
- Insider threat investigations require both technical controls and organizational coordination




