# SC-200 Study Notes - Module 1: Microsoft Defender for Endpoint (MDE)
## 📘 Complete Guide - Updated for SC-200 Exam (April 21, 2025)

**Exam Weight:** This content supports multiple exam objectives accounting for **~15-20%** of the exam
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest Product Updates

---

## 🎯 SC-200 Exam Objectives Covered in This Module

### **From "Manage a security operations environment" (20-25%)**
- ✅ Configure settings in Microsoft Defender XDR
- ✅ Configure Microsoft Defender for Endpoint advanced features
- ✅ Configure endpoint rules settings
- ✅ Manage automated investigation and response capabilities
- ✅ Configure and manage device groups, permissions, and automation levels
- ✅ Identify unmanaged devices in Microsoft Defender for Endpoint
- ✅ Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management
- ✅ Mitigate risk by using Exposure Management in Microsoft Defender XDR

### **From "Configure protections and detections" (15-20%)**
- ✅ Configure security policies for Microsoft Defender for Endpoints, including ASR rules
- ✅ Configure and manage custom detection rules
- ✅ Configure deception rules in Microsoft Defender XDR

### **From "Manage incident response" (25-30%)**
- ✅ Respond to alerts and incidents identified by Microsoft Defender for Endpoint
- ✅ Investigate device timelines
- ✅ Perform actions on the device, including live response and collecting investigation packages
- ✅ Perform evidence and entity investigation

### **From "Manage security threats" (15-20%)**
- ✅ Identify threats by using Kusto Query Language (KQL)
- ✅ Create custom hunting queries by using KQL

---

## 📚 Table of Contents

1. [MDE Overview and Architecture](#1-mde-overview-and-architecture)
2. [Prerequisites and Requirements](#2-prerequisites-and-requirements)
3. [Deployment and Onboarding](#3-deployment-and-onboarding)
4. [MDE Plans: Plan 1 vs Plan 2](#4-mde-plans-plan-1-vs-plan-2)
5. [Advanced Features Configuration](#5-advanced-features-configuration)
6. [Device Management and Automation](#6-device-management-and-automation)
7. [Attack Surface Reduction (ASR)](#7-attack-surface-reduction-asr)
8. [Vulnerability Management](#8-vulnerability-management)
9. [Threat Response and Investigation](#9-threat-response-and-investigation)
10. [Live Response](#10-live-response)
11. [Custom Detections and Hunting](#11-custom-detections-and-hunting)
12. [Integration with Microsoft 365 Defender](#12-integration-with-microsoft-365-defender)
13. [Common Scenarios and Troubleshooting](#13-common-scenarios-and-troubleshooting)
14. [Exam Tips and Practice Questions](#14-exam-tips-and-practice-questions)

---

## 1. MDE Overview and Architecture

### What is Microsoft Defender for Endpoint?

Microsoft Defender for Endpoint (MDE) is a **cloud-powered enterprise endpoint security platform** designed to help organizations:
- **Prevent** sophisticated attacks
- **Detect** advanced threats
- **Investigate** security breaches
- **Respond** to security incidents
- **Remediate** threats automatically

### Core Capabilities (The 6 Pillars)

```
MDE Architecture
│
├─ 1️⃣ Threat & Vulnerability Management (TVM)
│   └─ Risk-based vulnerability discovery and prioritization
│
├─ 2️⃣ Attack Surface Reduction (ASR)
│   └─ First line of defense - hardening and exploit mitigation
│
├─ 3️⃣ Next-Generation Protection
│   └─ Microsoft Defender Antivirus (MDAV) - ML-powered protection
│
├─ 4️⃣ Endpoint Detection & Response (EDR)
│   └─ Advanced threat detection and behavioral analysis
│
├─ 5️⃣ Automated Investigation & Remediation (AIR)
│   └─ AI-powered automatic threat resolution
│
└─ 6️⃣ Microsoft Threat Experts
    └─ Managed threat hunting service (optional)
```

### Supported Platforms (2025)

| Platform | Version | Agent Type | Status |
|----------|---------|------------|--------|
| **Windows 11** | All versions | Built-in | ✅ Fully Supported |
| **Windows 10** | 1709+ | Built-in | ✅ Fully Supported |
| **Windows Server 2025** | RTM | Built-in | ⚠️ Limited (Oct 2025) |
| **Windows Server 2022** | All | Built-in | ✅ Fully Supported |
| **Windows Server 2019** | All | Built-in | ✅ Fully Supported |
| **Windows Server 2016** | All | **Unified Agent** | ✅ Supported |
| **Windows Server 2012 R2** | All | **Unified Agent** | ✅ Supported |
| **Windows Server 2008 R2 SP1** | All | MMA (Legacy) | ⚠️ Limited Support |
| **Windows 8.1** | Pro/Enterprise | MMA (Legacy) | ⚠️ Limited Support |
| **Windows 7 SP1** | Pro/Enterprise | MMA (Legacy) | ⚠️ Limited Support |
| **macOS** | 10.15+ (Catalina+) | MDE for Mac | ✅ Fully Supported |
| **Linux** | Various distros | MDE for Linux | ✅ Fully Supported |
| **iOS** | 14.0+ | MDE for iOS | ✅ Fully Supported |
| **Android** | 10+ | MDE for Android | ✅ Fully Supported |

**🚨 CRITICAL UPDATE (2025):**
- **MMA (Microsoft Monitoring Agent) was RETIRED August 31, 2024**
- Windows Server 2012 R2 and 2016 now use **Unified MDE Agent** (not MMA)
- Only Windows 7, 8.1, and Server 2008 R2 still require MMA (unsupported but functional)

---

## 2. Prerequisites and Requirements

### 2.1 Licensing Requirements

**Microsoft Defender for Endpoint is available in TWO plans:**

| Feature | Plan 1 | Plan 2 | Standalone |
|---------|--------|--------|------------|
| **Price** | ~$3/user/mo | ~$5.20/user/mo | Varies |
| **Included in** | M365 E3/A3 | M365 E5/A5 | Individual purchase |
| **Device limit** | 5 per user | 5 per user | 5 per user |

### 2.2 System Requirements

#### **Modern OS (Built-in EDR Sensor)**

**Windows 10/11:**
- Minimum: Version 1709 (Fall Creators Update)
- Recommended: Latest version
- Architecture: x64, x86, ARM64

**Windows Server 2019+:**
- Server 2019 (all versions)
- Server 2022 (all versions)
- Server 2025 (limited support as of Oct 2025)

**Prerequisites:**
- ✅ Windows Defender Antivirus enabled (Active or Passive mode)
- ✅ Real-time protection enabled
- ✅ Cloud-delivered protection enabled
- ✅ Internet connectivity (HTTPS 443)
- ✅ Sense service must be able to start

#### **Down-Level OS (Unified Agent Required)**

**Windows Server 2012 R2 / 2016:**

**NEW METHOD (2025):**
```
Unified MDE Agent
├─ No workspace ID/key needed
├─ Full EDR capabilities
├─ Extended feature set
└─ Onboard like modern OS
```

**Prerequisites:**
- ✅ Latest monthly rollup package installed
- ✅ Update for customer experience and diagnostic telemetry
- ✅ Servicing Stack Update (SSU) September 2021 or later
- ✅ .NET Framework 4.5 or later
- ✅ KB5005292 (MDE EDR sensor updates)

**🚨 DO NOT USE MMA - It's deprecated!**

#### **Legacy OS (MMA Required - Unsupported)**

**Windows 7 SP1, 8.1, Server 2008 R2 SP1:**

⚠️ **Warning:** MMA was retired August 31, 2024. These systems still function but are not officially supported.

**If you MUST use these (not recommended):**
- MMA Agent version 10.20.18053 or later
- Workspace ID and Key from MDE portal
- SCEP (System Center Endpoint Protection) if using MECM
- Specific monthly rollup patches
- .NET Framework updates

### 2.3 Network Requirements

#### **Required URLs (Allow HTTPS 443 Outbound)**

**Core MDE Services:**
```
*.atp.azure.com
*.blob.core.windows.net
*.oms.opinsights.azure.com
*.microsoftdefender.com
*.security.microsoft.com
```

**Security Intelligence Updates:**
```
*.update.microsoft.com
*.download.microsoft.com
*.windowsupdate.com
definitionupdates.microsoft.com
```

**Full list:** Check Microsoft Docs for complete domain list
- Documentation: `https://docs.microsoft.com/defender-endpoint/production-deployment`

#### **Proxy Configuration**

If endpoints are behind a proxy, configure using one of these methods:

**Method 1: WinHTTP Proxy (Group Policy)**
```
Computer Configuration → Administrative Templates
→ Windows Components → Data Collection and Preview Builds
→ Configure Authenticated Proxy usage for Connected User Experience
```

**Method 2: Registry**
```powershell
# Set proxy
netsh winhttp set proxy proxy.company.com:8080

# Verify
netsh winhttp show proxy
```

**Method 3: MDE Proxy Configuration**
```powershell
# Configure via registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" `
  -Name "ProxyServer" -Value "http://proxy.company.com:8080"
```

### 2.4 Permission Requirements

**Azure/Entra ID Roles Required:**

| Task | Required Role |
|------|--------------|
| **Onboard devices** | Security Administrator, Global Administrator |
| **Configure settings** | Security Administrator |
| **View alerts** | Security Reader, Security Operator |
| **Respond to alerts** | Security Operator, Security Administrator |
| **Manage roles** | Global Administrator |

**🆕 URBAC (Unified RBAC) - For customers after Feb 16, 2025:**
- New customers must use Unified Role-Based Access Control
- More granular permissions
- Cross-service role management
- Integration with Azure AD roles

---

## 3. Deployment and Onboarding

### 3.1 Onboarding Decision Tree

```
START: What OS are you onboarding?
│
├─ Windows 10/11 or Server 2019+?
│   └─ Use Onboarding Script Method
│       ├─ Group Policy
│       ├─ MECM/SCCM
│       ├─ MEM/Intune
│       └─ Local Script
│
├─ Server 2012 R2 or 2016?
│   └─ Use Unified Agent Method (NEW!)
│       ├─ Download installer from portal
│       ├─ Deploy via MECM/GPO/Script
│       └─ No workspace needed
│
└─ Server 2008 R2, Windows 7, 8.1?
    └─ Use MMA Method (Legacy - Unsupported)
        ├─ Download MMA agent
        ├─ Get Workspace ID/Key
        └─ Install with parameters
```

### 3.2 Onboarding Modern OS (Windows 10/11, Server 2019+)

#### **Step 1: Download Onboarding Package**

1. Navigate to **Microsoft Defender portal** (`security.microsoft.com`)
2. Go to **Settings** → **Endpoints** → **Onboarding**
3. Select:
   - **Operating System:** Windows 10/11 or Windows Server 1803+
   - **Deployment method:** Choose your method
4. Click **Download onboarding package**
5. Extract the ZIP file (contains `WindowsDefenderATPOnboardingScript.cmd`)

#### **Step 2: Deploy Using Group Policy**

**A. Create GPO:**
```
1. Open Group Policy Management Console (GPMC)
2. Create new GPO: "MDE Onboarding"
3. Link to target OU (Workstations or Servers)
```

**B. Configure Startup Script:**
```
GPO Settings:
Computer Configuration
└─ Policies
   └─ Windows Settings
      └─ Scripts (Startup/Shutdown)
         └─ Startup
            → Add Script
            → Browse to WindowsDefenderATPOnboardingScript.cmd
            → OK
```

**C. Apply and Verify:**
```powershell
# Force GP update on test machine
gpupdate /force

# Wait for reboot or trigger startup script
# Verify sensor status
Get-Service -Name Sense

# Check onboarding status
Get-MpComputerStatus
```

#### **Step 3: Deploy Using MECM (Configuration Manager)**

**Current Branch 2207+ supports MDE Client:**

**A. Create Application:**
```
1. Console: Software Library → Applications → Create Application
2. Type: Script Installer
3. Content Location: Path to onboarding script
4. Install Command: WindowsDefenderATPOnboardingScript.cmd
5. Detection Method: Custom script or file/folder
```

**B. Detection Script (PowerShell):**
```powershell
# Detection method
$sense = Get-Service -Name Sense -ErrorAction SilentlyContinue
if ($sense.Status -eq "Running") {
    Write-Output "Detected"
    exit 0
} else {
    exit 1
}
```

**C. Deploy to Collection:**
```
1. Right-click application → Deploy
2. Select target collection
3. Purpose: Required
4. Schedule: As soon as possible
5. User experience: Install for system, whether or not user is logged on
```

#### **Step 4: Deploy Using Intune (MEM)**

**A. Create Configuration Profile:**
```
1. Endpoint Security → Microsoft Defender for Endpoint
2. Platform: Windows 10 and later
3. Profile type: Microsoft Defender for Endpoint
4. Create profile
```

**B. Configure Settings:**
```
Configuration settings:
- Onboarding blob: [Paste from portal]
- Auto-onboarding: Enabled
- Sample sharing: Enabled
- Telemetry reporting frequency: Expedited
```

**C. Assign to Groups:**
```
1. Assignments → Add groups
2. Select Azure AD security groups
3. Include/exclude as needed
4. Save and deploy
```

### 3.3 Onboarding Down-Level Servers (2012 R2 / 2016)

**🆕 NEW METHOD (2025) - Unified Agent**

#### **Step 1: Download Unified Agent Installer**

```
1. Go to security.microsoft.com
2. Settings → Endpoints → Onboarding
3. Select: Windows Server 2012 R2 and 2016
4. Download installer package
```

#### **Step 2: Deploy Unified Agent**

**Option A: MECM Deployment (Recommended for Scale)**

```
1. Create Application in MECM
2. Content: md4ws_installer.msi (from downloaded package)
3. Install command:
   msiexec /i md4ws_installer.msi /quiet /qn
4. Detection: Check for "Microsoft Defender for Endpoint" service
5. Deploy to Server 2012 R2 / 2016 collection
```

**Option B: PowerShell Script (Manual/Small Scale)**

```powershell
# Download and install unified agent
$installerPath = "\\server\share\md4ws_installer.msi"

# Install silently
Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /qn" -Wait

# Verify installation
Get-Service | Where-Object {$_.DisplayName -like "*Defender*"}

# Wait for onboarding to complete (may take 5-15 minutes)
Start-Sleep -Seconds 300

# Check status
Get-MpComputerStatus
```

#### **Step 3: Verify Onboarding**

```powershell
# Check if Sense service is running
Get-Service -Name Sense

# Expected output:
# Status   Name               DisplayName
# ------   ----               -----------
# Running  Sense              Windows Defender Advanced Threat Protection Service

# Verify in portal (takes 10-20 minutes)
# Go to security.microsoft.com → Devices inventory
# Look for your server with "Healthy" status
```

**Key Differences from MMA Method:**
- ✅ No workspace ID/key needed
- ✅ Full EDR capabilities (same as modern OS)
- ✅ Extended feature set
- ✅ Simpler deployment
- ✅ Better performance

### 3.4 Legacy OS Onboarding (Not Recommended)

**⚠️ For Windows 7, 8.1, Server 2008 R2 ONLY (MMA - Deprecated)**

**Only use if:**
- Cannot upgrade OS
- Understand MMA is unsupported since Aug 2024
- Willing to accept limited capabilities

**Quick Steps (if absolutely necessary):**

1. Download MMA: `https://go.microsoft.com/fwlink/?LinkId=828603` (64-bit)
2. Get Workspace ID and Key from MDE portal (Settings → Onboarding)
3. Install:
```cmd
MMASetup-AMD64.exe /c /t:C:\Temp\MMA
cd C:\Temp\MMA
setup.exe /qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 ^
  OPINSIGHTS_WORKSPACE_ID="<workspace-id>" ^
  OPINSIGHTS_WORKSPACE_KEY="<workspace-key>" ^
  AcceptEndUserLicenseAgreement=1
```

**Better Alternative:** Plan OS upgrade to Windows 10/11 or Server 2019+

---

## 4. MDE Plans: Plan 1 vs Plan 2

### 4.1 Overview

**SC-200 Exam Focus:** The exam primarily tests **Plan 2** features (EDR, AIR, Advanced Hunting).

### 4.2 Detailed Comparison

| Capability | Plan 1 | Plan 2 | Importance for SC-200 |
|------------|--------|--------|----------------------|
| **Next-Generation Protection (MDAV)** | ✅ Full | ✅ Full | ⭐⭐⭐⭐ High |
| **Attack Surface Reduction (ASR) Rules** | ✅ Full | ✅ Full | ⭐⭐⭐⭐⭐ Critical |
| **Device Control** | ✅ Full | ✅ Full | ⭐⭐⭐ Medium |
| **Network Protection** | ✅ Full | ✅ Full | ⭐⭐⭐⭐ High |
| **Firewall Management** | ✅ Full | ✅ Full | ⭐⭐⭐ Medium |
| **Application Control** | ✅ Full | ✅ Full | ⭐⭐⭐ Medium |
| **Web Protection** | ✅ Full | ✅ Full | ⭐⭐⭐ Medium |
| **Manual Response Actions** | ✅ Limited | ✅ Full | ⭐⭐⭐⭐ High |
| | | | |
| **EDR (Endpoint Detection & Response)** | ❌ No | ✅ Full | ⭐⭐⭐⭐⭐ **CRITICAL** |
| **Automated Investigation & Remediation** | ❌ No | ✅ Full | ⭐⭐⭐⭐⭐ **CRITICAL** |
| **Advanced Hunting (KQL)** | ❌ No | ✅ Full | ⭐⭐⭐⭐⭐ **CRITICAL** |
| **Threat Analytics** | ❌ No | ✅ Full | ⭐⭐⭐⭐ High |
| **Device Discovery** | ❌ No | ✅ Full | ⭐⭐⭐⭐ High |
| **Core Vulnerability Management** | ❌ No | ✅ Included | ⭐⭐⭐⭐⭐ **CRITICAL** |
| **Threat Intelligence** | ❌ No | ✅ Full | ⭐⭐⭐⭐ High |
| **Live Response** | ❌ No | ✅ Full | ⭐⭐⭐⭐⭐ **CRITICAL** |
| **Deep Analysis (Sandbox)** | ❌ No | ✅ Full | ⭐⭐⭐⭐ High |
| **Microsoft 365 Defender XDR** | ❌ Limited | ✅ Full | ⭐⭐⭐⭐⭐ **CRITICAL** |
| **Incident Correlation** | ❌ No | ✅ Full | ⭐⭐⭐⭐⭐ **CRITICAL** |
| **Unified Queue** | ❌ No | ✅ Full | ⭐⭐⭐⭐ High |

### 4.3 What Plan 1 Can Do (Prevention Only)

**Use Case:** Replace traditional antivirus, basic endpoint protection

**Capabilities:**
- ✅ Real-time malware protection
- ✅ Behavioral monitoring
- ✅ Cloud-delivered protection
- ✅ Block common attack techniques (ASR rules)
- ✅ Control USB devices
- ✅ Block malicious websites and downloads
- ✅ Configure Windows Firewall
- ✅ Manual isolation of compromised devices
- ✅ Manual quarantine of files

**What it CANNOT do:**
- ❌ **No EDR alerts or telemetry**
- ❌ **No automated investigation**
- ❌ **No advanced hunting with KQL**
- ❌ **No vulnerability management**
- ❌ **No threat analytics**
- ❌ **No live response**

### 4.4 What Plan 2 Adds (Detection, Investigation, Response)

**Use Case:** Full SOC operations, threat hunting, incident response

**🔥 Key Plan 2 Exclusive Features (Exam Focus):**

#### **1. Endpoint Detection & Response (EDR)**
```
EDR Capabilities:
├─ Behavioral analytics
├─ Attack detection
├─ Forensic timeline
├─ Process tree analysis
├─ Network connections tracking
└─ File activity monitoring
```

**Example EDR Alert:**
- Event: PowerShell executed suspicious command
- Context: Parent process, command line, user context
- Timeline: Full chain of events
- Evidence: Files, registry keys, network connections

#### **2. Automated Investigation & Remediation (AIR)**

**How AIR Works:**
```
1. Alert Triggers
   ↓
2. Automated Investigation Starts
   ├─ Collect evidence
   ├─ Analyze artifacts
   ├─ Determine verdict (malicious/suspicious/clean)
   └─ Calculate confidence level
   ↓
3. Remediation Actions (if auto-remediation enabled)
   ├─ Quarantine files
   ├─ Stop processes
   ├─ Remove registry keys
   ├─ Isolate device (if needed)
   └─ Send notifications
   ↓
4. Action Center shows results
```

**Exam Scenario Example:**
```
Question: A suspicious PowerShell script is detected. What happens with AIR enabled?

Answer:
1. AIR automatically investigates:
   - Analyzes script content
   - Checks parent processes
   - Reviews files created
   - Examines registry changes
   - Checks network connections

2. If malicious:
   - Quarantines script
   - Terminates related processes
   - Removes persistence mechanisms
   - Isolates device if spreading

3. Security team reviews in Action Center
```

#### **3. Advanced Hunting (KQL)**

**What is Advanced Hunting?**
- Threat hunting using Kusto Query Language
- Query 30 days of EDR telemetry
- Create custom detection rules
- Proactive threat hunting

**Key Tables for Advanced Hunting:**
```
DeviceProcessEvents      - Process execution
DeviceNetworkEvents      - Network connections
DeviceFileEvents         - File operations
DeviceRegistryEvents     - Registry changes
DeviceLogonEvents        - Authentication events
DeviceImageLoadEvents    - DLL loading
DeviceEvents             - General security events
AlertEvidence            - Alert details
DeviceInfo               - Device inventory
```

**Example Hunt Query:**
```kql
// Find PowerShell launching suspicious processes
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "IEX" or ProcessCommandLine contains "Invoke-Expression"
| where ProcessCommandLine contains "Net.WebClient"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| limit 100
```

#### **4. Threat & Vulnerability Management (Core TVM)**

**Included in Plan 2:**
- ✅ Software inventory
- ✅ Vulnerability assessment
- ✅ Configuration assessments
- ✅ Security recommendations
- ✅ Exposure score
- ✅ Remediation tracking
- ✅ Exception management

**Premium TVM (Add-on):**
- ✅ Security baselines assessment
- ✅ Browser plugins assessment
- ✅ Certificate assessment
- ✅ Block vulnerable applications
- ✅ Advanced reporting

#### **5. Live Response**

**Capabilities:**
- Remote shell access to device
- Collect forensic evidence
- Run commands
- Upload/download files
- Undo remediation actions (new in 2025)

**Example Commands:**
```
analyzefile                 - Deep analysis of file
collect                     - Collect file for analysis
connections                 - Show network connections
findfile                    - Search for files (includes OneDrive shares - new)
getfile                     - Download file from device
processes                   - List running processes
registry                    - Query registry
remediate                   - Execute remediation script
run                         - Run command
undo                        - Undo previous remediation (new 2025)
```

### 4.5 Choosing the Right Plan

**When Plan 1 is Sufficient:**
- Small organization (<500 endpoints)
- Limited security team
- Basic protection needs
- No SOC or threat hunting
- Budget constraints

**When Plan 2 is Required (SC-200 assumes this):**
- SOC operations
- Incident response team
- Threat hunting
- Regulatory compliance (HIPAA, PCI-DSS)
- Advanced persistent threats (APT) concerns
- Integration with SIEM/SOAR

**🎯 Exam Tip:** SC-200 scenarios assume **Plan 2** unless explicitly stated otherwise. If a question asks about "investigating an incident" or "hunting for threats," these are Plan 2 features.

---

## 5. Advanced Features Configuration

### 5.1 Configure Microsoft Defender for Endpoint Advanced Features

**Exam Objective:** *Configure Microsoft Defender for Endpoint advanced features*

**Location:** Settings → Endpoints → General → Advanced features

#### **Key Advanced Features**

| Feature | Purpose | Exam Relevance |
|---------|---------|----------------|
| **Automated Investigation** | Enable AIR | ⭐⭐⭐⭐⭐ Critical |
| **Live Response** | Remote forensics | ⭐⭐⭐⭐⭐ Critical |
| **Live Response for Servers** | Enable on servers | ⭐⭐⭐⭐ High |
| **Live Response unsigned script** | Run custom scripts | ⭐⭐⭐⭐ High |
| **Autoresolve remediated alerts** | Auto-close alerts after remediation | ⭐⭐⭐⭐ High |
| **Allow or block file** | Custom indicators | ⭐⭐⭐⭐⭐ Critical |
| **Custom network indicators** | Block IPs/URLs | ⭐⭐⭐⭐⭐ Critical |
| **Tamper protection** | Prevent disabling protection | ⭐⭐⭐⭐⭐ Critical |
| **Show user details** | Show user info in alerts | ⭐⭐⭐ Medium |
| **Skype for Business integration** | Contact via Skype | ⭐⭐ Low |
| **Microsoft Defender for Cloud Apps** | MCAS integration | ⭐⭐⭐⭐ High |
| **Web content filtering** | Block websites by category | ⭐⭐⭐⭐ High |
| **Device discovery** | Find unmanaged devices | ⭐⭐⭐⭐⭐ Critical |
| **Download quarantined files** | Forensic analysis | ⭐⭐⭐ Medium |
| **Microsoft Intune connection** | Intune integration | ⭐⭐⭐⭐ High |
| **Share endpoint alerts with Microsoft Purview Compliance** | DLP integration | ⭐⭐⭐⭐ High |

#### **Configuration Example: Enable Live Response**

**Step-by-step:**
```
1. Navigate to security.microsoft.com
2. Settings → Endpoints → General → Advanced features
3. Scroll to "Live Response"
4. Toggle ON:
   ☑ Enable live response
   ☑ Enable live response for servers
   ☑ Enable live response unsigned script execution
5. Save preferences
```

**PowerShell Configuration (via Graph API):**
```powershell
# Requires Microsoft.Graph module
Connect-MgGraph -Scopes "SecurityEvents.ReadWrite.All"

# Enable live response
$body = @{
    liveResponseEnabled = $true
    liveResponseUnsignedScriptExecutionEnabled = $true
}

Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/security/advancedThreatProtection/configuration" -Body $body
```

### 5.2 Configure Alert and Vulnerability Notifications

**Exam Objective:** *Configure alert and vulnerability notification rules*

**Purpose:** Send email notifications when alerts are triggered or vulnerabilities are found.

#### **Alert Notification Rules**

**Location:** Settings → Endpoints → General → Email notifications

**Configuration Steps:**
```
1. Go to Settings → Endpoints → General
2. Select "Email notifications"
3. Click "+ Add item"
4. Configure:
   - Rule name: "Critical Alerts - SOC Team"
   - Severity: High, Medium, or Low (select multiple)
   - Device groups: All devices or specific groups
   - Email recipients: soc@company.com
   - Include organization name in email: Yes
5. Save
```

**Example Scenarios:**

**Scenario 1: SOC Team - High Severity Only**
```
Rule: "SOC Critical Alerts"
Severity: High
Device groups: All devices
Recipients: soc@company.com, security-team@company.com
```

**Scenario 2: Server Team - Servers Only**
```
Rule: "Server Alerts"
Severity: High, Medium
Device groups: Production Servers
Recipients: server-team@company.com
```

#### **Vulnerability Notification Rules**

**Configuration:**
```
1. Go to Settings → Endpoints → General
2. Select "Vulnerability email notifications"
3. Click "+ Add notification rule"
4. Configure:
   - Rule name: "Critical CVEs"
   - Severity threshold: Critical (CVSS 9.0-10.0)
   - Frequency: Weekly
   - Recipients: vulnerability-team@company.com
5. Save
```

**Best Practice:**
- Critical vulnerabilities → Daily notifications
- High vulnerabilities → Weekly notifications
- Medium/Low → Monthly summary

### 5.3 Configure Endpoint Rules Settings

**Exam Objective:** *Configure endpoint rules settings*

#### **A. Suppression Rules**

**Purpose:** Reduce alert noise by suppressing expected behaviors.

**Use Cases:**
- Administrative tools that trigger false positives
- Known safe applications
- Authorized penetration testing
- Scheduled tasks

**Create Suppression Rule:**
```
1. Go to Settings → Endpoints → Rules → Alert suppression rules
2. Click "+ Add rule"
3. Configure:
   - Rule name: "Suppress SCCM WMI Activity"
   - Alert title: Contains "WMI"
   - Device groups: SCCM Servers
   - Expiration: 90 days
   - Comments: "SCCM uses WMI for management"
4. Save
```

**Example:**
```
Scenario: Security scanner runs weekly, triggers "Port Scanning" alerts

Suppression Rule:
- Alert title: "Port scanning activity detected"
- Initiating process: nmap.exe
- Device groups: Security Scanner Hosts
- Scope: Suppress completely
```

#### **B. Custom Detection Rules**

**Purpose:** Create custom alerts based on specific behaviors.

**Example - Detect Mimikatz Execution:**

```kql
// Custom detection rule
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "mimilib.dll")
   or ProcessCommandLine has_any ("sekurlsa::logonpasswords", "lsadump::sam")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
```

**Configuration:**
```
1. Go to Settings → Endpoints → Rules → Custom detections
2. Click "+ Create rule"
3. Rule details:
   - Name: "Mimikatz Activity Detected"
   - Frequency: Real-time
   - Query: [paste KQL above]
4. Alert details:
   - Severity: High
   - Title: "Credential dumping tool detected: {{FileName}}"
   - Category: Credential Access
5. Actions:
   - Recommended: Isolate device
6. Scope: All devices or specific groups
7. Save
```

#### **C. Deception Rules (Honeytokens)**

**🆕 New in 2025:** Configure deception rules in Microsoft Defender XDR

**Purpose:** Lure attackers by creating fake credentials and monitoring their use.

**Types of Deception:**
1. **Lure accounts** - Fake user accounts
2. **Honey files** - Fake documents with embedded beacons
3. **Honey credentials** - Fake credentials in memory

**Configuration:**
```
1. Go to Settings → Endpoints → Deception
2. Select deception type: Lure accounts
3. Configure:
   - Account name: admin_backup
   - Description: "Backup administrator account"
   - Placement: Domain Controllers, File Servers
4. Alert settings:
   - Severity: High
   - Action: Automatic isolation
5. Deploy
```

**Exam Scenario:**
```
Q: An attacker compromises a workstation and starts lateral movement.
   How can deception help detect this early?

A: Deploy lure credentials on workstations. When attacker harvests
   credentials and tries to use the fake admin_backup account,
   an immediate high-severity alert triggers with automatic device isolation.
```

### 5.4 Manage Automated Investigation and Response

**Exam Objective:** *Manage automated investigation and response capabilities in Microsoft Defender XDR*

#### **Automation Levels**

**Per Device Group:**

| Level | Behavior | Use Case |
|-------|----------|----------|
| **Full automation** | Remediate automatically | Production endpoints |
| **Semi automation** | Require approval for folders/files | Servers, critical systems |
| **Semi automation (core folders)** | Auto remediate core folders only | Mixed environments |
| **No automation** | Manual remediation only | Test/dev, unsupported apps |

#### **Configure Automation Level**

**Step-by-step:**
```
1. Go to Settings → Endpoints → Permissions → Device groups
2. Select device group (or create new)
3. Set Automation level:
   - Workstations: Full automation
   - Production servers: Semi automation
   - Test servers: No automation
4. Save
```

**Example Configuration:**

```
Device Group: Corporate Workstations
├─ Automation level: Full - remediate threats automatically
├─ Members: All Windows 10/11 workstations
└─ Remediation: Automatic for all threat types

Device Group: Production SQL Servers
├─ Automation level: Semi - require approval for any folders
├─ Members: All SQL Server instances
└─ Remediation: Manual approval required

Device Group: Development Machines
├─ Automation level: No automated response
├─ Members: Developer workstations
└─ Remediation: Fully manual
```

#### **Action Center**

**Purpose:** View pending and completed automated investigations.

**Location:** Microsoft Defender Portal → Action Center

**Tabs:**
- **Pending:** Actions awaiting approval
- **History:** Completed actions
- **Unified action center:** Across all Defender products

**Common Actions:**
```
Pending Actions:
├─ Quarantine file
├─ Stop and quarantine process
├─ Isolate device
├─ Require password change
└─ Disable user account

Actions to Approve/Reject:
- Review evidence
- Check confidence level
- Approve or reject
- Add comments
```

### 5.5 Configure Automatic Attack Disruption

**🆕 Exam Objective (2025):** *Configure automatic attack disruption in Microsoft Defender XDR*

**What is Attack Disruption?**
- Automatic containment of active attacks
- Works across Microsoft 365 Defender (endpoint, identity, email, cloud apps)
- Disrupts attack chains in real-time
- Reduces dwell time

#### **How It Works**

```
Attack Detected
│
├─ 1. Correlation engine identifies attack pattern
│     (e.g., phishing email → credential compromise → lateral movement)
│
├─ 2. Automatic disruption triggers
│     ├─ Contain compromised accounts
│     ├─ Isolate affected devices
│     ├─ Block malicious IPs
│     └─ Disable compromised identities
│
└─ 3. Incident created in unified queue
      └─ Security team reviews and completes remediation
```

#### **Configuration**

**Enable Attack Disruption:**
```
1. Go to Settings → Microsoft Defender XDR → Attack disruption
2. Toggle ON: "Enable automatic attack disruption"
3. Configure exclusions:
   - Exclude specific IPs (e.g., VPN gateways)
   - Exclude service accounts
   - Exclude VIP users (with approval)
4. Save
```

**Exclusion Example:**
```
Scenario: VPN gateway IP triggering false positives

Configuration:
1. Settings → Attack disruption → Exclusions
2. Add IP exclusion:
   - IP: 203.0.113.1
   - Reason: "Corporate VPN gateway"
   - Approved by: Security Manager
   - Expiration: 365 days
3. Save
```

**🎯 Exam Tip:** Attack disruption is automatic and works across ALL Defender products (Endpoint, Identity, Office 365, Cloud Apps). It's a unified XDR capability.

---

## 6. Device Management and Automation

### 6.1 Device Groups

**Exam Objective:** *Configure and manage device groups, permissions, and automation levels in Microsoft Defender for Endpoint*

**Purpose:**
- Organize devices logically
- Apply different automation levels
- Delegate permissions
- Apply policies selectively

#### **Create Device Group**

**Step-by-step:**
```
1. Go to Settings → Endpoints → Permissions → Device groups
2. Click "+ Add device group"
3. Configure:
   - Name: "Production SQL Servers"
   - Description: "All production SQL database servers"
   - Automation level: Semi - require approval for any folders
   - Members: Define using rules
4. Define membership:
   - Device name: Contains "SQL" OR
   - Tags: Contains "Production" AND "Database" OR
   - Device value: High
5. User access (optional):
   - Assign Azure AD groups that can see these devices
6. Save
```

#### **Device Group Strategies**

**By Function:**
```
├─ Workstations
├─ Servers
│  ├─ Web Servers
│  ├─ Database Servers
│  └─ Domain Controllers
├─ VDI/Virtual Desktops
└─ Mobile Devices
```

**By Criticality:**
```
├─ Tier 0 (Domain Controllers, PAWs)
│  └─ Automation: Semi - require approval
├─ Tier 1 (Application Servers)
│  └─ Automation: Semi - core folders only
└─ Tier 2 (Workstations)
   └─ Automation: Full
```

**By Environment:**
```
├─ Production
│  └─ Automation: Semi
├─ Staging
│  └─ Automation: Full
└─ Development
   └─ Automation: No automation
```

### 6.2 Device Tags

**Purpose:** Label devices for filtering and automation.

**Common Tags:**
```
- Environment: Production, Test, Dev
- Department: Finance, HR, IT
- Criticality: High, Medium, Low
- Compliance: PCI, HIPAA, SOX
- Project: ProjectX, Migration2025
```

**Apply Tags:**

**Method 1: Portal (Individual)**
```
1. Go to Device inventory
2. Select device
3. Click "Manage tags"
4. Add tags: Production, HighValue, Finance
5. Save
```

**Method 2: API (Bulk)**
```powershell
# Requires Microsoft.Graph module
$deviceId = "device-guid-here"
$tags = @("Production", "SQLServer", "HighValue")

Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/machines/$deviceId/tags" -Body (@{ Value = $tags } | ConvertTo-Json)
```

**Method 3: Automation (Dynamic)**
```powershell
# Tag all SQL servers automatically
$devices = Get-MgDevice | Where-Object { $_.DeviceName -like "*SQL*" }

foreach ($device in $devices) {
    $tags = @("Production", "SQLServer")
    # Apply tags via API
}
```

### 6.3 Device Value

**Purpose:** Indicate business criticality of device.

**Values:**
- **Low** - Standard workstations
- **Normal** - Default value
- **High** - Servers, VIP machines
- **Critical** - Domain controllers, critical infrastructure

**Impact:**
- Influences exposure score
- Affects incident priority
- Used in device groups
- Considered by AIR

**Set Device Value:**
```
1. Device inventory → Select device
2. Click "..." → Set device value
3. Choose: Critical
4. Save
```

**Bulk Set via API:**
```powershell
# Set all domain controllers to Critical
$dcs = Get-MgDevice | Where-Object { $_.DeviceName -like "*DC*" }

foreach ($dc in $dcs) {
    Invoke-MgGraphRequest -Method POST `
      -Uri "https://graph.microsoft.com/v1.0/security/machines/$($dc.Id)/setDeviceValue" `
      -Body (@{ Value = "Critical" } | ConvertTo-Json)
}
```

### 6.4 Identify Unmanaged Devices

**Exam Objective:** *Identify unmanaged devices in Microsoft Defender for Endpoint*

**What are Unmanaged Devices?**
- Devices on network NOT onboarded to MDE
- Discovered through device discovery
- Potential security gaps
- Shadow IT

#### **Enable Device Discovery**

**Step 1: Enable Feature**
```
1. Settings → Endpoints → General → Advanced features
2. Scroll to "Device discovery"
3. Toggle ON: "Basic discovery" or "Standard discovery"
4. Save
```

**Discovery Modes:**

| Mode | Method | Coverage |
|------|--------|----------|
| **Basic** | Endpoint sensors query network | Local subnet only |
| **Standard** | Active probing via network sensors | Full network coverage |

**Step 2: View Unmanaged Devices**
```
1. Device inventory
2. Filter: Onboarding status = "Can be onboarded"
3. Review:
   - Device name
   - Last seen
   - IP address
   - Device type
   - OS
4. Select devices → "Onboard devices"
```

**Exam Scenario:**
```
Q: A security audit finds 50 devices on the network not managed by MDE.
   How do you identify and onboard them?

A:
1. Enable "Standard discovery" in advanced features
2. Wait for discovery cycle (24-48 hours)
3. Go to Device inventory
4. Filter: "Can be onboarded"
5. Select discovered devices
6. Choose onboarding method (Intune/SCCM/script)
7. Bulk onboard discovered devices
8. Verify in inventory after onboarding
```

---

## 7. Attack Surface Reduction (ASR)

### 7.1 Overview

**Exam Objective:** *Configure security policies for Microsoft Defender for Endpoints, including attack surface reduction (ASR) rules*

**What is ASR?**
Attack Surface Reduction is the **first line of defense** in MDE. It reduces vulnerabilities by:
- Hardening configurations
- Blocking risky behaviors
- Preventing exploits
- Limiting attack vectors

### 7.2 ASR Components

```
Attack Surface Reduction
│
├─ 1. ASR Rules
│   └─ Block risky behaviors (Office macros, script execution, etc.)
│
├─ 2. Network Protection
│   └─ Block malicious IP addresses, domains, URLs
│
├─ 3. Web Protection
│   └─ Block access to phishing and malware sites
│
├─ 4. Device Control
│   └─ Control removable storage and devices
│
├─ 5. Exploit Protection
│   └─ Mitigate exploitation techniques
│
└─ 6. Application Control
    └─ Allow only trusted applications
```

### 7.3 ASR Rules

**Purpose:** Block specific behaviors commonly exploited by malware.

#### **Available ASR Rules (Exam Focus)**

| Rule | GUID | Purpose | Exam Importance |
|------|------|---------|-----------------|
| **Block executable content from email client and webmail** | BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 | Prevent malware from email | ⭐⭐⭐⭐⭐ |
| **Block all Office applications from creating child processes** | D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Block Office exploit chains | ⭐⭐⭐⭐⭐ |
| **Block Office applications from creating executable content** | 3B576869-A4EC-4529-8536-B80A7769E899 | Prevent macro malware | ⭐⭐⭐⭐⭐ |
| **Block Office applications from injecting code into other processes** | 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 | Block process injection | ⭐⭐⭐⭐⭐ |
| **Block JavaScript or VBScript from launching downloaded executable content** | D3E037E1-3EB8-44C8-A917-57927947596D | Block script-based malware | ⭐⭐⭐⭐⭐ |
| **Block execution of potentially obfuscated scripts** | 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC | Block PowerShell obfuscation | ⭐⭐⭐⭐⭐ |
| **Block Win32 API calls from Office macros** | 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B | Harden Office macros | ⭐⭐⭐⭐ |
| **Block credential stealing from Windows local security authority subsystem** | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 | Prevent credential dumping (Mimikatz) | ⭐⭐⭐⭐⭐ |
| **Block process creations originating from PSExec and WMI commands** | D1E49AAC-8F56-4280-B9BA-993A6D77406C | Block lateral movement | ⭐⭐⭐⭐⭐ |
| **Block untrusted and unsigned processes that run from USB** | B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 | Control USB threats | ⭐⭐⭐⭐ |
| **Block Adobe Reader from creating child processes** | 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C | Block PDF exploits | ⭐⭐⭐ |
| **Block persistence through WMI event subscription** | E6DB77E5-3DF2-4CF1-B95A-636979351E5B | Block WMI persistence | ⭐⭐⭐⭐ |

#### **ASR Rule Actions**

| Action | Behavior | Use Case |
|--------|----------|----------|
| **Block** | Block the behavior | Production, strict security |
| **Audit** | Log only, no blocking | Testing, baseline |
| **Warn** | Show warning, allow bypass | User awareness, transition |
| **Not configured** | Disabled | Exceptions |

#### **Configure ASR Rules (Group Policy)**

**Location:**
```
Computer Configuration
└─ Administrative Templates
   └─ Windows Components
      └─ Microsoft Defender Antivirus
         └─ Microsoft Defender Exploit Guard
            └─ Attack Surface Reduction
               └─ Configure Attack Surface Reduction rules
```

**Configuration:**
```
1. Open Group Policy Management Editor
2. Navigate to: [path above]
3. Enable "Configure Attack Surface Reduction rules"
4. Click "Show..." to add rules
5. Add rule GUID and value:
   - GUID: BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550
   - Value: 1 (Block) or 2 (Audit) or 6 (Warn)
6. Repeat for each rule
7. Apply GPO to target OUs
```

**Example GPO Configuration:**
```
Rule: Block executable content from email
GUID: BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550
Value: 1 (Block)

Rule: Block Office apps creating child processes
GUID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A
Value: 1 (Block)

Rule: Block credential stealing
GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
Value: 1 (Block)
```

#### **Configure ASR Rules (Intune)**

**Method 1: Endpoint Security Policy**
```
1. Endpoint security → Attack surface reduction
2. Create policy:
   - Platform: Windows 10 and later
   - Profile: Attack surface reduction rules
3. Configure rules:
   - Block executable content from email: Block
   - Block Office apps creating child processes: Block
   - Block credential stealing: Block
   [... configure other rules ...]
4. Assign to groups
5. Deploy
```

**Method 2: Configuration Profile (Settings Catalog)**
```
1. Devices → Configuration profiles → Create profile
2. Platform: Windows 10 and later
3. Profile type: Settings catalog
4. Add settings:
   - Category: Microsoft Defender Antivirus > Attack Surface Reduction
   - Settings: [select rules]
5. Configure values (Block/Audit/Warn)
6. Assign and deploy
```

#### **Configure ASR Rules (PowerShell)**

```powershell
# Set all rules to Audit mode (for testing)
$rules = @(
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", # Email content
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Office child processes
    "3B576869-A4EC-4529-8536-B80A7769E899", # Office executable content
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", # Office code injection
    "D3E037E1-3EB8-44C8-A917-57927947596D", # Script launching executable
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Obfuscated scripts
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", # Win32 API from macros
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", # Credential stealing
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C", # PSExec and WMI
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"  # USB processes
)

# Set to Audit mode (2)
foreach ($rule in $rules) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Audit
}

# Verify
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
```

**Set to Block Mode (Production):**
```powershell
# After testing in Audit, switch to Block (1)
foreach ($rule in $rules) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Block
}
```

#### **ASR Exclusions**

**When to use exclusions:**
- Known false positives
- Business-critical applications
- Vendor software with legitimate behaviors

**Configure Exclusions (PowerShell):**
```powershell
# Exclude specific file
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Program Files\BusinessApp\app.exe"

# Exclude folder
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\TrustedApps\*"

# View exclusions
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionOnlyExclusions
```

**Configure Exclusions (Intune):**
```
1. Edit ASR policy
2. Scroll to "Attack Surface Reduction Only Exclusions"
3. Add paths:
   - C:\Program Files\BusinessApp\app.exe
   - C:\TrustedApps\*
4. Save and deploy
```

### 7.4 Network Protection

**Purpose:** Block connections to malicious IPs, domains, and URLs.

**Protection Against:**
- Phishing sites
- Malware distribution sites
- Command and control (C2) servers
- Known malicious infrastructure

#### **Enable Network Protection**

**PowerShell:**
```powershell
# Enable Network Protection
Set-MpPreference -EnableNetworkProtection Enabled

# Verify
Get-MpPreference | Select-Object EnableNetworkProtection

# Values:
# 0 = Disabled
# 1 = Enabled (Block mode)
# 2 = Audit mode
```

**Group Policy:**
```
Computer Configuration
└─ Administrative Templates
   └─ Windows Components
      └─ Microsoft Defender Antivirus
         └─ Microsoft Defender Exploit Guard
            └─ Network Protection
               └─ Prevent users and apps from accessing dangerous websites

Value: Enabled (Block mode)
```

**Intune:**
```
Endpoint Security → Attack surface reduction
→ Network filtering → Network protection
→ Enable (Block mode)
```

#### **Custom Network Indicators**

**Purpose:** Block or allow specific IPs/URLs.

**Create Indicator:**
```
1. Settings → Endpoints → Rules → Indicators
2. Click "+ Add indicator"
3. Select: IP addresses or URLs/Domains
4. Configure:
   - Indicator: 203.0.113.50 or evil.com
   - Action: Block and generate alert
   - Description: "Known C2 server"
   - Severity: High
   - Expiration: 90 days
5. Save
```

**Example Scenarios:**

**Scenario 1: Block Known C2 Domain**
```
Indicator: malware-c2.example.com
Type: URL/Domain
Action: Block and generate alert
Title: "C2 Communication Blocked"
Severity: High
Recommended response: Isolate device
```

**Scenario 2: Allow Business Partner IP**
```
Indicator: 198.51.100.25
Type: IP address
Action: Allow
Description: "Partner company VPN gateway"
Expiration: 365 days
```

### 7.5 Web Protection

**Purpose:** Block access to malicious and phishing websites.

**Categories:**
- Adult content
- Gambling
- Violence
- Drugs
- Malware/phishing (always blocked)

#### **Enable Web Protection**

**Advanced Feature:**
```
Settings → Endpoints → General → Advanced features
→ Web content filtering: ON
```

**Create Policy:**
```
1. Settings → Endpoints → Rules → Web content filtering
2. Click "+ Add policy"
3. Policy name: "Block Adult Content"
4. Scope: All devices or device groups
5. Select categories:
   ☑ Adult content
   ☑ High bandwidth
   ☑ Gambling
   [ ] Social networking (optional)
6. Save
```

**Custom URL Exclusions:**
```
1. Edit web content filtering policy
2. Add allowed sites:
   - https://businesssite.com
   - https://trustedpartner.com
3. Save
```

### 7.6 Device Control

**Purpose:** Control access to removable storage and unauthorized devices.

**Supported Device Types:**
- USB storage
- CD/DVD
- Bluetooth
- Printers

#### **Block All Removable Storage (Simple)**

**Intune:**
```
Devices → Configuration profiles → Create profile
Platform: Windows 10 and later
Profile type: Device restrictions
Settings:
- General → Removable storage: Block
Deploy to all users
```

**Group Policy:**
```
Computer Configuration
└─ Administrative Templates
   └─ System
      └─ Removable Storage Access
         → All Removable Storage classes: Deny all access

Value: Enabled
```

#### **Advanced Device Control (Granular)**

**Allow specific USB devices only:**

**Step 1: Get Device IDs**
```powershell
# List all USB devices
Get-PnpDevice | Where-Object { $_.Class -eq "USB" }

# Get hardware IDs
(Get-PnpDevice -InstanceId "USB\VID_1234&PID_5678\123456789").HardwareID
```

**Step 2: Create Policy (Intune)**
```
1. Endpoint security → Attack surface reduction
2. Profile: Device control
3. Configure:
   - Default enforcement: Block
   - Allowed device list:
     * Hardware ID: USB\VID_046D&PID_C52B (Logitech mouse)
     * Hardware ID: USB\VID_0781&PID_5567 (SanDisk approved USB)
4. Apply to device groups
```

**Exam Scenario:**
```
Q: Users need to use USB keyboards and mice, but USB storage should be blocked.
   How do you configure this?

A:
1. Create device control policy
2. Default enforcement: Block removable storage
3. Add allowed device classes:
   - HIDClass (keyboards/mice): Allow
   - DiskDrive: Block
4. Deploy via Intune/GPO to all workstations
5. Test with approved mouse (should work) and USB drive (should block)
```

### 7.7 Controlled Folder Access

**Purpose:** Protect sensitive folders from unauthorized changes by ransomware.

**Protected Folders (Default):**
- Documents
- Pictures
- Videos
- Music
- Desktop
- Favorites

#### **Enable Controlled Folder Access**

**PowerShell:**
```powershell
# Enable
Set-MpPreference -EnableControlledFolderAccess Enabled

# Add protected folder
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\SensitiveData"

# Allow application
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\App\app.exe"

# View configuration
Get-MpPreference | Select-Object EnableControlledFolderAccess, `
  ControlledFolderAccessProtectedFolders, `
  ControlledFolderAccessAllowedApplications
```

**Intune:**
```
Endpoint security → Attack surface reduction
→ Controlled folder access: Enable
→ List of additional folders to protect:
  - C:\CompanyData
  - C:\Financial Records
→ List of apps that have access to protected folders:
  - C:\Program Files\Backup\backup.exe
  - C:\Program Files\BusinessApp\app.exe
```

**Test:**
```powershell
# Test ransomware simulation (safe test)
# Try to create file in Documents from cmd.exe (should be blocked)
cmd /c "echo test > %userprofile%\Documents\test.txt"

# If blocked, you'll see:
# Access Denied: Controlled Folder Access blocked this operation
```

---

## 8. Vulnerability Management

### 8.1 Overview

**Exam Objective:** *Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management*

**What is TVM (Now called MDVM)?**
Microsoft Defender Vulnerability Management (formerly Threat & Vulnerability Management) provides:
- Continuous vulnerability assessment
- Risk-based prioritization
- Security recommendations
- Remediation tracking
- Configuration assessment

**Included in:**
- ✅ Defender for Endpoint Plan 2 (Core TVM)
- ✅ Defender Vulnerability Management Add-on (Premium features)
- ✅ Defender Vulnerability Management Standalone (for non-MDE customers)

### 8.2 Core TVM Features (Plan 2)

**Capabilities:**

1. **Software Inventory**
   - Installed applications
   - Versions and patch levels
   - Vendor information
   - End-of-support tracking

2. **Vulnerability Assessment**
   - CVE detection
   - CVSS scoring
   - Exploitability analysis
   - Proof-of-concept availability

3. **Security Recommendations**
   - Prioritized remediation actions
   - Impact analysis
   - Remediation complexity
   - Alternative mitigations

4. **Configuration Assessment**
   - Security baseline compliance
   - Missing security updates
   - Misconfigured settings

5. **Exposure Score**
   - Organization-wide risk score
   - Trending over time
   - Comparison to industry

### 8.3 Access Vulnerability Management

**Location:** Microsoft Defender Portal → Vulnerability management

**Dashboard Sections:**
```
Vulnerability Management Dashboard
│
├─ Exposure Score (0-1000)
│  └─ Lower is better
│
├─ Microsoft Secure Score for Devices
│  └─ Configuration improvements
│
├─ Top Security Recommendations
│  └─ Prioritized actions
│
├─ Top Vulnerable Software
│  └─ Applications with most CVEs
│
├─ Top Exposed Devices
│  └─ Devices with highest risk
│
└─ Remediation Activities
   └─ Tracking remediation tasks
```

### 8.4 Security Recommendations

**View Recommendations:**
```
1. Vulnerability management → Recommendations
2. Sort by: Exposure impact (default)
3. Each recommendation shows:
   - Title (e.g., "Update Google Chrome")
   - Exposed devices count
   - CVEs associated
   - Exposure impact score
   - Remediation type
   - Effort level
4. Click recommendation for details
```

**Recommendation Details:**

```
Recommendation: Update Google Chrome
│
├─ Description: Chrome version 118 has 15 vulnerabilities
├─ Exposure impact: 5,234 points
├─ Exposed devices: 523 devices
├─ CVEs: CVE-2024-XXXX (Critical), CVE-2024-YYYY (High), ...
├─ Security alerts: 3 active alerts related to this vulnerability
├─ Exploitability: Exploit code available publicly
│
└─ Remediation options:
   ├─ Option 1: Update via software deployment (Recommended)
   ├─ Option 2: Apply temporary mitigation
   └─ Option 3: Accept risk (not recommended)
```

#### **Create Remediation Task**

**Step-by-step:**
```
1. Select recommendation
2. Click "Remediation options"
3. Choose: "Software update via Intune/MECM"
4. Fill in:
   - Task name: "Update Chrome to v120"
   - Due date: 30 days
   - Priority: High
   - Assignee: Endpoint team
   - Notes: "CVE-2024-XXXX has active exploitation"
   - Remediation type: Update
   - Send notification: Yes
5. Create task
```

**Track Remediation:**
```
1. Vulnerability management → Remediation
2. View:
   - Active tasks
   - Completed tasks
   - Overdue tasks
3. Filter by:
   - Priority
   - Assignee
   - Due date
4. Update status as remediation progresses
```

### 8.5 Vulnerability Assessment

**Automated Scanning:**
- Continuous assessment (no scan windows)
- No performance impact
- No credentials needed
- Real-time updates

**View Vulnerabilities:**
```
1. Vulnerability management → Weaknesses
2. Browse CVEs:
   - CVE ID
   - CVSS score
   - Severity
   - Exposed devices
   - Public exploit
   - Alerts generated
3. Click CVE for details:
   - Description
   - Affected products
   - Remediation steps
   - Exposed devices list
   - Related alerts
```

**Example CVE Details:**

```
CVE-2024-1234: Remote Code Execution in Adobe Acrobat
│
├─ CVSS Score: 9.8 (Critical)
├─ Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
├─ Description: Heap overflow allows remote code execution
├─ Exploit Status: Exploit code publicly available
├─ Exposed devices: 1,247 devices
├─ First detected: 2024-01-15
│
└─ Remediation:
   ├─ Update to Acrobat 23.001.20514 or later
   └─ Or apply workaround: Disable JavaScript in PDF
```

### 8.6 Software Inventory

**View Installed Software:**
```
1. Vulnerability management → Inventory → Software
2. See all installed applications across organization:
   - Software name
   - Vendor
   - Version
   - Installed devices
   - Weaknesses (CVEs)
   - End-of-support status
3. Click software for details:
   - Version distribution
   - Devices with this software
   - Known vulnerabilities
   - Recommendations
```

**Filter End-of-Support Software:**
```
1. Software inventory
2. Filter: "End of support" = Yes
3. Review:
   - Windows 7 devices (unsupported)
   - Office 2013 (unsupported)
   - Expired third-party software
4. Create remediation plan
```

### 8.7 Device Exposure Levels

**Exposure Levels:**
- **Critical** - Multiple critical vulnerabilities, active threats
- **High** - Critical vulnerabilities or many high-severity issues
- **Medium** - Some high-severity vulnerabilities
- **Low** - Up-to-date, few issues

**View Exposed Devices:**
```
1. Vulnerability management → Inventory → Devices
2. Sort by: Exposure level
3. Filter: Exposure level = Critical
4. Review devices:
   - Device name
   - OS version
   - Exposure score
   - Active vulnerabilities
   - Missing patches
5. Drill into device for details
```

**Device Vulnerability Profile:**
```
Device: WKS-FIN-001
│
├─ Exposure score: 847 (High)
├─ Exposure level: High
├─ OS: Windows 10 21H2 (outdated)
├─ Last seen: 2 hours ago
│
├─ Vulnerabilities:
│  ├─ Critical: 3 CVEs
│  ├─ High: 12 CVEs
│  └─ Medium: 25 CVEs
│
├─ Security recommendations:
│  ├─ Update Windows 10 to 22H2
│  ├─ Update Chrome to latest
│  └─ Install missing security updates
│
└─ Threat intelligence:
   └─ 2 active threats targeting these vulnerabilities
```

### 8.8 Block Vulnerable Applications

**🆕 Premium Feature (MDVM Add-on)**

**Purpose:** Automatically block applications with known critical vulnerabilities.

**Configure:**
```
1. Vulnerability management → Settings
2. General → Block vulnerable applications
3. Toggle ON
4. Configure:
   - Severity threshold: Critical only
   - Grace period: 30 days
   - Exclusions: Business-critical apps (if needed)
5. Save
```

**How It Works:**
```
1. TVM detects critical CVE in application
2. Grace period starts (30 days)
3. If not remediated:
   └─ Application blocked from launching
   └─ User sees message: "This application has critical security vulnerabilities"
   └─ Admin can grant temporary exception
4. After remediation:
   └─ Block removed automatically
```

### 8.9 Exposure Management (🆕 2025)

**Exam Objective:** *Mitigate risk by using Exposure Management in Microsoft Defender XDR*

**What is Exposure Management?**
- Unified view of organizational risk across all Defender products
- Attack path analysis
- Initiative-based remediation
- Critical asset protection

**Key Features:**
1. **Attack Surface**
   - All internet-facing assets
   - Unmanaged devices
   - Shadow IT discovery

2. **Attack Paths**
   - Potential routes attackers can take
   - Chain vulnerabilities together
   - Prioritize based on business impact

3. **Security Initiatives**
   - Group related remediation tasks
   - Track progress towards goals
   - Executive reporting

4. **Critical Asset Management**
   - Identify crown jewels
   - Focus protection efforts
   - Measure crown jewel exposure

**Access Exposure Management:**
```
Microsoft Defender Portal → Exposure management
```

**Example Attack Path:**

```
Attack Path: Domain Admin Compromise
│
├─ Step 1: Phishing email → User workstation (WKS-001)
│  └─ Vulnerability: User lacks MFA, unpatched Office
│
├─ Step 2: Credential theft → Local admin credentials harvested
│  └─ Vulnerability: LSASS credential exposure
│
├─ Step 3: Lateral movement → Jump to file server (FS-001)
│  └─ Vulnerability: Shared local admin password
│
├─ Step 4: Privilege escalation → Exploit vulnerable service
│  └─ Vulnerability: CVE-2024-XXXX on file server
│
└─ Step 5: Access domain controller (DC-001)
   └─ Impact: Full domain compromise, data exfiltration

Risk Score: Critical
Recommended Actions:
1. Enable MFA for all users (highest impact)
2. Implement LAPS for local admin passwords
3. Patch CVE-2024-XXXX on FS-001
4. Apply ASR rules to prevent credential theft
```

**Create Security Initiative:**
```
1. Exposure management → Initiatives
2. Click "+ Create initiative"
3. Initiative details:
   - Name: "Reduce Domain Admin Risk"
   - Description: "Eliminate attack paths to domain controllers"
   - Owner: Security team
   - Timeline: 90 days
4. Add metrics:
   - Attack paths targeting DCs: Reduce from 5 to 0
   - Devices with admin credential exposure: Reduce 80%
   - Domain admin MFA coverage: Increase to 100%
5. Link recommendations:
   - Enable MFA
   - Deploy LAPS
   - Apply ASR rules
   - Patch critical CVEs
6. Create and track progress
```

**🎯 Exam Tip:** Exposure Management integrates data from ALL Microsoft Defender products (Endpoint, Identity, Office 365, Cloud Apps, Cloud) to provide unified risk view and attack path analysis.

---

## 9. Threat Response and Investigation

### 9.1 Incident Response Workflow

**Exam Objective:** *Respond to alerts and incidents identified by Microsoft Defender for Endpoint*

**Incident Response Process:**

```
1. Alert Triggered
   ↓
2. Incident Created (auto-correlation)
   ↓
3. SOC Analyst Assigned
   ↓
4. Investigate
   ├─ Device timeline
   ├─ Evidence analysis
   ├─ User activity
   └─ Related alerts
   ↓
5. Contain Threat
   ├─ Isolate device
   ├─ Block files/URLs
   ├─ Disable user
   └─ Stop processes
   ↓
6. Remediate
   ├─ Remove malware
   ├─ Restore files
   ├─ Reset passwords
   └─ Apply patches
   ↓
7. Close Incident
   └─ Document lessons learned
```

### 9.2 Investigate Incidents

**Access Incidents:**
```
Microsoft Defender Portal → Incidents & alerts → Incidents
```

**Incident Queue:**
```
Incident List
│
├─ Columns:
│  ├─ Name
│  ├─ Severity (High/Medium/Low/Informational)
│  ├─ Status (New/In progress/Resolved)
│  ├─ Assignment
│  ├─ Detection source (EDR/AV/ASR/etc.)
│  ├─ Impacted entities (devices/users/mailboxes)
│  └─ Last updated time
│
└─ Filters:
   ├─ Status
   ├─ Severity
   ├─ Service source (MDE/MDI/MDO/MDCA)
   ├─ Assigned to
   └─ Tags
```

#### **Open and Investigate Incident**

**Incident Page Sections:**

```
Incident: Multi-stage attack detected
│
├─ Header
│  ├─ Incident ID: #12345
│  ├─ Severity: High
│  ├─ Status: In progress
│  ├─ Assigned to: soc-analyst@company.com
│  └─ Tags: Ransomware, Credential_Access
│
├─ Story (Attack Chain)
│  └─ Visual timeline of attack progression
│     ├─ Initial access (Email)
│     ├─ Execution (Malicious macro)
│     ├─ Credential access (LSASS dump)
│     ├─ Lateral movement (PSExec)
│     └─ Impact (File encryption)
│
├─ Alerts (all related alerts in this incident)
│  ├─ Alert 1: Suspicious email attachment
│  ├─ Alert 2: Macro execution detected
│  ├─ Alert 3: Credential dumping tool
│  └─ Alert 4: Ransomware behavior
│
├─ Evidence & Response
│  ├─ Devices (3 affected)
│  ├─ Users (2 accounts)
│  ├─ Files (malware samples)
│  ├─ IP addresses (C2 servers)
│  ├─ URLs (phishing sites)
│  └─ Processes
│
├─ Investigation
│  ├─ Automated investigation results
│  ├─ AI-generated summary (Security Copilot)
│  └─ Analyst notes
│
└─ Response Actions
   ├─ Recommended actions
   ├─ Pending actions
   └─ Completed actions
```

### 9.3 Investigate Device Timeline

**Exam Objective:** *Investigate device timelines*

**Purpose:** 
- See everything that happened on a device
- Understand attack sequence
- Identify root cause
- Find related artifacts

#### **Access Device Timeline**

**Method 1: From Device Page**
```
1. Device inventory → Select device
2. Click "Timeline" tab
3. Choose time range (last 6 months available)
```

**Method 2: From Incident**
```
1. Open incident
2. Evidence & Response → Devices
3. Click device
4. Timeline tab
```

#### **Timeline Events**

**Event Types:**

| Category | Events | Exam Importance |
|----------|--------|-----------------|
| **Process** | Process created, terminated | ⭐⭐⭐⭐⭐ |
| **File** | Created, modified, deleted | ⭐⭐⭐⭐⭐ |
| **Registry** | Key/value created, modified | ⭐⭐⭐⭐ |
| **Network** | Connection initiated, DNS query | ⭐⭐⭐⭐⭐ |
| **Logon** | User logged on/off, failed logon | ⭐⭐⭐⭐⭐ |
| **Behavior** | ASR rule triggered, suspicious activity | ⭐⭐⭐⭐⭐ |
| **Alert** | Alert generated | ⭐⭐⭐⭐ |

**Timeline View:**
```
Timeline (Filtered: Last 24 hours)
│
├─ 2025-10-22 08:15:23 - User Logon
│  └─ User: john.doe logged on to WKS-001
│
├─ 2025-10-22 08:17:45 - Email Opened
│  └─ Outlook.exe opened attachment invoice.docm
│
├─ 2025-10-22 08:17:50 - Process Created (SUSPICIOUS)
│  └─ WINWORD.EXE created child process: powershell.exe
│      Command: powershell.exe -enc <base64>
│      Parent: WINWORD.EXE
│      Alert: Suspicious PowerShell execution
│
├─ 2025-10-22 08:17:52 - Network Connection
│  └─ powershell.exe connected to 203.0.113.50:443
│      Reputation: Malicious (Known C2)
│
├─ 2025-10-22 08:17:55 - File Created (MALICIOUS)
│  └─ File: C:\Users\john.doe\AppData\Roaming\update.exe
│      SHA256: abc123...
│      Verdict: Malware detected
│
├─ 2025-10-22 08:18:10 - Registry Modified
│  └─ Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
│      Value: "Updater" = "C:\Users\...\update.exe"
│      Purpose: Persistence mechanism
│
└─ 2025-10-22 08:18:15 - Device Isolated (AUTO)
   └─ Action: Automated device isolation
      Reason: Malware detected with active C2 communication
      Status: Isolated successfully
```

#### **Filter and Search Timeline**

**Filters:**
```
Timeline Filters:
├─ Time range: Last 24 hours / 7 days / 30 days / Custom
├─ Event types: Process / File / Network / Registry / All
├─ Severity: High / Medium / Low
├─ Detection source: EDR / AV / ASR
└─ Search: Keyword, file name, IP, process name
```

**Example Investigation:**

**Scenario: Investigate potential data exfiltration**

**Steps:**
```
1. Open device timeline
2. Filter: Last 7 days, Network connections
3. Look for:
   - Unusual destinations
   - Large data transfers
   - Non-business hours activity
   - Cloud storage connections
4. Found: WinRAR.exe created archive at 2 AM
5. Expand timeline:
   - What process created archive?
   - What files were included?
   - Where was archive uploaded?
   - Who was logged on?
6. Collect evidence:
   - Archive file hash
   - Network traffic logs
   - Process command lines
7. Take action:
   - Isolate device
   - Block destination IP
   - Collect investigation package
   - Reset user credentials
```

### 9.4 Perform Actions on Devices

**Exam Objective:** *Perform actions on the device, including live response and collecting investigation packages*

#### **Available Device Actions**

| Action | Purpose | When to Use | Exam Importance |
|--------|---------|-------------|-----------------|
| **Isolate device** | Cut off network access (except MDE) | Active malware, spreading threat | ⭐⭐⭐⭐⭐ |
| **Restrict app execution** | Allow only Microsoft-signed apps | Limit attacker movement | ⭐⭐⭐⭐ |
| **Run antivirus scan** | Full or quick scan | Verify malware removal | ⭐⭐⭐⭐ |
| **Collect investigation package** | Gather forensic data | Deep investigation needed | ⭐⭐⭐⭐⭐ |
| **Initiate live response** | Remote shell access | Real-time investigation | ⭐⭐⭐⭐⭐ |
| **Initiate automated investigation** | Trigger AIR | Suspicious but not confirmed | ⭐⭐⭐⭐ |
| **Stop and quarantine file** | Remove specific file | Known malware file | ⭐⭐⭐⭐ |
| **Add device tags** | Label for tracking | Organize incident response | ⭐⭐⭐ |
| **Run EDR in block mode** | Extra protection layer | High-risk device | ⭐⭐⭐ |

#### **Isolate Device**

**When to Use:**
- Active malware spreading
- Ransomware detected
- Data exfiltration in progress
- Lateral movement detected
- APT activity

**How It Works:**
- Blocks all network traffic
- **Exception:** MDE sensor communication still allowed
- User can still use device locally
- No internet access
- Cannot access internal resources

**Isolate Device:**
```
1. Device inventory → Select device
2. Click "..." → Isolate device
3. Select isolation type:
   - Full isolation (recommended for malware)
   - Selective isolation (exceptions for specific IPs)
4. Add comment: "Ransomware detected, isolating to prevent spread"
5. Confirm
6. Wait for isolation to complete (1-5 minutes)
7. Verify: Device status shows "Isolated"
```

**Release from Isolation:**
```
1. Device page → "Release from isolation"
2. Confirm device is clean:
   - Malware removed
   - Vulnerabilities patched
   - No suspicious activity
3. Add comment: "Remediation complete, releasing device"
4. Confirm
5. Device reconnects to network
```

**PowerShell (via Graph API):**
```powershell
# Isolate device
$deviceId = "device-guid-here"
Invoke-MgGraphRequest -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/security/machines/$deviceId/isolate" `
  -Body (@{ Comment = "Malware detected" } | ConvertTo-Json)

# Release from isolation
Invoke-MgGraphRequest -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/security/machines/$deviceId/releaseFromIsolation" `
  -Body (@{ Comment = "Remediation complete" } | ConvertTo-Json)
```

#### **Restrict App Execution**

**Purpose:** Allow only Microsoft-signed applications to run (whitelisting).

**Use Case:**
- Device compromised but not isolated
- Prevent attacker from running tools
- Limit damage during investigation
- Temporary containment measure

**Enable:**
```
1. Device page → "..." → Restrict app execution
2. Warning: Only Microsoft-signed apps can run
3. Confirm
4. User notified of restrictions
```

**What Gets Blocked:**
- Third-party applications
- Downloaded executables
- Unsigned scripts
- Malware

**What Still Works:**
- Windows built-in tools
- Microsoft Office
- Edge browser
- Microsoft-signed apps

**Remove Restriction:**
```
1. Device page → "Remove app restrictions"
2. Confirm
3. All apps can run again
```

#### **Collect Investigation Package**

**Purpose:** Gather comprehensive forensic data from device.

**What's Collected:**
- Process memory dumps
- Registry hives
- Event logs
- Prefetch files
- PowerShell history
- Network configuration
- Running processes
- Scheduled tasks
- Services
- User accounts
- File metadata
- Browser history
- And more (~200 MB package)

**Collect Package:**
```
1. Device page → "..." → Collect investigation package
2. Confirm collection
3. Wait for collection (5-15 minutes)
4. Download package from Action Center:
   - Action Center → History
   - Find "Collect investigation package"
   - Status: Completed
   - Click "Download package"
5. Save .zip file (password-protected)
6. Password shown in Action Center
```

**Analyze Package:**
```
Investigation Package Contents:
├─ /Registry
│  ├─ SYSTEM
│  ├─ SOFTWARE
│  ├─ SAM
│  └─ SECURITY
├─ /EventLogs
│  ├─ Security.evtx
│  ├─ System.evtx
│  └─ Application.evtx
├─ /Processes
│  ├─ processes.csv
│  └─ memory_dumps/
├─ /Network
│  ├─ netstat.txt
│  ├─ ipconfig.txt
│  └─ dns_cache.txt
├─ /Prefetch
│  └─ *.pf files
├─ /PowerShell
│  └─ ConsoleHost_history.txt
└─ /System
   ├─ services.csv
   ├─ scheduled_tasks.csv
   └─ users.csv
```

**Use Investigation Package With:**
- KAPE (Kroll Artifact Parser and Extractor)
- Volatility (memory analysis)
- RegistryExplorer
- Event Log Explorer
- Manual forensic analysis

**Exam Scenario:**
```
Q: A device may be compromised. You need to conduct offline forensic analysis.
   What action should you take?

A:
1. Isolate device (to preserve state)
2. Collect investigation package
3. Download package from Action Center
4. Analyze offline with forensic tools
5. Look for:
   - Persistence mechanisms (Run keys, scheduled tasks)
   - Malicious processes in memory
   - Event log anomalies
   - Network connections to suspicious IPs
6. Remediate based on findings
7. Release device after cleanup
```

---

## 10. Live Response

### 10.1 Overview

**Exam Objective:** *Perform actions on the device, including live response and collecting investigation packages*

**What is Live Response?**
- Remote shell access to compromised device
- Real-time forensic investigation
- Run commands remotely
- Collect files
- Execute remediation scripts

**Requirements:**
- ✅ Defender for Endpoint Plan 2
- ✅ Live Response enabled (Settings → Advanced features)
- ✅ Device must be online
- ✅ Device must be onboarded to MDE
- ✅ Appropriate RBAC permissions

### 10.2 Enable Live Response

**Enable Feature:**
```
1. Settings → Endpoints → General → Advanced features
2. Scroll to "Live Response"
3. Toggle ON:
   ☑ Enable live response
   ☑ Enable live response for servers
   ☑ Enable live response unsigned script execution (if needed)
4. Save preferences
```

**RBAC Requirements:**

| Permission | Can Do |
|------------|--------|
| **View Data - Live Response** | View sessions only |
| **Manage security settings - Live Response capabilities** | Initiate sessions, run basic commands |
| **Manage security settings - Live Response advanced** | Run advanced commands, upload files |

### 10.3 Initiate Live Response Session

**Start Session:**
```
1. Device inventory → Select device
2. Click "..." → Initiate live response session
3. Wait for connection (10-30 seconds)
4. Live Response console opens
```

**Console Interface:**
```
Live Response Session: WKS-001
Status: Connected
Session ID: abc-123-def-456
User: soc-analyst@company.com
Duration: 00:05:32

C:\>_
```

### 10.4 Live Response Commands

#### **Basic Commands (No Advanced Permission Needed)**

| Command | Purpose | Syntax | Example |
|---------|---------|--------|---------|
| **help** | List commands | `help` | `help` |
| **connections** | Network connections | `connections` | `connections` |
| **processes** | Running processes | `processes` | `processes` |
| **registry** | Query registry | `registry <action> <key>` | `registry query HKLM\Software\Microsoft` |
| **fileinfo** | File metadata | `fileinfo <file>` | `fileinfo C:\Windows\System32\cmd.exe` |
| **findfile** | Search for files | `findfile <filename>` | `findfile malware.exe` |
| **getfile** | Download file | `getfile <file>` | `getfile C:\Temp\suspicious.exe` |
| **cat** | Display file | `cat <file>` | `cat C:\Temp\log.txt` |

#### **Advanced Commands (Requires Advanced Permission)**

| Command | Purpose | Syntax | Example |
|---------|---------|--------|---------|
| **run** | Execute command | `run <command>` | `run ipconfig /all` |
| **putfile** | Upload file | `putfile <library_file> <destination>` | `putfile remediation.ps1 C:\Temp\` |
| **remediate** | Run script | `remediate <library_file> [args]` | `remediate cleanup.ps1 -Force` |
| **undo** | Undo remediation | `undo <action_id>` | `undo 12345` |
| **scheduledtask** | Manage tasks | `scheduledtask <query/delete>` | `scheduledtask query` |
| **persist** | Show persistence | `persist` | `persist` |
| **trace** | Network trace | `trace <start/stop>` | `trace start` |

### 10.5 Investigation Commands - Deep Dive

#### **connections - Network Connections**

**Purpose:** See all active network connections.

```
C:\> connections

LocalAddress    LocalPort  RemoteAddress    RemotePort  State       ProcessId  ProcessName
192.168.1.100   49234     203.0.113.50     443         ESTABLISHED  4892      powershell.exe
192.168.1.100   49235     93.184.216.34    80          ESTABLISHED  3344      chrome.exe
192.168.1.100   49236     10.0.0.5         445         ESTABLISHED  1234      explorer.exe
```

**What to Look For:**
- ❌ Connections to unknown external IPs
- ❌ Unusual ports (not 80, 443, 445, etc.)
- ❌ Connections from system processes to internet
- ❌ High volume of connections

**Exam Scenario:**
```
Q: You see powershell.exe connected to 203.0.113.50:443.
   What should you investigate next?

A:
1. Check IP reputation (likely C2)
2. Review process command line: processes
3. Get process memory: getfile [memory dump]
4. Check parent process
5. Look for persistence: persist
6. Isolate device if malicious
```

#### **processes - Running Processes**

**Purpose:** List all running processes with details.

```
C:\> processes

ProcessId  ProcessName          ParentProcessId  CommandLine
1234       explorer.exe         1000             "C:\Windows\explorer.exe"
4892       powershell.exe       2344             powershell.exe -enc <base64>
3344       chrome.exe           1234             "C:\Program Files\Google\Chrome\..."
5678       malware.exe          4892             C:\Users\Public\malware.exe
```

**What to Look For:**
- ❌ Suspicious parent-child relationships (Office → PowerShell)
- ❌ Obfuscated command lines (-enc, Base64)
- ❌ Processes running from temp/public folders
- ❌ Misspelled system process names (scvhost.exe instead of svchost.exe)
- ❌ System processes with wrong parent (svchost.exe parent should be services.exe)

**Exam Scenario:**
```
Q: You find powershell.exe with parent WINWORD.EXE. What does this indicate?

A:
- Likely malicious macro execution
- Word shouldn't spawn PowerShell normally
- Check command line for suspicious activity
- Look for downloaded files
- Check persistence mechanisms
- Likely initial access vector for attack
```

#### **findfile - Search for Files**

**Purpose:** Search entire device for specific files.

**🆕 2025 Update:** Now includes OneDrive shares in search!

```
C:\> findfile malware.exe

Searching device and OneDrive...

Found 3 instances:
C:\Users\john.doe\Downloads\malware.exe
C:\Users\john.doe\AppData\Roaming\malware.exe
C:\Users\john.doe\OneDrive\Backup\malware.exe
```

**Use Cases:**
- Find malware copies
- Locate evidence
- Check for data exfiltration staging
- Find configuration files

**Example:**
```
C:\> findfile *.docx

Found 1,247 .docx files
Display first 100? (y/n): y

C:\Users\john.doe\Documents\Financial_Report_2024.docx
C:\Users\john.doe\Desktop\passwords.docx (SUSPICIOUS!)
C:\Users\john.doe\AppData\Local\Temp\exfil_data.docx (SUSPICIOUS!)
...
```

#### **getfile - Download File from Device**

**Purpose:** Download suspicious file for analysis.

```
C:\> getfile C:\Users\Public\malware.exe

File queued for download: malware.exe
Size: 1.2 MB
SHA256: abc123def456...

Download available in Action Center in 2-5 minutes.
```

**What to Download:**
- Suspicious executables
- Malicious scripts
- Dropped files
- Configuration files
- Evidence files

**After Download:**
- Submit to sandbox (Deep Analysis in MDE)
- Check VirusTotal
- Reverse engineer if needed
- Generate file hash IOCs

#### **registry - Query Registry**

**Purpose:** Check registry keys for persistence, configuration.

```
C:\> registry query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Values:
Name: OneDrive
Data: "C:\Users\...\OneDrive.exe"
Type: REG_SZ

Name: Updater
Data: "C:\Users\Public\malware.exe"  <-- SUSPICIOUS!
Type: REG_SZ
```

**Common Persistence Locations:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

**Exam Scenario:**
```
Q: How do you find persistence mechanisms via Live Response?

A:
1. Open Live Response session
2. Check Run keys:
   registry query HKCU\...\Run
   registry query HKLM\...\Run
3. Check services:
   run sc query
4. Check scheduled tasks:
   scheduledtask query
5. Look for suspicious entries
6. Remove malicious entries
7. Verify removal
```

#### **persist - Show All Persistence**

**Purpose:** Automatically find all persistence mechanisms.

```
C:\> persist

Scanning for persistence mechanisms...

Found 3 suspicious persistence methods:

1. Registry Run Key:
   Location: HKCU\...\Run
   Name: Updater
   Value: C:\Users\Public\malware.exe
   Risk: HIGH

2. Scheduled Task:
   Name: SystemUpdate
   Command: powershell.exe -File C:\Temp\update.ps1
   Trigger: At logon
   Risk: HIGH

3. Service:
   Name: WindowsUpdateService (Misspelled!)
   Binary: C:\Windows\Temp\svc.exe
   Startup: Automatic
   Risk: CRITICAL
```

**What to Do:**
- Review each persistence method
- Determine if legitimate or malicious
- Remove malicious entries
- Document for incident report

### 10.6 Remediation Commands

#### **run - Execute Command**

**Purpose:** Run any Windows command remotely.

**Examples:**

**Network Troubleshooting:**
```
C:\> run ipconfig /all
C:\> run nslookup malicious.com
C:\> run netstat -ano
```

**Process Management:**
```
C:\> run taskkill /F /PID 4892
C:\> run taskkill /IM malware.exe /F
```

**Service Management:**
```
C:\> run sc query | findstr "RUNNING"
C:\> run sc stop MaliciousService
C:\> run sc delete MaliciousService
```

**File Operations:**
```
C:\> run del C:\Users\Public\malware.exe /F
C:\> run rmdir /S /Q C:\Users\Public\MalwareFolder
```

**Check Logs:**
```
C:\> run wevtutil qe Security "/q:*[System[(EventID=4624)]]" /c:10 /f:text
```

#### **putfile - Upload File to Device**

**Purpose:** Upload remediation scripts or tools to device.

**Step 1: Prepare Library File**
```
1. Settings → Endpoints → General → Advanced features
2. Click "Manage live response library"
3. Upload files:
   - cleanup.ps1
   - autoruns.exe
   - remediation_tool.exe
4. Approve for use
```

**Step 2: Upload to Device**
```
C:\> putfile cleanup.ps1 C:\Temp\cleanup.ps1

Uploading from library...
Upload complete: C:\Temp\cleanup.ps1
```

**Step 3: Execute**
```
C:\> remediate cleanup.ps1 -Verbose
```

#### **remediate - Run Remediation Script**

**Purpose:** Execute pre-approved remediation scripts.

**Example Script: Remove Persistence**

**cleanup.ps1:**
```powershell
# Remove malicious persistence
param($Verbose)

Write-Output "Starting cleanup..."

# Remove Run key
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -ErrorAction SilentlyContinue

# Stop and delete service
Stop-Service -Name "MaliciousService" -Force -ErrorAction SilentlyContinue
sc.exe delete "MaliciousService"

# Remove scheduled task
Unregister-ScheduledTask -TaskName "SystemUpdate" -Confirm:$false -ErrorAction SilentlyContinue

# Delete malware files
Remove-Item -Path "C:\Users\Public\malware.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Temp\*.evil" -Force -ErrorAction SilentlyContinue

Write-Output "Cleanup complete!"
```

**Execute:**
```
C:\> remediate cleanup.ps1 -Verbose

Running cleanup.ps1...
Starting cleanup...
Removed registry key: HKCU\...\Run\Updater
Stopped service: MaliciousService
Deleted service: MaliciousService
Removed scheduled task: SystemUpdate
Deleted: C:\Users\Public\malware.exe
Cleanup complete!

Action ID: 67890 (can undo with: undo 67890)
```

#### **undo - Undo Remediation**

**🆕 2025 Feature:** Undo previous remediation actions.

**Purpose:** Roll back changes if remediation was too aggressive.

```
C:\> undo 67890

Undoing action 67890...

Restored:
- Registry key: HKCU\...\Run\Updater
- Service: MaliciousService
- Scheduled task: SystemUpdate
- Files: [files restored from recycle bin if available]

Undo complete.
Note: Some actions cannot be fully reversed.
```

**Use Cases:**
- False positive remediation
- Accidentally removed legitimate software
- Need to preserve evidence
- Rollback for deeper analysis

### 10.7 Live Response Best Practices

**Do:**
- ✅ Document all commands run
- ✅ Take screenshots of findings
- ✅ Save session logs
- ✅ Use `getfile` before deleting evidence
- ✅ Verify device state before and after
- ✅ Follow incident response playbook
- ✅ End session when done

**Don't:**
- ❌ Run destructive commands without approval
- ❌ Modify evidence unnecessarily
- ❌ Forget to collect files before removal
- ❌ Leave session open indefinitely
- ❌ Use for routine maintenance
- ❌ Share session logs publicly

**Exam Scenario:**
```
Q: During Live Response, you find malware. What is the correct order of actions?

A:
1. Document current state (connections, processes)
2. Collect evidence:
   - getfile malware.exe
   - getfile related scripts
3. Check persistence: persist
4. Remediate:
   - Stop malicious processes
   - Remove persistence
   - Delete malware files
5. Verify cleanup:
   - Re-run processes
   - Re-check persist
6. End session and document
7. Submit files to sandbox for analysis
```

---

## 11. Custom Detections and Hunting

### 11.1 Advanced Hunting Overview

**Exam Objective:** *Identify threats by using Kusto Query Language (KQL)* and *Create custom hunting queries by using KQL*

**What is Advanced Hunting?**
- Proactive threat hunting using KQL
- Query up to 30 days of raw EDR telemetry
- Create custom detections
- Find threats that bypass automated detection

**Access:**
```
Microsoft Defender Portal → Hunting → Advanced hunting
```

### 11.2 Advanced Hunting Schema

**Key Tables:**

| Table | Data Stored | Retention | Use For |
|-------|-------------|-----------|---------|
| **DeviceProcessEvents** | Process creation/termination | 30 days | Malware execution, suspicious processes |
| **DeviceNetworkEvents** | Network connections | 30 days | C2 communication, data exfiltration |
| **DeviceFileEvents** | File operations | 30 days | Malware drops, document access |
| **DeviceRegistryEvents** | Registry changes | 30 days | Persistence mechanisms |
| **DeviceLogonEvents** | Authentication events | 30 days | Lateral movement, failed logins |
| **DeviceImageLoadEvents** | DLL loading | 30 days | DLL injection, suspicious libraries |
| **DeviceEvents** | General security events | 30 days | ASR triggers, SmartScreen blocks |
| **DeviceInfo** | Device inventory | Current | Device details, OS versions |
| **DeviceNetworkInfo** | Network configuration | Current | IP addresses, network adapters |
| **AlertEvidence** | Alert details | 30 days | Alert context, evidence |
| **AlertInfo** | Alert metadata | 30 days | Alert properties, severity |

**Complete Schema:**
```
Hunting → Advanced hunting → Schema tab
```

### 11.3 KQL Basics for SC-200

#### **Query Structure**

```kql
TableName                          // Start with table
| where Condition                  // Filter rows
| extend NewColumn = Expression    // Add calculated column
| project Column1, Column2         // Select columns
| summarize Count = count() by Category  // Aggregate
| order by Column desc             // Sort
| limit 100                        // Limit results
```

#### **Common Operators**

| Operator | Purpose | Example |
|----------|---------|---------|
| `==` | Equals (case-sensitive) | `ProcessName == "cmd.exe"` |
| `=~` | Equals (case-insensitive) | `FileName =~ "MALWARE.EXE"` |
| `!=` | Not equals | `Severity != "Low"` |
| `contains` | Contains substring | `CommandLine contains "invoke"` |
| `has` | Contains whole word | `CommandLine has "invoke-mimikatz"` |
| `startswith` | Starts with | `FileName startswith "mal"` |
| `endswith` | Ends with | `FileName endswith ".exe"` |
| `in~` | In list (case-insensitive) | `FileName in~ ("cmd.exe", "powershell.exe")` |
| `between` | Between values | `Timestamp between (ago(1h) .. now())` |
| `and` | Logical AND | `Severity == "High" and Status == "New"` |
| `or` | Logical OR | `ActionType == "PowerShellCommand" or ActionType == "ScriptExecution"` |

#### **Time Functions**

```kql
// Last hour
| where Timestamp > ago(1h)

// Last 24 hours
| where Timestamp > ago(1d)

// Last 7 days
| where Timestamp > ago(7d)

// Specific date range
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-22))

// Today
| where Timestamp > startofday(now())
```

### 11.4 Hunting Queries - Exam Focus

#### **Query 1: Find Credential Dumping (Mimikatz)**

**Technique:** Detect tools attempting to access LSASS process for credential theft.

```kql
// Find processes accessing LSASS memory (credential theft)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("mimikatz.exe", "procdump.exe", "dumpert.exe")
    or ProcessCommandLine has_any ("sekurlsa", "lsadump", "lsass")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, 
          AccountName, InitiatingProcessFileName
| order by Timestamp desc
```

**What to Look For:**
- Mimikatz or similar tool names
- Command lines with "sekurlsa::logonpasswords"
- ProcDump targeting lsass.exe
- PowerShell running Invoke-Mimikatz

**MITRE ATT&CK:** T1003 (Credential Dumping)

#### **Query 2: Detect PowerShell Download and Execute**

**Technique:** PowerShell downloading and running malicious payloads.

```kql
// PowerShell downloading files from internet
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression", 
        "DownloadString", "DownloadFile", "Net.WebClient", 
        "Invoke-WebRequest", "wget", "curl")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**What to Look For:**
- IEX (Invoke-Expression) - executes downloaded code
- DownloadString/DownloadFile - downloads files
- Net.WebClient - HTTP client for downloads
- Obfuscated commands (-enc, base64)

**MITRE ATT&CK:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)

**Exam Scenario:**
```
Q: Create a KQL query to find devices where PowerShell downloaded and
   executed content from the internet in the last 24 hours.

A: [Query above with "ago(1d)" instead of "ago(30d)"]
```

#### **Query 3: Find Lateral Movement (PSExec/WMI)**

**Technique:** Detect lateral movement using PSExec or WMI.

```kql
// Detect PSExec and WMI lateral movement
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("psexec.exe", "paexec.exe")
    or InitiatingProcessCommandLine has "wmic"
    or ProcessCommandLine has_any ("psexec", "wmic process call create")
| where AccountName != "SYSTEM"  // Filter out legitimate system processes
| project Timestamp, DeviceName, FileName, ProcessCommandLine, 
          AccountName, InitiatingProcessFileName
| order by Timestamp desc
```

**Indicators:**
- PSExec.exe execution (or similar tools)
- WMI process creation
- Remote command execution
- Non-system account running remote tools

**MITRE ATT&CK:** T1021.002 (SMB/Windows Admin Shares), T1047 (WMI)

#### **Query 4: Detect Persistence via Registry Run Keys**

**Technique:** Find malware establishing persistence through registry.

```kql
// Find registry Run key modifications
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any (
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)
| where ActionType == "RegistryValueSet"
| where RegistryValueData !contains "Program Files"  // Filter legitimate apps
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, 
          RegistryValueData, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

**What to Look For:**
- Run keys modified by suspicious processes
- Executables in Temp, Public, or AppData folders
- Obfuscated file paths
- Unknown/suspicious executable names

**MITRE ATT&CK:** T1547.001 (Registry Run Keys)

#### **Query 5: Find File Encryption (Ransomware Behavior)**

**Technique:** Detect mass file encryption typical of ransomware.

```kql
// Detect rapid file renaming/encryption
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileRenamed"
| where FileName endswith ".encrypted" 
    or FileName endswith ".locked"
    or FileName endswith ".crypted"
    or FileName matches regex @"\.[a-z]{6,8}$"  // Random extension
| summarize FilesModified = count(), 
            FileTypes = make_set(FolderPath),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName
| where FilesModified > 100  // Many files modified quickly
| order by FilesModified desc
```

**Indicators:**
- High volume of file renames (>100 files)
- Short time window (minutes)
- Random or specific ransomware extensions
- Executable in unusual location

**MITRE ATT&CK:** T1486 (Data Encrypted for Impact)

**Response:**
1. Immediately isolate device
2. Identify patient zero
3. Check for ransom note
4. Restore from backups
5. Hunt for spread to other devices

#### **Query 6: Suspicious Office Macro Execution**

**Technique:** Office documents spawning unusual child processes.

```kql
// Office applications creating child processes (macro execution)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", 
        "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", 
        "cscript.exe", "mshta.exe", "regsvr32.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

**Normal vs Suspicious:**
- ✅ Normal: winword.exe → splwow64.exe (printer)
- ❌ Suspicious: winword.exe → powershell.exe (macro)
- ❌ Suspicious: excel.exe → cmd.exe (macro)

**MITRE ATT&CK:** T1204.002 (Malicious File)

#### **Query 7: Find Unusual Parent-Child Relationships**

**Technique:** Process spawned by unusual parent.

```kql
// Find suspicious process parent-child relationships
DeviceProcessEvents
| where Timestamp > ago(7d)
// System processes that shouldn't have children
| where InitiatingProcessFileName in~ ("explorer.exe", "svchost.exe", "lsass.exe")
    and FileName in~ ("powershell.exe", "cmd.exe", "net.exe", "whoami.exe")
// Or Office spawning unusual processes
| union (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("winword.exe", "excel.exe")
    | where FileName !in~ ("splwow64.exe")  // Exclude legitimate children
)
| project Timestamp, DeviceName, InitiatingProcessFileName, 
          FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

**Suspicious Relationships:**
- explorer.exe → powershell.exe (unusual)
- lsass.exe → anything (lsass shouldn't spawn children)
- svchost.exe → cmd.exe (depends on context)

#### **Query 8: Detect Suspicious Network Connections**

**Technique:** Find unusual external connections.

```kql
// Find connections to suspicious ports and IPs
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (4444, 5555, 6666, 7777, 8080, 8443, 9999)  // Common C2 ports
    or RemoteIPType == "Public" and RemotePort !in (80, 443)  // Non-standard ports
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", 
        "firefox.exe", "teams.exe", "outlook.exe")  // Filter browsers
| project Timestamp, DeviceName, InitiatingProcessFileName, 
          RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

**What to Look For:**
- Non-browser processes connecting to internet
- Unusual ports (4444, 5555 common for C2)
- System processes connecting externally
- High-frequency connections

**MITRE ATT&CK:** T1071 (Application Layer Protocol - C2)

#### **Query 9: Find New Services Created**

**Technique:** Detect service installation for persistence.

```kql
// Find newly created services
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "sc.exe" and ProcessCommandLine has "create"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp desc

// Alternative: Look in DeviceEvents
| union (
    DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "ServiceInstalled"
    | project Timestamp, DeviceName, FileName, FolderPath, AccountName
)
```

**Indicators:**
- Service created in unusual location (Temp, Public)
- Service name mimics legitimate service (misspelling)
- Service created outside maintenance windows
- Service created by non-admin user

**MITRE ATT&CK:** T1543.003 (Create or Modify System Process: Windows Service)

#### **Query 10: Detect Scheduled Task Creation**

**Technique:** Find scheduled tasks for persistence or execution.

```kql
// Find new scheduled tasks
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "schtasks" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| extend TaskName = extract(@'/TN\s+""?([^""]+)""?', 1, ProcessCommandLine),
         TaskCommand = extract(@'/TR\s+""?([^""]+)""?', 1, ProcessCommandLine)
| project Timestamp, DeviceName, TaskName, TaskCommand, AccountName
| order by Timestamp desc
```

**What to Look For:**
- Tasks running scripts from Temp/Public
- Tasks triggered at logon or startup
- Tasks running PowerShell with suspicious commands
- Tasks created outside business hours

**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job)

### 11.5 Create Custom Detection Rules

**Exam Objective:** *Configure and manage custom detection rules*

**Purpose:** Create alerts when hunting queries find threats.

#### **Convert Hunt to Detection**

**Step 1: Test Query**
```
1. Advanced hunting → Run hunt query
2. Verify results
3. Tune query to reduce false positives
4. Test on multiple days of data
```

**Step 2: Create Detection Rule**
```
1. Click "Create detection rule" from query editor
2. Or: Settings → Endpoints → Rules → Custom detections
3. Click "+ Create custom detection rule"
```

**Step 3: Configure Rule**

```
Detection Rule: Credential Dumping Detected
│
├─ Query:
│  [Paste your KQL query]
│
├─ Rule details:
│  ├─ Rule name: Credential Dumping Tools Detected
│  ├─ Frequency: Real-time (recommended) or Every 24 hours
│  ├─ Alert threshold: 1 match (or 5, 10, etc.)
│  └─ Description: "Detects use of credential dumping tools"
│
├─ Alert details:
│  ├─ Alert title: "Credential dumping tool detected: {{FileName}}"
│  ├─ Severity: High
│  ├─ Category: Credential Access
│  └─ MITRE techniques: T1003.001
│
├─ Actions (if device group supports automation):
│  ├─ Recommended response: Isolate device
│  ├─ Quarantine file: {{FileName}}
│  └─ Initiate investigation
│
└─ Scope:
   ├─ All devices
   └─ Or specific device groups
```

**Step 4: Enable and Monitor**
```
1. Save and enable rule
2. Monitor in Incidents queue
3. Review triggered alerts
4. Tune false positives
5. Adjust sensitivity
```

**Best Practices:**
- Start with audit mode (low severity)
- Monitor for false positives for 1-2 weeks
- Tune query if needed
- Increase severity when confident
- Document rationale for rule

### 11.6 Hunting Bookmarks

**Purpose:** Save interesting findings during hunts for later investigation.

**Create Bookmark:**
```
1. Run hunting query
2. Find interesting result
3. Click row → "Add bookmark"
4. Enter:
   - Bookmark name: "Suspicious PowerShell on WKS-001"
   - Description: "PowerShell downloaded and executed payload"
   - Tags: Credential_Access, Investigation
5. Save
```

**Use Bookmarks:**
```
Hunting → Advanced hunting → Bookmarks tab
- View saved bookmarks
- Link to investigation
- Create incidents from bookmarks
- Share with team
```

**Exam Scenario:**
```
Q: During a hunt, you find 5 devices with suspicious activity.
   You need to track these for further investigation. What do you do?

A:
1. For each finding, create a bookmark
2. Add descriptive name and tags
3. Link related bookmarks if part of same campaign
4. Create incident from bookmarks
5. Assign to analyst for investigation
6. Track remediation in incident
```

---

## 12. Integration with Microsoft 365 Defender

### 12.1 Microsoft 365 Defender (M365D) Overview

**What is Microsoft 365 Defender (formerly Microsoft Threat Protection)?**

Unified XDR (Extended Detection and Response) platform that integrates:
- **Microsoft Defender for Endpoint** (MDE) - Endpoints
- **Microsoft Defender for Identity** (MDI) - On-prem AD
- **Microsoft Defender for Office 365** (MDO) - Email, Teams, SharePoint
- **Microsoft Defender for Cloud Apps** (MDCA) - Cloud apps, SaaS
- **Azure AD Identity Protection** - Cloud identities

### 12.2 Unified Incident Queue

**Key Benefit:** See attacks spanning multiple domains in one incident.

**Example Unified Incident:**

```
Incident #54321: Business Email Compromise Detected
Severity: High
Status: Active
Impacted assets: 3 users, 5 devices, 12 emails

Attack Story:
│
├─ 1. Initial Access (MDO)
│  └─ Phishing email sent to john.doe@company.com
│      Subject: "Urgent: Wire Transfer Required"
│      Sender: ceo@evildomain.com (spoofed)
│
├─ 2. Credential Compromise (MDI)
│  └─ User john.doe credentials compromised
│      Method: Phishing page captured credentials
│      Location: 203.0.113.50 (Russia)
│
├─ 3. Account Takeover (MDCA)
│  └─ Unusual sign-in to Office 365
│      Location: New country (Russia)
│      Activity: Downloaded company financials
│
├─ 4. Lateral Movement (MDE)
│  └─ Compromised account accessed workstation WKS-002
│      Used RDP from unusual location
│
└─ 5. Impact (MDO + MDE)
   └─ Sent phishing emails to 50 contacts
      Attempted wire transfer
      Downloaded sensitive files

Correlated Alerts:
- Alert 1 (MDO): Suspicious email detected
- Alert 2 (MDI): Unusual authentication from new location
- Alert 3 (MDCA): Impossible travel detected
- Alert 4 (MDE): Suspicious RDP connection
- Alert 5 (MDO): Mass email sent

Recommended Actions:
1. Reset user credentials
2. Revoke all active sessions
3. Block sender domain
4. Isolate accessed devices
5. Review sent emails
6. Notify recipients
```

**Benefits:**
- Single incident instead of 5 separate alerts
- Full attack chain visible
- Correlated evidence
- Coordinated response
- Executive summary generated by AI

### 12.3 Automatic Attack Disruption

**How It Works Across Products:**

```
Attack Detected
│
├─ MDO detects phishing email
│  └─ Contains malicious link
│
├─ M365 Defender correlates:
│  ├─ Same link clicked by 3 users
│  ├─ MDI detects credential spray on AD
│  ├─ MDE sees malware dropped
│  └─ MDCA detects unusual cloud app access
│
└─ Automatic Disruption Triggers:
   ├─ Block sender domain (MDO)
   ├─ Quarantine emails (MDO)
   ├─ Disable compromised accounts (MDI)
   ├─ Isolate infected devices (MDE)
   ├─ Block malicious IPs (Network Protection)
   └─ Revoke cloud app sessions (MDCA)
```

### 12.4 Cross-Product Hunting

**Advanced Hunting Across All Products:**

**Query: Find attack spanning email → endpoint → identity**

```kql
// Start with email click
let ClickedLinks = 
EmailEvents
| where Timestamp > ago(1d)
| where ThreatTypes has "Phish"
| where EmailDirection == "Inbound"
| project Timestamp, RecipientEmailAddress, Subject, SenderFromAddress;

// Find devices used by those users
let AffectedDevices = 
ClickedLinks
| join kind=inner (
    DeviceLogonEvents
    | where Timestamp > ago(1d)
) on $left.RecipientEmailAddress == $right.AccountName
| project DeviceName, AccountName, Timestamp;

// Find suspicious activity on those devices
AffectedDevices
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName in~ ("powershell.exe", "cmd.exe")
) on DeviceName
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp
```

**This query shows:**
1. Users who clicked phishing links
2. Devices they logged into
3. Suspicious processes on those devices
4. Complete attack timeline

### 12.5 Unified Response Actions

**Take Action Across All Products:**

**From Single Incident:**
```
Actions Available:
├─ User Actions (MDI/Azure AD)
│  ├─ Disable user account
│  ├─ Force password reset
│  ├─ Revoke refresh tokens
│  └─ Require MFA re-registration
│
├─ Device Actions (MDE)
│  ├─ Isolate device
│  ├─ Run antivirus scan
│  ├─ Collect investigation package
│  ├─ Initiate live response
│  └─ Restrict app execution
│
├─ Email Actions (MDO)
│  ├─ Soft delete emails
│  ├─ Hard delete emails
│  ├─ Move to Junk
│  └─ Block sender
│
└─ Cloud App Actions (MDCA)
   ├─ Suspend user
   ├─ Revoke sessions
   ├─ Block app access
   └─ Require re-authentication
```

**Example: Respond to Ransomware**
```
1. From incident, select all affected devices
2. Click "Take actions" → Isolate devices (bulk action)
3. Select compromised user
4. Click "Take actions" → Disable user, Reset password
5. Review affected files
6. Restore from backups
7. Release devices after verification
8. Close incident
```

### 12.6 Microsoft Security Copilot Integration

**🆕 Exam Objective (2025):** *Implement and use Microsoft Security Copilot*

**What is Security Copilot?**
- AI-powered security assistant
- Natural language queries
- Automated analysis
- Guided response

**Use Cases with MDE:**

**1. Incident Summarization**
```
Analyst: "Summarize incident #54321"

Copilot: "This incident involves a business email compromise that started
with a phishing email to john.doe@company.com. The attacker gained
credentials, accessed the account from Russia, and sent phishing emails
to 50 contacts. Affected systems include 3 user accounts and 5 devices.
Recommended actions: Reset credentials, isolate devices, block sender."
```

**2. Threat Intelligence**
```
Analyst: "Tell me about the file hash abc123..."

Copilot: "This file is a variant of the Emotet trojan, first seen in
January 2025. It's distributed via phishing emails with malicious
attachments. Known to steal credentials and download additional
payloads. MITRE: T1204.002, T1003.001. Remediation: Quarantine
file, scan devices, reset credentials."
```

**3. Guided Investigation**
```
Analyst: "How do I investigate this PowerShell alert?"

Copilot: "
1. Check the PowerShell command line for suspicious patterns
2. Review parent process (should not be Office apps)
3. Check network connections from PowerShell
4. Look for files created or downloaded
5. Review user's recent activity
6. Check for persistence mechanisms
7. Isolate device if malicious confirmed
Would you like me to run these checks automatically?"
```

**4. Response Recommendations**
```
Analyst: "What should I do about this credential dumping alert?"

Copilot: "Immediate actions:
1. Isolate the affected device (WKS-001)
2. Reset compromised user credentials
3. Check for lateral movement to other devices
4. Review admin account access
5. Enable MFA if not already configured

I can execute steps 1 and 3 automatically. Approve?"
```

**Configure Security Copilot:**
```
Settings → Microsoft Security Copilot
├─ Enable Copilot
├─ Configure data sources:
│  ☑ Microsoft Defender for Endpoint
│  ☑ Microsoft Defender for Identity
│  ☑ Microsoft Defender for Office 365
│  ☑ Microsoft Sentinel
├─ Set permissions
├─ Monitor usage and costs
└─ Create promptbooks (saved queries)
```

**🎯 Exam Tip:** Security Copilot uses AI to analyze incidents and provide recommendations. It's integrated across all Microsoft Defender products and can execute response actions with approval.

---

## 13. Common Scenarios and Troubleshooting

### 13.1 Onboarding Issues

#### **Scenario 1: Sense Service Won't Start**

**Symptoms:**
- Device not showing in portal
- Sense service status: Stopped
- Cannot start manually

**Causes:**
- Missing prerequisites
- Conflicting software
- Permissions issues

**Troubleshoot:**
```powershell
# Check service status
Get-Service -Name Sense

# Check dependencies
sc.exe qc Sense

# Check event logs
Get-EventLog -LogName Application -Source "SENSE" -Newest 50 | Format-List

# Verify prerequisites
Get-HotFix | Where-Object {$_.HotFixID -like "KB*"}

# Check tamper protection
Get-MpPreference | Select-Object DisableTamperProtection
```

**Solutions:**
1. Install missing KB updates
2. Temporarily disable third-party AV (test mode)
3. Run as admin: `net start sense`
4. Check firewall rules (allow *.atp.azure.com)
5. Re-run onboarding script

#### **Scenario 2: Device Shows "Inactive"**

**Symptoms:**
- Device listed in portal
- Status: Inactive or Misconfigured
- Last seen: Days/weeks ago

**Causes:**
- Network connectivity issues
- Proxy not configured
- Sense service stopped
- Certificate issues

**Troubleshoot:**
```powershell
# Test connectivity
Test-NetConnection -ComputerName winatp-gw-wus.microsoft.com -Port 443

# Check proxy settings
netsh winhttp show proxy

# Verify service
Get-Service Sense

# Check onboarding info
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"

# Run connectivity test
# Download and run MDE Client Analyzer from Microsoft
MDEClientAnalyzer.cmd
```

**Solutions:**
1. Configure proxy if needed
2. Restart Sense service
3. Verify URL access
4. Re-onboard if persistently inactive
5. Check device time/date synchronization

#### **Scenario 3: Server 2016 Not Onboarding**

**Symptoms:**
- Installer completes but device not in portal
- No errors shown

**Common Mistake:** Using MMA instead of unified agent.

**Solution:**
```
1. Uninstall MMA if installed:
   - Control Panel → Programs → Microsoft Monitoring Agent → Uninstall
2. Download CORRECT installer:
   - Portal → Settings → Onboarding
   - Select: Windows Server 2012 R2 and 2016
   - Download: md4ws_installer.msi (NOT MMA!)
3. Install unified agent:
   msiexec /i md4ws_installer.msi /quiet /qn
4. Wait 10-15 minutes
5. Verify in portal
```

### 13.2 Detection and Alert Issues

#### **Scenario 4: Too Many False Positives**

**Symptoms:**
- ASR rules triggering on legitimate apps
- Users complaining about blocks
- High alert volume, low accuracy

**Solutions:**

**Option 1: Audit Mode**
```powershell
# Set ASR rules to audit (test mode)
$rules = @("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550")  # Email content
Add-MpPreference -AttackSurfaceReductionRules_Ids $rules `
  -AttackSurfaceReductionRules_Actions Audit
```

**Option 2: Exclusions**
```powershell
# Exclude legitimate app
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\BusinessApp\app.exe"
```

**Option 3: Suppress Alerts**
```
Settings → Alert suppression rules
→ Suppress specific alert titles
→ For specific device groups
```

#### **Scenario 5: Missing Vulnerabilities**

**Symptoms:**
- Known vulnerabilities not showing in TVM
- Software inventory incomplete

**Causes:**
- Device not communicating
- Stale data
- Software not detected

**Solutions:**
```
1. Verify device is online and communicating
2. Wait for sync (updates every 24 hours)
3. Manually trigger sync:
   - Device page → "Refresh device"
4. Check if software is supported by TVM
5. For unsupported software:
   - Use premium TVM
   - Or manual tracking
```

### 13.3 Response Action Failures

#### **Scenario 6: Device Isolation Fails**

**Symptoms:**
- Isolation action pending
- Never completes
- Device still has network access

**Troubleshoot:**
```
1. Check device status:
   - Must be online
   - Sense service running
2. Verify network:
   - Can reach *.atp.azure.com
3. Check Action Center:
   - View action status
   - Error message details
4. Try again:
   - Cancel pending action
   - Re-initiate isolation
```

**Alternative:**
```
If MDE isolation fails:
1. Manually disable network adapter
2. Or disconnect from network switch
3. Or use firewall to block traffic
```

#### **Scenario 7: Live Response Won't Connect**

**Symptoms:**
- "Connecting..." never completes
- Connection timeout

**Causes:**
- Device offline
- Live Response not enabled
- Firewall blocking
- Permission issues

**Solutions:**
```
1. Verify device is online (last seen recently)
2. Check advanced features:
   Settings → Live Response → Enabled?
3. Verify user permissions:
   - Need "Manage security settings - Live Response"
4. Check proxy/firewall allows connections
5. Try different device to isolate issue
6. Wait 5 minutes and retry
```

### 13.4 Performance Issues

#### **Scenario 8: High CPU Usage by Sense.exe**

**Symptoms:**
- Sense.exe consuming high CPU
- Device performance slow

**Normal vs Abnormal:**
- Normal: CPU spike during scans or investigations (temporary)
- Abnormal: Constant high CPU usage

**Solutions:**
```
1. Check for active scans:
   Get-MpComputerStatus
2. Wait for scan to complete
3. If persistent:
   - Check Windows Update (may need update)
   - Review exclusions (add performance-critical apps)
   - Check for conflicts with third-party AV
4. Collect diagnostic data:
   MDEClientAnalyzer.cmd
5. Contact Microsoft Support if persistent
```

#### **Scenario 9: Slow Advanced Hunting Queries**

**Symptoms:**
- Queries timeout
- Take minutes to run
- No results returned

**Solutions:**
```
1. Reduce time range:
   - Instead of 30 days, try 7 days
   - Add: | where Timestamp > ago(7d)

2. Add filters early:
   - Filter before joins
   - Use specific device names
   - Example: | where DeviceName == "WKS-001"

3. Limit results:
   - Add: | limit 1000
   - Use summarize instead of raw results

4. Optimize joins:
   - Use kind=inner instead of kind=leftouter
   - Join on indexed columns (DeviceId, Timestamp)

5. Break complex queries into smaller parts
```

**Example Optimization:**

**Slow (searches entire table):**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "malware"  // Searches everything first
| limit 100
```

**Fast (filters first):**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)  // Filter by time first
| where DeviceName == "WKS-001"  // Further filter
| where ProcessCommandLine contains "malware"  // Then search
| limit 100
```

### 13.5 Integration Issues

#### **Scenario 10: MDE Not Showing in Sentinel**

**Symptoms:**
- Sentinel connector configured
- No MDE alerts in Sentinel

**Troubleshoot:**
```
1. Verify connector:
   Sentinel → Data connectors → Microsoft Defender for Endpoint
   Status: Connected?

2. Check data ingestion:
   Sentinel → Logs → SecurityAlert table
   | where ProviderName == "MDATP"

3. Verify permissions:
   - Reader permission on MDE workspace
   - Sentinel workspace connected correctly

4. Check latency:
   - Can take 5-15 minutes for first alerts
   - Verify by creating test alert in MDE

5. Re-configure connector if needed
```

**Exam Scenario:**
```
Q: MDE alerts are not appearing in Sentinel. What troubleshooting steps
   should you take?

A:
1. Verify MDE connector status in Sentinel (Connected?)
2. Check SecurityAlert table for MDATP provider entries
3. Confirm Reader permissions on MDE workspace
4. Check for recent alerts in MDE portal
5. Allow 15 minutes for synchronization
6. Re-configure connector if persistent issue
7. Check firewall allows Sentinel to access MDE workspace
```

---

## 14. Exam Tips and Practice Questions

### 14.1 Key Exam Topics Summary

**Most Important Topics (Expect Multiple Questions):**

1. ⭐⭐⭐⭐⭐ **ASR Rules** - Configuration, GUIDs, use cases
2. ⭐⭐⭐⭐⭐ **Advanced Hunting (KQL)** - Write queries, hunt threats
3. ⭐⭐⭐⭐⭐ **Device Actions** - Isolate, live response, collect packages
4. ⭐⭐⭐⭐⭐ **Automated Investigation** - AIR configuration, action center
5. ⭐⭐⭐⭐⭐ **Vulnerability Management** - TVM, remediation, exposure score
6. ⭐⭐⭐⭐ **Plan 1 vs Plan 2** - Feature differences
7. ⭐⭐⭐⭐ **Device Groups** - Configuration, automation levels
8. ⭐⭐⭐⭐ **Custom Detections** - Create rules from KQL queries
9. ⭐⭐⭐⭐ **Incident Investigation** - Timeline, evidence analysis
10. ⭐⭐⭐⭐ **Integration** - Microsoft 365 Defender, Sentinel

**Less Emphasized (But Still Important):**

- MMA vs Unified Agent (know that MMA is deprecated)
- Network protection configuration
- Device control policies
- Onboarding methods (GPO, Intune, MECM)

### 14.2 Common Exam Traps

**Trap 1: MMA Agent**
```
Question: "How do you onboard Windows Server 2016?"

Wrong Answer: "Install MMA with workspace ID and key"
✅ Right Answer: "Use unified MDE agent (md4ws_installer.msi)"

Explanation: MMA was deprecated Aug 2024. Server 2016 now uses unified agent.
```

**Trap 2: Plan 1 Features**
```
Question: "You have Plan 1. Can you use advanced hunting?"

❌ Wrong Answer: "Yes, advanced hunting is available in Plan 1"
✅ Right Answer: "No, advanced hunting requires Plan 2"

Explanation: Plan 1 is prevention only. All investigation features need Plan 2.
```

**Trap 3: ASR Rule Actions**
```
Question: "What value sets an ASR rule to Audit mode?"

❌ Wrong Answer: "0 = Audit"
✅ Right Answer: "2 = Audit mode"

Values: 0 = Disabled, 1 = Block, 2 = Audit, 6 = Warn
```

**Trap 4: Device Isolation**
```
Question: "When a device is isolated, can it still communicate with MDE?"

❌ Wrong Answer: "No, all network traffic is blocked"
✅ Right Answer: "Yes, MDE sensor communication is allowed"

Explanation: Isolation allows ONLY MDE sensor traffic, nothing else.
```

**Trap 5: Automated Investigation**
```
Question: "Can you configure different automation levels per device?"

❌ Wrong Answer: "Yes, set automation level on each device"
✅ Right Answer: "No, automation levels are set per device GROUP"

Explanation: Automation is configured at device group level, not individual devices.
```

**Trap 6: Timeline Retention**
```
Question: "How long is device timeline data retained?"

❌ Wrong Answer: "90 days"
✅ Right Answer: "6 months (180 days)"

Advanced hunting: 30 days
Device timeline: 6 months
```

**Trap 7: Live Response**
```
Question: "Which command can undo a previous remediation action?"

❌ Wrong Answer: "rollback"
✅ Right Answer: "undo <action_id>"

New command in 2025: undo
```

**Trap 8: Custom Detections**
```
Question: "Where do you create custom detection rules?"

❌ Wrong Answer: "Advanced hunting only"
✅ Right Answer: "Settings → Custom detections OR from advanced hunting"

Can create from both locations.
```

### 14.3 Practice Questions

#### **Question 1: ASR Configuration**

You need to configure Attack Surface Reduction rules for your organization. The business requires:
- Block Office apps from creating child processes
- Allow testing mode for 30 days before enforcing
- Exclude a business-critical macro-enabled document

What should you configure?

**A)** Set ASR rule to Block mode, add document to antivirus exclusions
**B)** Set ASR rule to Audit mode, add document to ASR exclusions
**C)** Set ASR rule to Warn mode, add document to ASR exclusions
**D)** Set ASR rule to Disabled, add document to antivirus exclusions

<details>
<summary>Click to see answer</summary>

**✅ Answer: B**

Explanation:
- Audit mode = testing mode (logs but doesn't block)
- ASR exclusions = specific exclusions for ASR rules
- After 30 days, change to Block mode
- Antivirus exclusions are separate from ASR exclusions
</details>

#### **Question 2: Plan Selection**

A security operations center (SOC) needs to:
- Hunt for threats across the environment
- Create custom detection rules
- Automate incident response
- Investigate incidents with KQL queries

Which Microsoft Defender for Endpoint plan should they deploy?

**A)** Plan 1
**B)** Plan 2
**C)** Either plan is sufficient
**D)** Plan 1 plus Vulnerability Management add-on

<details>
<summary>Click to see answer</summary>

**✅ Answer: B**

Explanation:
- Advanced hunting (KQL) = Plan 2 only
- Custom detections = Plan 2 only
- Automated investigation = Plan 2 only
- Plan 1 = Prevention only (no investigation features)
</details>

#### **Question 3: Device Isolation**

You isolate a device due to active malware. The user reports they can still access:
- Local applications
- Local files
- MDE portal (security.microsoft.com)

Which behavior is INCORRECT for device isolation?

**A)** User can access local applications
**B)** User can access local files
**C)** User can access MDE portal
**D)** All behaviors are correct

<details>
<summary>Click to see answer</summary>

**✅ Answer: C**

Explanation:
- Isolation blocks ALL network access except MDE sensor
- User CANNOT access any websites, including MDE portal
- Can only access local resources
- Cannot access internet or internal network
</details>

#### **Question 4: KQL Query**

You need to create a query to find devices where PowerShell was used to download files from the internet in the last 24 hours. Which query should you use?

**A)**
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where Timestamp > ago(24h)
```

**B)**
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "DownloadString"
| where Timestamp > ago(1d)
```

**C)**
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| where Timestamp > ago(1d)
```

**D)**
```kql
DeviceFileEvents
| where InitiatingProcessFileName == "powershell.exe"
| where Timestamp > ago(1d)
```

<details>
<summary>Click to see answer</summary>

**✅ Answer: B**

Explanation:
- Need to check ProcessCommandLine for download indicators
- "DownloadString" is common PowerShell download method
- Option A doesn't check command line
- Options C & D use wrong tables
- ago(1d) = last 24 hours
</details>

#### **Question 5: Vulnerability Management**

Your organization's exposure score is 850 (High). The TVM dashboard shows:
- 15 critical vulnerabilities affecting 200 devices
- 50 high vulnerabilities affecting 500 devices
- 100 medium vulnerabilities affecting 800 devices

Which action will have the GREATEST impact on reducing exposure score?

**A)** Remediate all medium vulnerabilities first (most devices)
**B)** Remediate critical vulnerabilities first (highest severity)
**C)** Remediate vulnerabilities with active exploits first
**D)** Remediate based on TVM's prioritized recommendations

<details>
<summary>Click to see answer</summary>

**✅ Answer: D**

Explanation:
- TVM calculates exposure impact for each recommendation
- Considers: severity, exploitability, exposed devices, business impact
- Follow TVM's prioritization (highest exposure impact first)
- Not always critical = highest impact
- Sometimes high on many devices > critical on few devices
</details>

#### **Question 6: Automated Investigation**

You configure device groups with automation levels:
- Workstations: Full automation
- Servers: Semi - require approval for any folders
- Development: No automation

A malware alert triggers on a server. What happens?

**A)** Alert closes automatically, no action taken
**B)** Investigation runs, actions execute automatically
**C)** Investigation runs, actions pending in Action Center
**D)** Alert generates but no investigation starts

<details>
<summary>Click to see answer</summary>

**✅ Answer: C**

Explanation:
- Semi automation = Investigation runs automatically
- Actions require approval (appear in Action Center)
- SOC analyst must review and approve remediation
- Full automation = auto-remediation
- No automation = no investigation at all
</details>

#### **Question 7: Live Response**

During a live response session, you need to:
1. Download a suspicious file for analysis
2. Upload a remediation script
3. Run the script
4. Undo the remediation if it causes issues

Which commands should you use?

**A)** get, put, run, rollback
**B)** getfile, putfile, remediate, undo
**C)** download, upload, execute, revert
**D)** collect, deploy, run, restore

<details>
<summary>Click to see answer</summary>

**✅ Answer: B**

Explanation:
- getfile = Download file from device
- putfile = Upload file to device
- remediate = Run remediation script
- undo = Undo previous action (new in 2025)
</details>

#### **Question 8: Custom Detection**

You create a custom detection rule to find credential dumping. The rule triggers 50 alerts on the first day, but 45 are false positives from a backup tool. What should you do?

**A)** Delete the custom detection rule
**B)** Add the backup tool path to ASR exclusions
**C)** Modify the KQL query to exclude the backup tool process
**D)** Change alert severity to Low

<details>
<summary>Click to see answer</summary>

**✅ Answer: C**

Explanation:
- Tune the query to exclude known good processes
- Add: | where InitiatingProcessFileName !~ "BackupTool.exe"
- ASR exclusions don't affect custom detections
- Lowering severity doesn't fix false positives
- Don't delete rule, improve it
</details>

#### **Question 9: Attack Surface Reduction**

You enable the ASR rule "Block credential stealing from Windows local security authority subsystem (lsass.exe)". A legitimate IT tool gets blocked. What should you do?

**A)** Disable the ASR rule
**B)** Add the tool to ASR exclusions
**C)** Change ASR rule to Audit mode
**D)** Contact vendor for updated tool

<details>
<summary>Click to see answer</summary>

**✅ Answer: B**

Explanation:
- ASR exclusions allow specific files/folders to bypass rules
- Keeps protection active for everything else
- Audit mode would allow ALL credential access (not secure)
- Disabling rule leaves entire organization vulnerable
- ASR exclusions are the correct solution
</details>

#### **Question 10: Incident Response**

An incident shows:
- Initial access: Phishing email (MDO)
- Credential theft: Mimikatz on WKS-001 (MDE)
- Lateral movement: RDP to SVR-001 (MDE)
- Data exfiltration: Files uploaded to cloud (MDCA)

What is the BEST first response action?

**A)** Delete the phishing email
**B)** Isolate WKS-001
**C)** Disable the compromised user account
**D)** Block the cloud storage URL

<details>
<summary>Click to see answer</summary>

**✅ Answer: C**

Explanation:
- Credential theft means attacker has user credentials
- Must disable account to prevent further access
- Even if you isolate WKS-001, attacker can use creds elsewhere
- Then: Isolate devices, delete emails, block URLs
- Order: Stop access (disable user) → Contain (isolate) → Clean up
</details>

---

## 15. Summary and Final Exam Tips

### 15.1 Critical Topics Checklist

Before the exam, ensure you know:

**✅ MDE Architecture and Plans**
- [ ] Understand 6 pillars of MDE
- [ ] Know Plan 1 vs Plan 2 differences (critical!)
- [ ] Remember unified agent replaces MMA (Server 2012 R2/2016)
- [ ] Know which features require Plan 2 (EDR, AIR, hunting, TVM)

**✅ Onboarding and Configuration**
- [ ] Onboarding methods (GPO, Intune, MECM)
- [ ] Prerequisites per OS
- [ ] Advanced features configuration
- [ ] Device groups and automation levels

**✅ Attack Surface Reduction**
- [ ] Key ASR rules and their GUIDs
- [ ] ASR rule actions (0=Disabled, 1=Block, 2=Audit, 6=Warn)
- [ ] Network protection, web protection, device control
- [ ] Controlled folder access

**✅ Vulnerability Management**
- [ ] Exposure score and what affects it
- [ ] Security recommendations prioritization
- [ ] Remediation tasks and tracking
- [ ] Device exposure levels

**✅ Threat Response**
- [ ] Device actions (isolate, restrict, collect package)
- [ ] Investigation package contents
- [ ] Device timeline analysis
- [ ] Evidence and entity investigation

**✅ Live Response**
- [ ] When to use live response
- [ ] Common commands (connections, processes, getfile, etc.)
- [ ] Remediation and undo capabilities
- [ ] Advanced vs basic permissions

**✅ Advanced Hunting**
- [ ] KQL syntax and operators
- [ ] Key tables (DeviceProcessEvents, DeviceNetworkEvents, etc.)
- [ ] Common hunting queries
- [ ] Time functions (ago, between)

**✅ Custom Detections**
- [ ] Create detection rules from queries
- [ ] Configure alert details
- [ ] Set automation actions
- [ ] Tune false positives

**✅ Integration**
- [ ] Microsoft 365 Defender unified incidents
- [ ] Automatic attack disruption
- [ ] Cross-product hunting
- [ ] Security Copilot capabilities

**✅ Troubleshooting**
- [ ] Common onboarding issues
- [ ] Sense service troubleshooting
- [ ] Performance issues
- [ ] Alert and detection problems

### 15.2 Last-Minute Study Tips

**3 Days Before Exam:**
- Review ASR rule GUIDs and actions
- Practice KQL queries (write 10 queries from scratch)
- Review Plan 1 vs Plan 2 table
- Go through common exam traps

**1 Day Before Exam:**
- Review this summary section
- Focus on high-value topics (ASR, KQL, device actions)
- Practice reading scenarios carefully
- Get good sleep!

**Day of Exam:**
- Read questions carefully (look for key words)
- Watch for exam traps (MMA, Plan 1 features, etc.)
- Manage time (100 minutes, ~40-60 questions)
- Flag uncertain questions and return

### 15.3 Exam Day Strategy

**Reading Questions:**
- Read the scenario completely
- Identify what they're really asking
- Look for key words: "BEST", "FIRST", "MOST", "LEAST"
- Eliminate obviously wrong answers

**Time Management:**
- Spend ~1.5-2 minutes per question
- Don't spend more than 3 minutes on any single question
- Flag and move on if stuck
- Review flagged questions at end

**Common Question Patterns:**
```
Pattern 1: "You need to..."
→ Looking for configuration steps

Pattern 2: "What should you do FIRST?"
→ Looking for proper response order

Pattern 3: "Which plan should you deploy?"
→ Testing Plan 1 vs Plan 2 knowledge

Pattern 4: "Complete the KQL query..."
→ Testing KQL syntax knowledge

Pattern 5: "What happens when..."
→ Testing understanding of behavior
```

### 15.4 Final Thoughts

**You're Ready If:**
- ✅ You can explain Plan 1 vs Plan 2 differences
- ✅ You can write basic KQL queries from scratch
- ✅ You know ASR rule actions and common rules
- ✅ You understand device actions and when to use them
- ✅ You can describe the incident response workflow
- ✅ You know how to configure automation levels
- ✅ You understand MDE integration with M365 Defender

**Remember:**
- SC-200 tests **practical application**, not just theory
- Focus on **HOW** to do things, not just WHAT things are
- **Scenario-based questions** dominate the exam
- **Hands-on experience** with MDE portal is invaluable
- **Read carefully** - watch for traps

**Good luck with your SC-200 exam! 🚀**

---

## 16. Important Acronyms Quick Reference

| Acronym | Full Term |
|---------|-----------|
| **MDE** | Microsoft Defender for Endpoint |
| **EDR** | Endpoint Detection and Response |
| **AIR** | Automated Investigation and Remediation |
| **ASR** | Attack Surface Reduction |
| **TVM** | Threat and Vulnerability Management |
| **MDVM** | Microsoft Defender Vulnerability Management |
| **MMA** | Microsoft Monitoring Agent (deprecated Aug 2024) |
| **MDAV** | Microsoft Defender Antivirus |
| **KQL** | Kusto Query Language |
| **RBAC** | Role-Based Access Control |
| **URBAC** | Unified Role-Based Access Control (new 2025) |
| **GPO** | Group Policy Object |
| **MECM** | Microsoft Endpoint Configuration Manager (formerly SCCM) |
| **MEM** | Microsoft Endpoint Manager (includes Intune) |
| **M365D** | Microsoft 365 Defender |
| **MDI** | Microsoft Defender for Identity |
| **MDO** | Microsoft Defender for Office 365 |
| **MDCA** | Microsoft Defender for Cloud Apps |
| **XDR** | Extended Detection and Response |
| **C2** | Command and Control |
| **CVE** | Common Vulnerabilities and Exposures |
| **CVSS** | Common Vulnerability Scoring System |
| **MITRE ATT&CK** | MITRE Adversarial Tactics, Techniques, and Common Knowledge |
| **SOC** | Security Operations Center |
| **IOC** | Indicator of Compromise |
| **APT** | Advanced Persistent Threat |

---

**Document Version:** 2.0 - Complete Edition (October 2025)
**Aligned with:** SC-200 Exam Objectives (April 21, 2025 Update)
**Next Update:** After any major exam changes or product updates

---

**End of Module 1 - Microsoft Defender for Endpoint**

*Continue to Module 2: Microsoft Defender for Identity for identity protection and detection capabilities.*

**Best wishes for your SC-200 certification journey! 💪🎓**
