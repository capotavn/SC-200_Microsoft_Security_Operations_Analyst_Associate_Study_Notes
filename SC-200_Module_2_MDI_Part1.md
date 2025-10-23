# SC-200 Study Notes - Module 2: Microsoft Defender for Identity (MDI)
## 📘 Complete Guide - Updated for SC-200 Exam (April 21, 2025)

**Exam Weight:** This content supports multiple exam objectives accounting for **~10-15%** of the exam
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest MDI Updates (Sept-Oct 2025)

---

## 🎯 SC-200 Exam Objectives Covered in This Module

### **From "Manage incident response" (25-30%)**
- ✅ Investigate and remediate compromised identities identified by Microsoft Entra ID
- ✅ Investigate and remediate security alerts from Microsoft Defender for Identity

### **From "Configure protections and detections" (15-20%)**
- ✅ Configure detections in Microsoft Defender XDR (includes MDI alerts)
- ✅ Classify and analyze data by using entities (identity entities)

### **From "Manage security threats" (15-20%)**
- ✅ Hunt for threats by using Microsoft Defender XDR (identity-based threats)
- ✅ Analyze attack vector coverage by using the MITRE ATT&CK matrix (identity tactics)

### **Cross-Module Integration:**
- ✅ Microsoft 365 Defender unified incidents (identity + endpoint + email)
- ✅ Automatic attack disruption (identity containment)
- ✅ Advanced hunting (IdentityLogonEvents, IdentityQueryEvents, etc.)

---

## 📚 Table of Contents

1. [MDI Overview and Architecture](#1-mdi-overview-and-architecture)
2. [Prerequisites and Licensing](#2-prerequisites-and-licensing)
3. [Deployment Models: Sensor v2 vs v3](#3-deployment-models-sensor-v2-vs-v3)
4. [Sensor Deployment and Configuration](#4-sensor-deployment-and-configuration)
5. [Identity Security Posture Assessments](#5-identity-security-posture-assessments)
6. [Detection Capabilities and Alert Types](#6-detection-capabilities-and-alert-types)
7. [Lateral Movement Path Analysis](#7-lateral-movement-path-analysis)
8. [Honeytoken Accounts (Deception)](#8-honeytoken-accounts-deception)
9. [Investigate and Remediate Identity Threats](#9-investigate-and-remediate-identity-threats)
10. [Integration with Microsoft 365 Defender](#10-integration-with-microsoft-365-defender)
11. [Advanced Hunting for Identity Threats](#11-advanced-hunting-for-identity-threats)
12. [ITDR (Identity Threat Detection and Response)](#12-itdr-identity-threat-detection-and-response)
13. [Configuration and Best Practices](#13-configuration-and-best-practices)
14. [Troubleshooting Common Issues](#14-troubleshooting-common-issues)
15. [Exam Tips and Practice Questions](#15-exam-tips-and-practice-questions)

---

## 1. MDI Overview and Architecture

### 1.1 What is Microsoft Defender for Identity?

Microsoft Defender for Identity (MDI), formerly Azure Advanced Threat Protection (Azure ATP), is a **cloud-based security solution** that leverages **on-premises Active Directory signals** to:

- **Identify** sophisticated attacks targeting your organization
- **Detect** compromised identities and malicious insider actions
- **Investigate** suspicious user activities and advanced attacks
- **Provide** clear, actionable security posture recommendations

### 1.2 Core Capabilities

```
Microsoft Defender for Identity
│
├─ 1️⃣ Identity Threat Detection & Response (ITDR)
│   ├─ Detect privilege escalation
│   ├─ Identify lateral movement
│   ├─ Spot reconnaissance activities
│   └─ Alert on domain dominance attempts
│
├─ 2️⃣ Identity Security Posture Management (ISPM)
│   ├─ Assess misconfigurations
│   ├─ Identify weak points
│   ├─ Recommend improvements
│   └─ Track remediation progress
│
├─ 3️⃣ User & Entity Behavior Analytics (UEBA)
│   ├─ Baseline normal behavior
│   ├─ Detect anomalies
│   ├─ Identify compromised accounts
│   └─ Spot insider threats
│
├─ 4️⃣ Lateral Movement Path (LMP) Analysis
│   ├─ Map attack paths to sensitive accounts
│   ├─ Identify vulnerable routes
│   ├─ Show exposure to domain admins
│   └─ Recommend protective actions
│
└─ 5️⃣ Deception (Honeytokens)
    ├─ Create fake accounts (honeytoken)
    ├─ Monitor for use/access
    ├─ Instant alerts on compromise
    └─ Early attack detection
```

### 1.3 Supported Identity Infrastructure

| Component | Support Status | Sensor Required | Notes |
|-----------|----------------|----------------|-------|
| **Active Directory Domain Controllers** | ✅ Full Support | Yes (v2 or v3) | Primary deployment target |
| **Read-Only Domain Controllers (RODC)** | ✅ Full Support | Yes (v2 or v3) | Same capabilities as writable DCs |
| **AD FS (Federation Services)** | ✅ Full Support | Yes (v2 only) | Detects federation attacks |
| **AD CS (Certificate Services)** | ✅ Full Support | Yes (v2 only) | 🆕 Added 2024-2025 |
| **Microsoft Entra Connect** | ✅ Full Support | Yes (v2 only) | Sync server protection |
| **Multi-forest AD** | ✅ Partial Support | Yes | Requires trust relationships |
| **Azure AD / Entra ID** | ✅ Integration | No | Via M365 Defender correlation |

**🚨 IMPORTANT (2025 Update):**
- **Sensor v3.x (Unified):** Only supports Domain Controllers (Windows Server 2019+)
- **Sensor v2.x (Classic):** Supports all components (DC, AD FS, AD CS, Entra Connect)
- **Cannot mix v2 and v3 in same environment!**

### 1.4 Architecture Overview

```
On-Premises Environment
│
├─ Domain Controllers (DCs)
│  └─ MDI Sensor installed
│     ├─ Monitors network traffic
│     ├─ Reads event logs (4624, 4625, 4776, etc.)
│     ├─ Analyzes Kerberos, NTLM, DNS
│     └─ Sends parsed data to cloud
│
├─ AD FS Servers
│  └─ MDI Sensor (v2 only)
│     └─ Monitors authentication events
│
├─ AD CS Servers (🆕 2024-2025)
│  └─ MDI Sensor (v2 only)
│     └─ Monitors certificate requests/issuance
│
└─ Entra Connect Servers
   └─ MDI Sensor (v2 only)
      └─ Monitors sync activities

            ↓ HTTPS (Encrypted)

Microsoft Defender for Identity Cloud Service
│
├─ Data Processing
│  ├─ Machine learning analysis
│  ├─ Behavioral analytics
│  ├─ Threat intelligence correlation
│  └─ Attack detection algorithms
│
├─ Alerts & Incidents
│  └─ Generated based on detections
│
└─ Integration Layer
   ├─ Microsoft 365 Defender Portal
   ├─ Microsoft Sentinel
   └─ Microsoft Secure Score

            ↓

Security Analysts
└─ Investigate and respond via Microsoft Defender Portal
```

### 1.5 Data Flow

**What MDI Sensor Collects:**

1. **Network Traffic** (Domain Controller only)
   - Kerberos authentication (Port 88)
   - NTLM authentication
   - DNS queries (Port 53)
   - LDAP queries (Port 389/636)
   - SMB sessions (Port 445)

2. **Windows Event Logs**
   - Security logs (Event IDs: 4624, 4625, 4776, 4768, 4769, 4771, etc.)
   - System logs (relevant events)
   - Directory Service logs

3. **Active Directory Queries**
   - User and group information
   - Computer accounts
   - Group Policy Objects
   - Security permissions
   - Service Principal Names (SPNs)

**What Gets Sent to Cloud:**
- ✅ **Parsed metadata** (who, what, when, where)
- ✅ **Behavioral indicators** (anomalies, suspicious patterns)
- ✅ **Entity information** (users, computers, groups)
- ❌ **NO raw passwords or credentials**
- ❌ **NO full packet captures**
- ❌ **NO file contents**

### 1.6 Key Differentiators

**MDI vs Traditional IDS/IPS:**
- ✅ **Identity-focused:** Understands AD-specific attacks
- ✅ **Behavioral analytics:** Learns normal user behavior
- ✅ **Attack path analysis:** Shows routes to sensitive accounts
- ✅ **Zero configuration:** No signatures to update
- ✅ **Cloud-powered:** ML models continuously updated

**MDI vs Microsoft Defender for Endpoint:**
| Feature | MDI | MDE |
|---------|-----|-----|
| **Focus** | Identity infrastructure (AD) | Endpoint devices |
| **Deployment** | Sensor on DCs | Agent on endpoints |
| **Primary Threats** | Pass-the-hash, Golden Ticket, DCSync | Malware, ransomware, exploits |
| **Attack Surface** | AD, Kerberos, NTLM | Files, processes, registry |
| **Response Actions** | Disable user, reset password | Isolate device, quarantine file |

**🎯 Exam Tip:** MDI and MDE work together in M365 Defender to provide comprehensive protection. MDI protects identity infrastructure while MDE protects endpoints.

---

## 2. Prerequisites and Licensing

### 2.1 Licensing Requirements

**Microsoft Defender for Identity requires ONE of:**

| License | Includes MDI | Cost | Best For |
|---------|--------------|------|----------|
| **Microsoft 365 E5** | ✅ Included | ~$57/user/mo | Full enterprise suite |
| **Microsoft 365 E5 Security** | ✅ Included | ~$12/user/mo | Security-focused orgs |
| **Microsoft 365 A5** | ✅ Included | Academic pricing | Educational institutions |
| **Enterprise Mobility + Security E5 (EMS E5)** | ✅ Included | ~$16/user/mo | Identity + device mgmt |
| **Microsoft Defender for Identity Standalone** | ✅ Yes | ~$5/user/mo | MDI only |

**🚨 Important Notes:**
- User-based licensing (not per-sensor)
- Covers all identities in your organization
- No separate licensing for sensors
- Trial available: 90 days free

### 2.2 System Requirements

#### **For Sensor v2.x (Classic)**

**Supported Operating Systems:**

| OS | Version | Status | Notes |
|----|---------|--------|-------|
| **Windows Server 2025** | RTM | ⚠️ Limited Support (Oct 2025) | Some features pending |
| **Windows Server 2022** | All editions | ✅ Fully Supported | Recommended |
| **Windows Server 2019** | All editions | ✅ Fully Supported | Requires KB4487044+ |
| **Windows Server 2016** | All editions | ✅ Fully Supported | - |
| **Windows Server 2012 R2** | All editions | ⚠️ Extended Support Ended (Oct 2023) | Still works but not recommended |
| **Windows Server 2012** | All editions | ⚠️ Extended Support Ended (Oct 2023) | Still works but not recommended |

**Server Types Supported:**
- ✅ Desktop Experience (Full GUI)
- ✅ Server Core
- ❌ Nano Server (NOT supported)

**Hardware Requirements (Per DC):**

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 6 GB | 10+ GB |
| **Disk Space** | 6 GB | 10+ GB |
| **Network** | 1 Gbps | 10 Gbps (large environments) |

**Software Prerequisites:**
- ✅ .NET Framework 4.7 or later
- ✅ PowerShell 5.1 or later (for configuration)
- ✅ TLS 1.2 or later enabled

**🎯 Exam Tip:** MDI sensor reserves **15% of CPU and memory** on the DC. If it exceeds this, sensor automatically throttles or restarts.

#### **For Sensor v3.x (Unified - Preview as of Oct 2025)**

**Supported Operating Systems:**
- ✅ Windows Server 2019 or later
- ✅ Windows Server 2022 (recommended)
- ❌ Windows Server 2016 and earlier (NOT supported)

**Deployment Method:**
- ✅ No manual installation required
- ✅ Activated via Microsoft Defender portal
- ✅ Leverages Defender for Endpoint infrastructure

**⚠️ Sensor v3.x Limitations (Preview):**
- Only for Domain Controllers (no AD FS, AD CS, Entra Connect)
- Reduced functionality for:
  - Health alerts
  - Security posture assessments
  - Some security alerts
  - Advanced hunting data (limited)
- Cannot coexist with v2.x sensors in same environment

**When to Use v2.x vs v3.x:**

```
Decision Tree:

Do you have AD FS, AD CS, or Entra Connect?
├─ Yes → Use v2.x (Classic)
└─ No → Continue...

Are all DCs Windows Server 2019+?
├─ Yes → Can use v3.x (Unified) ✅
└─ No (mix of 2016/2012 R2) → Use v2.x (Classic)

Do you need full feature set?
├─ Yes (production) → Use v2.x (Classic) ✅
└─ No (testing) → Can try v3.x (Unified)
```

**🚨 Exam Critical:** You CANNOT mix v2.x and v3.x sensors in the same environment. If you have even ONE Server 2016 DC, you must use v2.x for ALL sensors.

### 2.3 Network Requirements

**Required Outbound Connectivity (HTTPS 443):**

**For Sensor v2.x:**
```
*.atp.azure.com              - MDI cloud service
*.atp.azure.us               - Government clouds
*.blob.core.windows.net      - Updates and diagnostics
nortauprod<region>.blob.core.windows.net  - Telemetry
```

**For Sensor v3.x:**
- Leverages Defender for Endpoint network requirements
- See Module 1 for MDE network requirements

**Internal Requirements:**
- ✅ All DCs must communicate with each other
- ✅ Sensor must access local event logs
- ✅ Sensor must capture network traffic on DC
- ✅ LDAP/LDAPS access to AD (389/636)

**Firewall Rules (if needed):**
- Allow outbound HTTPS (443) from DCs to *.atp.azure.com
- Allow port 88 (Kerberos) traffic monitoring
- Allow port 389/636 (LDAP) queries

**Proxy Configuration:**
```powershell
# Configure proxy for sensor v2.x
$proxyUrl = "http://proxy.company.com:8080"
$proxyUser = "DOMAIN\ProxyUser"
$proxyPassword = ConvertTo-SecureString "password" -AsPlainText -Force
$proxyCreds = New-Object System.Management.Automation.PSCredential($proxyUser, $proxyPassword)

# Set proxy via sensor config tool
# Or via registry:
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure Advanced Threat Protection\Sensor\Configuration" `
  -Name "ProxyUrl" -Value $proxyUrl
```

### 2.4 Permission Requirements

**Azure/Entra ID Roles (for workspace creation):**

| Task | Required Role |
|------|--------------|
| **Create MDI workspace** | Global Administrator or Security Administrator |
| **Configure sensors** | Security Administrator |
| **View alerts** | Security Reader |
| **Investigate incidents** | Security Operator |
| **Manage permissions** | Global Administrator |

**Active Directory Permissions (for sensor service account):**

**Directory Services Account (DSA):**
- Used by sensor to query AD
- Required permissions:
  - ✅ **Read** permissions on **Deleted Objects** container
  - ✅ **Read** permissions on all objects in domain
  - ✅ **No write or modify permissions needed**

**Create DSA Account:**
```powershell
# Create dedicated service account for MDI
New-ADUser -Name "MDI_Sensor" `
  -SamAccountName "MDI_Sensor" `
  -UserPrincipalName "MDI_Sensor@contoso.com" `
  -AccountPassword (ConvertTo-SecureString "ComplexP@ssw0rd!" -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true

# Grant permissions to Deleted Objects container
# (Use MDI Configuration PowerShell module)
Set-MDIConfiguration -Mode Domain -Configuration DeletedObjectsAuditing
```

**gMSA Support (🆕 Recommended 2025):**
- Group Managed Service Accounts supported
- Better security (automatic password rotation)
- Simplified management in multi-forest environments

```powershell
# Create gMSA for MDI
New-ADServiceAccount -Name "MDI_gMSA" `
  -DNSHostName "MDI_gMSA.contoso.com" `
  -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers"

# Install on DC
Install-ADServiceAccount -Identity "MDI_gMSA"
```

### 2.5 Event Logging Requirements

**Critical Windows Events for MDI:**

MDI relies on specific Windows event logs for detection. These must be enabled:

**Required Event IDs:**

| Event ID | Category | Purpose | Enable Via |
|----------|----------|---------|------------|
| **4776** | NTLM Authentication | Detect pass-the-hash | Default enabled |
| **4624** | Successful Logon | Track authentication | Default enabled |
| **4625** | Failed Logon | Detect brute force | Default enabled |
| **4768** | Kerberos TGT Request | Monitor Kerberos | Advanced Audit Policy |
| **4769** | Kerberos Service Ticket | Detect Golden Ticket | Advanced Audit Policy |
| **4771** | Kerberos Pre-auth Failed | Detect AS-REP Roasting | Advanced Audit Policy |
| **7045** | Service Installation | Detect suspicious services | Default enabled |
| **4662** | Object Access | Detect DCSync, DCShadow | Advanced Audit Policy |
| **4726** | User Deleted | Track account changes | Default enabled |
| **4728, 4732, 4756** | Group Membership | Track sensitive group changes | Default enabled |

**Configure Advanced Audit Policies:**

**Manual Configuration (Group Policy):**
```
Computer Configuration
└─ Policies
   └─ Windows Settings
      └─ Security Settings
         └─ Advanced Audit Policy Configuration
            └─ Audit Policies
               ├─ Account Logon
               │  ├─ Audit Kerberos Authentication Service: Success & Failure
               │  └─ Audit Kerberos Service Ticket Operations: Success & Failure
               ├─ Account Management
               │  └─ Audit Security Group Management: Success
               ├─ DS Access
               │  └─ Audit Directory Service Access: Success & Failure
               └─ Logon/Logoff
                  └─ Audit Logon: Success & Failure
```

**Automated Configuration (MDI PowerShell Module):**

```powershell
# Install MDI Configuration module
Install-Module -Name DefenderForIdentity -Force

# Configure all required audit policies
Set-MDIConfiguration -Mode Domain -Configuration All

# What this configures:
# - Advanced Audit Policies
# - Object Auditing on domain
# - Deleted Objects container permissions
# - Creates and links GPOs automatically
```

**Verify Configuration:**
```powershell
# Test readiness
Test-MdiReadiness.ps1

# Output shows:
# ✅ Event logs configured correctly
# ✅ Permissions set correctly
# ❌ Issues found (with remediation steps)
```

**🎯 Exam Tip:** Event ID 4662 (object access) is critical for detecting **DCSync** and **DCShadow** attacks. Without it, MDI cannot detect these advanced attacks.

---

## 3. Deployment Models: Sensor v2 vs v3

### 3.1 Sensor Architecture Comparison

**🆕 Major Change (2024-2025):** Microsoft introduced sensor v3.x (Unified) that leverages Defender for Endpoint infrastructure.

```
Sensor v2.x (Classic)                  Sensor v3.x (Unified)
│                                      │
├─ Manual Installation                 ├─ Automatic Activation
├─ Standalone Agent                    ├─ Uses MDE Infrastructure
├─ Separate Updates                    ├─ Unified Updates
├─ All Server Types Supported          ├─ DCs Only (Server 2019+)
└─ Full Feature Set                    └─ Limited Features (Preview)
```

### 3.2 Feature Comparison Table

| Feature | v2.x (Classic) | v3.x (Unified) | Exam Importance |
|---------|----------------|----------------|-----------------|
| **Installation Method** | Manual (setup.exe) | Automatic activation | ⭐⭐⭐⭐⭐ Critical |
| **Prerequisites** | .NET 4.7+ | MDE onboarded | ⭐⭐⭐⭐ High |
| **Supported Servers** | DC, AD FS, AD CS, Entra Connect | DC only | ⭐⭐⭐⭐⭐ Critical |
| **OS Support** | Server 2012+ | Server 2019+ | ⭐⭐⭐⭐⭐ Critical |
| **Can Coexist?** | No | No (with v2.x) | ⭐⭐⭐⭐ High |
| **Update Mechanism** | Cloud push | MDE updates | ⭐⭐⭐ Medium |
| **Health Alerts** | Full | Limited (Preview) | ⭐⭐⭐⭐ High |
| **Security Alerts** | Full | Limited (Preview) | ⭐⭐⭐⭐⭐ Critical |
| **Posture Assessments** | Full | Limited (Preview) | ⭐⭐⭐⭐ High |
| **Advanced Hunting** | Full tables | Limited data (Preview) | ⭐⭐⭐⭐⭐ Critical |
| **Lateral Movement Paths** | Full | Limited (Preview) | ⭐⭐⭐⭐ High |
| **Production Ready** | ✅ Yes | ⚠️ Preview (Oct 2025) | ⭐⭐⭐⭐⭐ Critical |

### 3.3 Decision Matrix

**When to Use Sensor v2.x (Classic):**

✅ **Must Use v2.x If:**
- You have AD FS, AD CS, or Entra Connect servers
- Any DCs run Windows Server 2016 or earlier
- You need full feature set for production
- You need complete security posture assessments
- You want all advanced hunting tables

✅ **Recommended for:**
- Production environments (as of Oct 2025)
- Organizations with hybrid infrastructure
- Compliance-driven environments
- Full MDI feature requirements

**When to Use Sensor v3.x (Unified):**

✅ **Can Use v3.x If:**
- All DCs are Windows Server 2019 or later
- No AD FS, AD CS, or Entra Connect to protect
- All DCs already have MDE deployed
- Testing/dev environment
- Willing to accept limited features (preview)

✅ **Benefits:**
- No manual installation required
- Centralized management via Defender portal
- Unified update mechanism
- Simplified deployment at scale

⚠️ **Current Limitations (Oct 2025):**
- Preview status (not recommended for production)
- Limited detection coverage
- Reduced advanced hunting data
- Cannot protect AD FS/AD CS/Entra Connect

### 3.4 Deployment Scenarios

#### **Scenario 1: All Modern DCs**

```
Environment:
- 5 Domain Controllers
- All running Windows Server 2022
- No AD FS or AD CS
- MDE already deployed

Recommended: Sensor v3.x (Unified) ✅
Reason: Simplified deployment, all prerequisites met

Alternative: Sensor v2.x still works but requires manual installation
```

#### **Scenario 2: Mixed DC Versions**

```
Environment:
- 3 DCs on Server 2022
- 2 DCs on Server 2016 (cannot upgrade soon)
- AD FS present

Required: Sensor v2.x (Classic) ✅✅
Reason:
1. Server 2016 doesn't support v3.x
2. AD FS requires v2.x
3. Cannot mix v2 and v3

Action: Deploy v2.x on ALL servers
```

#### **Scenario 3: Hybrid with AD FS/AD CS**

```
Environment:
- 4 DCs on Server 2019
- 2 AD FS servers
- 1 AD CS server
- 1 Entra Connect server

Required: Sensor v2.x (Classic) ✅✅
Reason: v3.x doesn't support AD FS/AD CS/Entra Connect

Deploy v2.x on:
- All 4 DCs
- Both AD FS servers
- AD CS server
- Entra Connect server
```

#### **Scenario 4: Future-Ready Deployment**

```
Environment:
- Greenfield deployment
- All new Server 2025 DCs
- No legacy infrastructure

Recommended: Plan for v3.x when GA ⚠️
Current Action: Deploy v2.x now
Reason: v3.x still in preview as of Oct 2025

Future Migration:
- Monitor for v3.x GA announcement
- Plan migration when fully supported
- Test in staging first
```

### 3.5 Migration Considerations

**Cannot Migrate Between v2 and v3 In-Place:**
- ❌ No direct upgrade path
- ❌ Cannot convert existing v2 sensor to v3
- ❌ Must uninstall v2, then activate v3

**Migration Process (When v3.x is GA):**

```
1. Planning Phase
   ├─ Verify all DCs meet v3.x requirements
   ├─ Confirm no AD FS/AD CS/Entra Connect
   ├─ Test v3.x in lab environment
   └─ Document current alert baselines

2. Preparation Phase
   ├─ Deploy MDE to all DCs (if not present)
   ├─ Verify MDE is healthy on all DCs
   ├─ Back up current MDI configuration
   └─ Schedule maintenance window

3. Migration Phase (Per DC)
   ├─ Uninstall v2.x sensor
   ├─ Reboot (recommended)
   ├─ Activate v3.x sensor via portal
   ├─ Wait for activation (up to 1 hour first time)
   └─ Verify sensor shows "Running"

4. Validation Phase
   ├─ Confirm all sensors online
   ├─ Verify alerts generating correctly
   ├─ Test lateral movement path analysis
   ├─ Validate advanced hunting data
   └─ Review health status

5. Optimization Phase
   ├─ Apply "Unified sensor RPC audit" tag (🆕)
   ├─ Tune alert thresholds if needed
   ├─ Update documentation
   └─ Train SOC team on any differences
```

**🆕 "Unified Sensor RPC Audit" Tag (2025):**

For v3.x sensors, Microsoft introduced a new capability via Asset Rule Management:

```
Purpose: Enable enhanced RPC auditing for better detection

How to Apply:
1. Navigate to: Settings → Microsoft Defender XDR → Asset Rule Management
2. Create rule:
   - Name: "Enable MDI RPC Audit"
   - Conditions: Device tag = "DomainController" AND Sensor version starts with "3."
   - Action: Add tag "Unified Sensor RPC Audit"
3. Save and apply

Benefits:
- Improved security visibility
- Additional identity detections
- Enhanced lateral movement detection
- Better coverage of RPC-based attacks
```

**🎯 Exam Tip:** For the SC-200 exam (as of Oct 2025), focus on **sensor v2.x** since it's production-ready and has full features. Be aware of v3.x limitations but don't expect deep questions on it yet.

---

## 4. Sensor Deployment and Configuration

### 4.1 Pre-Deployment Checklist

**Before Installing Any Sensor:**

✅ **Licensing**
- [ ] MDI license assigned to organization
- [ ] License covers all users/identities
- [ ] Workspace created in Microsoft Defender portal

✅ **Prerequisites Met**
- [ ] .NET Framework 4.7+ installed (v2.x)
- [ ] MDE deployed and healthy (v3.x)
- [ ] PowerShell 5.1+ available
- [ ] Outbound HTTPS 443 allowed
- [ ] Local admin rights for installation

✅ **AD Configuration**
- [ ] Event auditing configured (4776, 4768, 4769, 4662, etc.)
- [ ] DSA/gMSA account created with proper permissions
- [ ] Deleted Objects container readable
- [ ] All DCs identified for deployment

✅ **Network**
- [ ] Connectivity to *.atp.azure.com verified
- [ ] Proxy configured (if needed)
- [ ] Firewall rules updated
- [ ] DNS resolution working

### 4.2 Deploy Sensor v2.x (Classic)

#### **Step 1: Create MDI Workspace**

```
1. Navigate to Microsoft Defender portal (security.microsoft.com)
2. Settings → Identities → Setup
3. Click "Create workspace"
4. Configure:
   - Workspace name: (auto-generated based on domain)
   - Directory Service account: (use gMSA or dedicated account)
   - Skip synchronization: No (unless multi-forest)
5. Click "Create"
6. Wait for workspace creation (2-5 minutes)
```

#### **Step 2: Download Sensor Package**

```
1. Settings → Identities → Sensors
2. Click "+ Add sensor"
3. Select: "Windows Server"
4. Click "Download installer"
5. Save:
   - Azure ATP sensor Setup.exe
   - AccessKey.txt (contains workspace access key)
6. Copy both files to DC
```

#### **Step 3: Install Sensor on Domain Controller**

**Silent Installation (Recommended for Scale):**

```powershell
# Installation script
$installerPath = "C:\Temp\Azure ATP sensor Setup.exe"
$accessKey = Get-Content "C:\Temp\AccessKey.txt"

# Install silently
Start-Process -FilePath $installerPath -ArgumentList "/quiet NetFrameworkCommandLineArguments=`"/q`" AccessKey=$accessKey" -Wait

# Verify service is running
Get-Service -Name AATPSensor

# Expected output:
# Status   Name           DisplayName
# ------   ----           -----------
# Running  AATPSensor     Azure ATP Sensor
```

**Interactive Installation (For Single DC):**

```
1. Run "Azure ATP sensor Setup.exe" as Administrator
2. Welcome screen → Next
3. License terms → Accept
4. Configuration:
   - Access key: (paste from AccessKey.txt)
   - Use proxy: (if needed, configure proxy settings)
5. Install
6. Wait for installation (5-10 minutes)
7. Finish
```

#### **Step 4: Verify Sensor Installation**

**On the DC:**
```powershell
# Check sensor service
Get-Service AATPSensor

# Check sensor version
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure Advanced Threat Protection\Sensor" | Select-Object Version

# Check sensor status
Get-EventLog -LogName Application -Source "AATPSensor" -Newest 10
```

**In the Portal:**
```
1. Settings → Identities → Sensors
2. Find your DC in the list
3. Verify:
   - Status: Syncing (initial) → Running (after 10-15 min)
   - Version: Latest version
   - Health: Healthy (green checkmark)
   - Delay updates: Off
```

#### **Step 5: Configure Directory Service Account**

**Option A: Use gMSA (Recommended):**

```powershell
# On DC, after sensor installation
Install-ADServiceAccount -Identity "MDI_gMSA"

# Configure sensor to use gMSA
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure Advanced Threat Protection\Sensor\Configuration\Settings" `
  -Name "DirectoryServicesAccountName" -Value "CONTOSO\MDI_gMSA$"

# Restart sensor
Restart-Service AATPSensor
```

**Option B: Use Standard Account:**

```
1. Settings → Identities → Setup
2. Directory Services account
3. Enter:
   - Username: CONTOSO\MDI_Sensor
   - Password: (strong password)
4. Save
5. Sensor will use this account for AD queries
```

#### **Step 6: Deploy to Additional Servers**

**Deploy to All Domain Controllers:**
- Repeat installation on all writable DCs
- Repeat on all RODCs
- Use Group Policy or MECM for scale deployment

**Deploy to AD FS (if present):**
- Same installation process
- Use same access key
- Monitors federation authentication events

**Deploy to AD CS (if present - 🆕 2024-2025):**
- Same installation process
- Monitors certificate issuance
- Detects certificate-based attacks (ESC1-ESC15)

**Deploy to Entra Connect (if present):**
- Same installation process
- Monitors sync activities
- Detects sync-related attacks

**Scale Deployment with Group Policy:**

```
1. Create GPO: "Deploy MDI Sensor"
2. Link to: OU containing DCs
3. Configure:
   Computer Configuration
   └─ Policies
      └─ Windows Settings
         └─ Scripts (Startup/Shutdown)
            └─ Startup
               → Add script: Install-MDISensor.ps1
4. Script content:
```

```powershell
# Install-MDISensor.ps1
$installerPath = "\\server\share\Azure ATP sensor Setup.exe"
$accessKey = "YOUR-ACCESS-KEY-HERE"

# Check if already installed
if (!(Get-Service -Name AATPSensor -ErrorAction SilentlyContinue)) {
    # Copy installer locally
    Copy-Item $installerPath -Destination "C:\Temp\" -Force
    
    # Install
    Start-Process -FilePath "C:\Temp\Azure ATP sensor Setup.exe" `
      -ArgumentList "/quiet NetFrameworkCommandLineArguments=`"/q`" AccessKey=$accessKey" `
      -Wait
    
    # Log installation
    Write-EventLog -LogName Application -Source "MDI Deployment" `
      -EventId 1000 -Message "MDI Sensor installed successfully"
}
```

### 4.3 Deploy Sensor v3.x (Unified)

**Prerequisites:**
1. ✅ All DCs running Windows Server 2019 or later
2. ✅ Microsoft Defender for Endpoint deployed on all DCs
3. ✅ MDE sensors are healthy and communicating
4. ✅ No AD FS, AD CS, or Entra Connect (not supported in v3)

#### **Step 1: Verify MDE Deployment**

```
1. Microsoft Defender Portal → Assets → Devices
2. Filter: Device type = "Domain Controller"
3. Verify:
   - All DCs listed
   - Onboarding status: Onboarded
   - Health status: Active
   - Last seen: Recent (within minutes)
```

#### **Step 2: Activate Sensor v3.x**

**Automatic Activation (🆕 Recommended):**

```
1. Settings → Identities → Activation (Preview)
2. Toggle ON: "Automatic activation"
3. Defender for Identity will automatically activate sensor on:
   - New DCs as they're discovered
   - Existing DCs that meet requirements
4. Wait for activation:
   - First DC: Up to 1 hour
   - Subsequent DCs: Within 5 minutes
```

**Manual Activation:**

```
1. Settings → Identities → Activation (Preview)
2. View list of eligible servers:
   - Shows all DCs with MDE installed
   - Status: "Can be activated" or "Not eligible"
3. Select DC(s) to activate
4. Click "Activate"
5. Confirm activation
6. Wait for:
   - First sensor: Up to 1 hour to show "Running"
   - Additional sensors: Within 5 minutes
7. No restart required
```

#### **Step 3: Apply Enhanced RPC Audit Tag (🆕 Optional)**

```
1. Settings → Microsoft Defender XDR → Asset Rule Management
2. Click "+ Create rule"
3. Configure:
   - Name: "MDI Enhanced RPC Audit"
   - Description: "Enable RPC auditing for v3 sensors"
   - Conditions:
     * Device name: Contains "DC" OR
     * Device tag: Contains "DomainController" OR
     * Domain: Equals "contoso.com"
   - Verify rule matches your DCs
   - Add tag: "Unified Sensor RPC Audit"
4. Save
5. Rule applies automatically
6. Verify in Device Inventory:
   - DCs should now have tag visible
   - Enhanced detections enabled
```

#### **Step 4: Verify Activation**

```
1. Settings → Identities → Sensors
2. For each activated DC:
   - Sensor type: Shows "v3.x"
   - Status: Running
   - Health status: Healthy
   - Version: Latest v3.x version
3. If status is "Disconnected":
   - Check MDE sensor health
   - Verify network connectivity
   - Wait up to 1 hour for first activation
4. Check advanced hunting:
   - New tables: IdentityLogonEvents, IdentityQueryEvents
   - May be limited data compared to v2.x (Preview)
```

### 4.4 Post-Deployment Configuration

#### **Configure Directory Service Account (v2.x only)**

Already covered in sensor deployment steps above. For v3.x, this is handled automatically.

#### **Configure Delayed Update**

**Purpose:** Prevent all sensors from updating simultaneously (staged rollout).

```
1. Settings → Identities → Sensors
2. Select sensor (typically 1-2 sensors in large environment)
3. Click "..." → Manage delayed update
4. Toggle ON: Delay updates
5. This sensor will update 72 hours after others
6. Use for:
   - Canary testing
   - Phased rollouts
   - Critical DCs that need extra validation
```

#### **Configure Health Alerts**

```
1. Settings → Identities → Health issues (tab)
2. Review health alert categories:
   - Sensor issues
   - Configuration issues
   - Connectivity issues
   - Domain controller issues
3. For each type:
   - Enable email notifications
   - Set recipients: soc@company.com
   - Configure frequency: Immediate or Daily digest
```

#### **Configure Entity Tags**

**Sensitive Accounts:**
- Mark accounts that should be heavily monitored
- Examples: Domain Admins, Enterprise Admins, Service Accounts

```
1. Search for entity (user or computer)
2. Entity profile page
3. Click "..." → Manage tags
4. Add tag: "Sensitive"
5. MDI will prioritize alerts involving these entities
```

**Honeytoken Accounts (Deception):**
- Covered in detail in Section 8
- Create fake accounts to detect attackers

#### **Configure VPN Integration (Optional)**

**Purpose:** Correlate VPN logins with AD authentication.

```
1. Settings → Identities → VPN
2. Click "+ Add VPN"
3. Configure:
   - VPN name: "Cisco AnyConnect"
   - RADIUS accounting:
     * Server: 10.0.0.5
     * Secret: (shared secret)
4. Save
5. MDI will correlate:
   - VPN login location
   - AD authentication location
   - Detect impossible travel scenarios
```

#### **Configure Alert Exclusions**

**Known False Positives:**

```
1. Settings → Identities → Exclusions
2. Add exclusion:
   - Alert type: "Suspected Golden Ticket usage (ticket anomaly)"
   - Exclude: ServiceAccountBot (known to generate anomalous tickets)
   - Reason: "Automated process, not malicious"
   - Expiration: 365 days
3. Save
```

**Best Practice:** Document all exclusions and review quarterly.

### 4.5 Multi-Forest Deployment

**Supported Scenarios:**
- ✅ Single forest, single domain
- ✅ Single forest, multiple domains
- ✅ Multiple forests with trust relationships
- ⚠️ Multiple forests without trust (limited visibility)

**Multi-Forest Architecture:**

```
Forest A (contoso.com)          Forest B (fabrikam.com)
│                               │
├─ DC01 (MDI Sensor)           ├─ DC05 (MDI Sensor)
├─ DC02 (MDI Sensor)           └─ DC06 (MDI Sensor)
│                               │
└─ Two-way Trust ←─────────────┘

Both forests report to:
→ Single MDI Workspace

MDI can:
- Detect cross-forest attacks
- Map lateral movement between forests
- Correlate authentication across forests
```

**Configuration Steps:**

1. **Create Single Workspace:**
   - One workspace for entire organization
   - Configure primary domain

2. **Install Sensors in All Forests:**
   - Deploy sensors to all DCs in both forests
   - Use same workspace access key

3. **Configure Trust Relationships:**
   - Ensure trusts are configured correctly
   - Verify trust with: `nltest /trusted_domains`

4. **Validate Cross-Forest Visibility:**
   - Test authentication across forests
   - Verify MDI detects cross-forest activity

**Limitations:**
- Cannot detect attacks in untrusted forests
- Limited visibility if trust is one-way only

**🎯 Exam Tip:** Multi-forest deployments use a single MDI workspace but require sensors in all forests. Cross-forest attacks are detected if proper trust relationships exist.

---

## 5. Identity Security Posture Assessments

### 5.1 Overview

**What are Identity Security Posture Assessments (ISPMs)?**

ISPMs are **proactive security recommendations** generated by MDI to help you identify and fix security misconfigurations and vulnerabilities in your Active Directory environment.

**How They Work:**

```
MDI Continuously Monitors AD
│
├─ Analyzes configurations
├─ Identifies misconfigurations
├─ Compares against best practices
└─ Detects security weaknesses
│
Generates Recommendations
│
├─ Prioritized by risk
├─ Provides remediation steps
├─ Tracks progress
└─ Integrates with Secure Score
```

**🆕 2025 Updates:**
- New tab on Identity profile page showing all ISPMs
- Expanded recommendations for AD (not just Entra Connect)
- Integration with Microsoft Secure Score
- Improved UI and filtering

### 5.2 Accessing ISPMs

**Method 1: Identity Security Posture Page**

```
1. Microsoft Defender Portal → Identities
2. Click "Security posture" (left navigation)
3. View all recommendations:
   - Critical: Urgent action required
   - High: Important security issues
   - Medium: Recommended improvements
   - Low: Best practice enhancements
4. Filter by:
   - Severity
   - Status (Open/In progress/Resolved)
   - Category
```

**Method 2: Identity Profile Page (🆕 2025)**

```
1. Search for specific user or computer
2. Open entity profile
3. Click "Security posture" tab
4. View ISPMs specific to this entity:
   - User-specific issues
   - Computer-specific issues
   - Contextual recommendations
```

**Method 3: Microsoft Secure Score**

```
1. Microsoft Defender Portal → Secure Score
2. Filter: Defender for Identity
3. View improvement actions:
   - Score impact
   - Points to gain
   - Remediation steps
   - Implementation difficulty
```

### 5.3 Core ISPM Categories

MDI provides recommendations across several categories:

#### **Category 1: Lateral Movement Paths**

**Example Recommendations:**

1. **"Entities with clear-text password stored in Active Directory"**
   - **Risk:** Passwords stored in reversible encryption
   - **Impact:** Attackers can easily decrypt passwords
   - **Remediation:** Disable "Store password using reversible encryption"
   - **Affected:** User accounts with this setting enabled

2. **"Unsecure Kerberos delegation"**
   - **Risk:** Accounts configured with unconstrained or constrained delegation
   - **Impact:** Allows lateral movement attacks
   - **Remediation:** Use constrained delegation with protocol transition only
   - **Affected:** Service accounts with delegation configured

3. **"Unsecure SID History attributes"**
   - **Risk:** Accounts with SID History from privileged groups
   - **Impact:** Hidden privilege escalation
   - **Remediation:** Remove unnecessary SID History attributes
   - **Affected:** Migrated accounts with SID History

#### **Category 2: Account Security**

**🆕 2025 - Expanded Recommendations:**

1. **"Remove inactive accounts in sensitive groups"**
   - **Risk:** Dormant accounts in Domain Admins, Enterprise Admins, etc.
   - **Impact:** Attack surface for compromise
   - **Remediation:** Disable or remove inactive accounts (no login 90+ days)
   - **Affected:** Privileged accounts not used recently

2. **"Remove service accounts from privileged groups"**
   - **Risk:** Service accounts with unnecessary admin rights
   - **Impact:** Persistent access if compromised
   - **Remediation:** Use least privilege, dedicated service accounts
   - **Affected:** Service accounts in Domain Admins

3. **"Remove discovered passwords"**
   - **Risk:** Clear-text passwords found in descriptions or attributes
   - **Impact:** Easy credential theft
   - **Remediation:** Remove passwords from user descriptions
   - **Affected:** Users with passwords in AD attributes

4. **"Accounts with non-default Primary Group ID" (🆕 2025)**
   - **Risk:** Unusual Primary Group IDs indicate misconfigurations
   - **Impact:** Hidden group memberships, privilege escalation
   - **Remediation:** Reset to default (Domain Users: 513)
   - **Affected:** Accounts with modified Primary Group ID

#### **Category 3: Domain Controller Security**

**🆕 2025 - New Recommendations:**

1. **"Domain Controllers with unchanged Computer Account passwords"**
   - **Risk:** Computer passwords older than 45 days
   - **Impact:** Increased compromise risk
   - **Remediation:** Force password change or investigate why not auto-rotating
   - **Affected:** DCs with stale computer account passwords

2. **"Domain Controllers vulnerable to Zerologon (CVE-2020-1472)"**
   - **Risk:** Missing KB4565457 patch
   - **Impact:** Complete domain compromise via Netlogon elevation
   - **Remediation:** Apply security update immediately
   - **Affected:** Unpatched DCs

#### **Category 4: Group Policy Security**

**🆕 2025:**

1. **"GPO Assigns unprivileged Identities to Elevated Local Groups"**
   - **Risk:** GPOs granting local admin to non-privileged accounts
   - **Impact:** Lateral movement, privilege escalation
   - **Remediation:** Review and remove unnecessary assignments
   - **Affected:** GPOs assigning local admin rights incorrectly

2. **"Weak cipher suites in GPOs"**
   - **Risk:** GPOs allowing weak encryption (RC4, DES)
   - **Impact:** Kerberos ticket decryption
   - **Remediation:** Enforce AES-256 encryption only
   - **Affected:** GPOs with weak crypto configurations

#### **Category 5: Certificate Services (AD CS) - 🆕 2024-2025**

**ESC1 - ESC15 Vulnerabilities:**

Microsoft published 15 Active Directory Certificate Services escalation scenarios (ESC1-ESC15). MDI now detects many of these:

1. **"ESC1: Misconfigured Certificate Templates"**
   - **Risk:** Templates allowing SAN in CSR
   - **Impact:** Impersonation of any user
   - **Remediation:** Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag
   - **Affected:** Certificate templates with SAN enabled

2. **"ESC15: Certificate Enrollment with arbitrary Application Policies" (🆕 CVE-2024-49019)**
   - **Risk:** Vulnerable AD CS configurations
   - **Impact:** Certificate-based privilege escalation
   - **Remediation:** Apply KB5046740 or later, reconfigure templates
   - **Affected:** Unpatched AD CS servers with risky templates

3. **Other ESC Recommendations:**
   - ESC2, ESC3, ESC4, ESC6, ESC8 (various template misconfigurations)
   - Detected and reported with specific remediation steps

#### **Category 6: Microsoft Entra Connect**

1. **"Microsoft Entra Connect server has a read-only domain controller"**
   - **Risk:** Sync server using RODC for connection
   - **Impact:** Sync failures, security issues
   - **Remediation:** Configure to use writable DC
   - **Affected:** Entra Connect servers pointing to RODC

2. **"Microsoft Entra Connect account permissions are misconfigured"**
   - **Risk:** Sync account has excessive permissions
   - **Impact:** Potential privilege escalation
   - **Remediation:** Follow least privilege model for sync account
   - **Affected:** Entra Connect service account

### 5.4 Working with Recommendations

#### **View Recommendation Details**

```
1. Click on any recommendation
2. Details panel shows:
   ├─ Description: What the issue is
   ├─ Risk: Why it's dangerous
   ├─ Remediation: How to fix it
   ├─ Affected entities: List of impacted users/computers
   ├─ Status: Open / In Progress / Resolved / Dismissed
   └─ History: Changes over time
```

#### **Mark Status**

```
Track Remediation Progress:

1. Open → Acknowledged issue, planning fix
2. In Progress → Actively remediating
3. Resolved → Fixed and verified
4. Dismissed → Accepted risk (not recommended for Critical/High)
```

#### **Remediate Recommendations**

**Example: Remove Inactive Accounts**

```powershell
# Get list from MDI recommendation
# Export affected accounts

# Disable inactive accounts
$inactiveUsers = Import-Csv "C:\Temp\InactiveAccounts.csv"

foreach ($user in $inactiveUsers) {
    Disable-ADAccount -Identity $user.SamAccountName
    Set-ADUser -Identity $user.SamAccountName -Description "Disabled on 2025-10-22 - Inactive for 90+ days"
}

# Verify in MDI portal (updates within 24 hours)
```

**Example: Fix Unsecure Kerberos Delegation**

```powershell
# Find accounts with unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# For each account:
# Option 1: Remove delegation entirely (if not needed)
Set-ADUser -Identity "ServiceAccount1" -TrustedForDelegation $false

# Option 2: Convert to constrained delegation
# Use AD Users and Computers GUI:
# User Properties → Delegation tab → 
# Change from "Trust this user for delegation to any service"
# To: "Trust this user for delegation to specified services only"
```

**Example: Remove Clear-Text Passwords from AD**

```powershell
# Find users with passwords in description
Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -match "password|pw|pass"}

# Remove descriptions with passwords
Get-ADUser -Filter * -Properties Description | 
  Where-Object {$_.Description -match "password|pw|pass"} |
  ForEach-Object {
    Set-ADUser -Identity $_.SamAccountName -Description ""
    Write-Host "Cleared description for: $($_.SamAccountName)"
  }
```

### 5.5 Integration with Microsoft Secure Score

**How ISPMs Impact Secure Score:**

```
MDI Recommendations → Secure Score Improvement Actions

Each ISPM:
├─ Assigned point value
├─ Affects overall Secure Score
├─ Contributes to Identity score category
└─ Tracked for completion

Completing ISPMs:
├─ Increases Secure Score
├─ Improves security posture
└─ Demonstrates compliance
```

**View in Secure Score:**

```
1. Microsoft Defender Portal → Secure Score
2. Filter: "Defender for Identity"
3. See:
   - Current score from MDI
   - Max score possible
   - Improvement actions (ISPMs)
   - Each action shows:
     * Points: 1-10 points
     * Implementation cost: Minutes/Hours
     * User impact: Low/Medium/High
     * Remediation steps
```

**Example Score Impact:**

| Recommendation | Points | Effort | Priority |
|----------------|--------|--------|----------|
| Remove inactive admins | 8 pts | 15 min | High |
| Fix unsecure delegation | 6 pts | 1 hour | High |
| Remove clear-text passwords | 4 pts | 30 min | Medium |
| Enable MFA for admins | 10 pts | 2 hours | Critical |

**🎯 Exam Tip:** ISPMs are **proactive** (prevent attacks before they happen) while security alerts are **reactive** (detect attacks in progress). Both are critical for defense-in-depth.

### 5.6 Continuous Monitoring

**ISPM Update Frequency:**
- Scans run continuously
- New recommendations appear within 24 hours of detection
- Status updates reflect in portal within 24 hours of remediation

**Tracking Progress:**

```
1. Export current ISPMs as baseline
2. Create remediation plan:
   - Critical/High: 30 days
   - Medium: 60 days
   - Low: 90 days
3. Assign ownership (Identity team, AD admins, etc.)
4. Review progress weekly
5. Validate in MDI portal
6. Measure Secure Score improvement
```

---

## 6. Detection Capabilities and Alert Types

### 6.1 Detection Overview

Microsoft Defender for Identity provides **over 50 different alert types** across the cyber attack kill chain. These alerts detect:

- Reconnaissance activities
- Compromised credentials
- Lateral movement
- Domain dominance

**Detection Methods:**

```
MDI Uses Multiple Detection Techniques:
│
├─ 1. Signature-Based Detection
│   └─ Known attack patterns (e.g., Mimikatz signatures)
│
├─ 2. Behavioral Analytics (UEBA)
│   ├─ Machine learning baselines
│   ├─ Anomaly detection
│   └─ Statistical analysis
│
├─ 3. Threat Intelligence
│   ├─ Microsoft threat intelligence
│   ├─ Known IOCs
│   └─ Attack campaigns
│
└─ 4. Protocol Analysis
    ├─ Kerberos anomalies
    ├─ NTLM abuse
    └─ LDAP exploitation
```

### 6.2 Alert Classification by Kill Chain Phase

MDI maps alerts to the **MITRE ATT&CK framework** and traditional kill chain:

#### **Phase 1: Reconnaissance**

**Purpose:** Attackers gather information about the network.

| Alert | Description | MITRE | Exam Importance |
|-------|-------------|-------|-----------------|
| **Account enumeration reconnaissance** | Attacker enumerating valid usernames | T1087 | ⭐⭐⭐⭐ |
| **Network mapping reconnaissance (DNS)** | Suspicious DNS queries mapping network | T1018 | ⭐⭐⭐ |
| **User and IP address reconnaissance (SMB)** | SMB enumeration of users and IPs | T1087 | ⭐⭐⭐ |
| **User and group membership reconnaissance (SAMR)** | Enumerating domain users and groups | T1069 | ⭐⭐⭐⭐ |
| **Active Directory attributes reconnaissance (LDAP)** | LDAP queries for AD reconnaissance | T1069 | ⭐⭐⭐⭐ |

**Example Detection:**

```
Alert: Account enumeration reconnaissance

Detected Activity:
- User: CONTOSO\attacker
- Targeted: 500 different usernames via Kerberos
- Time: 2025-10-22 14:35:00
- Source: 192.168.1.100

Explanation:
Attacker attempted Kerberos pre-authentication on 500 usernames
to determine which accounts exist in the domain.

MITRE Technique: T1087.002 (Domain Account Discovery)

Recommended Actions:
1. Investigate source machine (192.168.1.100)
2. Check if user account is compromised
3. Review for other suspicious activity from this source
4. Consider blocking source IP if malicious
```

#### **Phase 2: Compromised Credentials**

**Purpose:** Attackers steal or crack credentials.

| Alert | Description | MITRE | Exam Importance |
|-------|-------------|-------|-----------------|
| **Suspected Brute Force attack (LDAP)** | Multiple failed LDAP binds | T1110 | ⭐⭐⭐⭐⭐ |
| **Suspected Brute Force attack (Kerberos)** | Multiple failed Kerberos pre-auths | T1110.001 | ⭐⭐⭐⭐⭐ |
| **Suspected AS-REP Roasting attack** | Requesting TGTs for accounts without pre-auth | T1558.004 | ⭐⭐⭐⭐⭐ |
| **Suspected Kerberoasting attack** | Requesting service tickets for offline cracking | T1558.003 | ⭐⭐⭐⭐⭐ |
| **Suspected password spray attack** | Same password tried across many accounts | T1110.003 | ⭐⭐⭐⭐⭐ |
| **Suspected WannaCry ransomware attack** | Specific attack pattern detected | T1486 | ⭐⭐⭐ |

**🔥 Critical Alert: AS-REP Roasting**

```
Alert: Suspected AS-REP Roasting attack

Detected Activity:
- User: CONTOSO\attacker
- Requested TGTs for 20 accounts without Kerberos pre-authentication
- Accounts targeted:
  * ServiceAccount1 (pre-auth not required)
  * ServiceAccount2 (pre-auth not required)
  * TestUser1 (pre-auth not required)
  ...
- Time: 2025-10-22 15:00:00
- Source: 192.168.1.100

Explanation:
Attacker requested TGTs for accounts with "Do not require Kerberos
preauth" enabled. These TGTs can be cracked offline to recover passwords.

MITRE Technique: T1558.004 (AS-REP Roasting)

Recommended Actions:
1. URGENT: Enable Kerberos pre-authentication for affected accounts
2. Force password reset for all affected accounts
3. Investigate source machine
4. Hunt for other compromised credentials
5. Check for follow-on attacks (lateral movement)

Remediation (PowerShell):
Set-ADUser -Identity ServiceAccount1 -KerberosEncryptionType AES256
Set-ADAccountControl -Identity ServiceAccount1 -DoesNotRequirePreAuth $false
```

**🔥 Critical Alert: Kerberoasting**

```
Alert: Suspected Kerberoasting attack

Detected Activity:
- User: CONTOSO\normaluser
- Requested 15 service tickets (TGS) within 5 minutes
- Services targeted:
  * MSSQL/SQL01.contoso.com
  * HTTP/SHAREPOINT.contoso.com
  * CIFS/FILESERVER.contoso.com
  ...
- Encryption: RC4 (weak, crackable offline)
- Time: 2025-10-22 16:00:00

Explanation:
User requested many service tickets with RC4 encryption.
These tickets contain the service account password hash
and can be cracked offline.

MITRE Technique: T1558.003 (Kerberoasting)

Recommended Actions:
1. Force password change for all service accounts
2. Use long, complex passwords (25+ characters)
3. Migrate from RC4 to AES256 encryption
4. Investigate user account for compromise
5. Review service account usage and remove if not needed

Prevention:
- Use gMSA (Group Managed Service Accounts)
- Enforce AES256: Set-ADUser -KerberosEncryptionType AES256
- Strong passwords: 25+ characters
```

#### **Phase 3: Lateral Movement**

**Purpose:** Attackers move across the network to reach valuable targets.

| Alert | Description | MITRE | Exam Importance |
|-------|-------------|-------|-----------------|
| **Suspected identity theft (pass-the-hash)** | Using stolen NTLM hash | T1550.002 | ⭐⭐⭐⭐⭐ |
| **Suspected identity theft (pass-the-ticket)** | Using stolen Kerberos ticket | T1550.003 | ⭐⭐⭐⭐⭐ |
| **Suspected Over-Pass-the-Hash attack** | Using NTLM to request Kerberos ticket | T1550.002 | ⭐⭐⭐⭐ |
| **Suspected use of Metasploit hacking framework** | Metasploit tool signatures detected | T1003 | ⭐⭐⭐⭐ |
| **Suspected DCSync attack (replication of directory services)** | Attacker replicating AD | T1003.006 | ⭐⭐⭐⭐⭐ |
| **Suspected skeleton key attack** | Backdoor allowing any password | T1547.008 | ⭐⭐⭐ |
| **Remote code execution attempt** | Attempts to execute code remotely | T1021 | ⭐⭐⭐⭐ |

**🔥 Critical Alert: Pass-the-Hash**

```
Alert: Suspected identity theft (pass-the-hash)

Detected Activity:
- Source user: CONTOSO\victim-laptop$
- Stolen identity: CONTOSO\domain-admin
- Method: NTLM authentication using stolen hash
- Target: DC01.contoso.com
- Time: 2025-10-22 17:00:00

Explanation:
Computer account authenticated as domain admin using
NTLM (not Kerberos). This indicates pass-the-hash attack
using stolen credential material.

MITRE Technique: T1550.002 (Pass the Hash)

Attack Flow:
1. Attacker compromised victim-laptop
2. Extracted domain-admin NTLM hash from memory (Mimikatz)
3. Used hash to authenticate to DC without knowing password
4. Gained domain admin access

Recommended Actions:
1. URGENT: Reset password for domain-admin account
2. Isolate victim-laptop immediately
3. Investigate what attacker accessed
4. Enable credential guard on all sensitive systems
5. Hunt for other compromised credentials
6. Review admin account usage (should not login to workstations)

Prevention:
- Protected Users group (blocks NTLM, cached creds)
- Credential Guard (Windows 10/11, Server 2016+)
- LAPS for local admin passwords
- Privileged Access Workstations (PAW)
```

**🔥 Critical Alert: DCSync**

```
Alert: Suspected DCSync attack (replication of directory services)

Detected Activity:
- User: CONTOSO\attacker (non-DC account)
- Requested replication from: DC01.contoso.com
- Objects replicated:
  * krbtgt (CRITICAL!)
  * Administrator
  * Domain Admins members
  * All user password hashes
- Time: 2025-10-22 18:00:00
- Source: 192.168.1.200

Explanation:
Non-domain controller account used Directory Replication
permissions to extract all password hashes, including krbtgt.
With krbtgt hash, attacker can create Golden Tickets for
unlimited domain access.

MITRE Technique: T1003.006 (DCSync)

Attack Requirements:
- Replicating Directory Changes permission
- Replicating Directory Changes All permission
- Typically only DCs have these rights

Recommended Actions:
1. CRITICAL: Reset krbtgt password TWICE (wait 24 hours between)
2. Disable attacker account immediately
3. Reset passwords for ALL replicated accounts
4. Investigate how attacker gained replication permissions
5. Review all accounts with DS-Replication permissions
6. Hunt for Golden Ticket usage
7. Enable 4662 auditing if not already enabled

Audit Requirement:
Event 4662 (object access) must be enabled to detect DCSync!

Prevention:
- Limit DS-Replication permissions to DCs only
- Monitor permission changes on domain object
- Use honeytokens to detect unauthorized replication
```

#### **Phase 4: Domain Dominance**

**Purpose:** Attackers achieve complete domain control.

| Alert | Description | MITRE | Exam Importance |
|-------|-------------|-------|-----------------|
| **Suspected Golden Ticket usage (encryption downgrade)** | RC4 ticket for AES-configured account | T1558.001 | ⭐⭐⭐⭐⭐ |
| **Suspected Golden Ticket usage (forged authorization data)** | Modified PAC data in ticket | T1558.001 | ⭐⭐⭐⭐⭐ |
| **Suspected Golden Ticket usage (nonexistent account)** | Ticket for deleted account | T1558.001 | ⭐⭐⭐⭐⭐ |
| **Suspected Golden Ticket usage (ticket anomaly)** | Anomalous ticket properties | T1558.001 | ⭐⭐⭐⭐⭐ |
| **Suspected Golden Ticket usage (time anomaly)** | Ticket lifetime violation | T1558.001 | ⭐⭐⭐⭐⭐ |
| **Suspected DCShadow attack (domain controller replication request)** | Fake DC replication | T1207 | ⭐⭐⭐⭐ |
| **Suspected DCShadow attack (domain controller promotion)** | Fake DC registration | T1207 | ⭐⭐⭐⭐ |

**🔥 Critical Alert: Golden Ticket**

```
Alert: Suspected Golden Ticket usage (encryption downgrade)

Detected Activity:
- User in ticket: CONTOSO\Administrator
- Encryption: RC4 (downgrade from AES256)
- Issuer: (forged, not actual DC)
- Lifetime: 10 years (vs standard 10 hours)
- Source: 192.168.1.250
- Time: 2025-10-22 19:00:00

Explanation:
A Kerberos TGT was presented with anomalous properties:
1. Account configured for AES256, but ticket uses RC4
2. Ticket lifetime is 10 years (policy is 10 hours)
3. Ticket was not issued by a legitimate DC

This indicates a Golden Ticket attack using stolen krbtgt hash.

MITRE Technique: T1558.001 (Golden Ticket)

How Golden Ticket Works:
1. Attacker obtained krbtgt password hash (via DCSync)
2. Used Mimikatz to forge TGT offline
3. Ticket grants unlimited access to entire domain
4. Can impersonate any user, including deleted accounts
5. No need to authenticate to DC

Recommended Actions:
1. CRITICAL: Reset krbtgt password TWICE
   - First reset: Invalidates tickets created with old hash
   - Wait 24 hours (allow replication)
   - Second reset: Invalidates any tickets from interim period
2. Identify all systems accessed with forged ticket
3. Assume full domain compromise
4. Complete incident response:
   - Reset ALL admin passwords
   - Review ALL admin actions in timeframe
   - Check for backdoors, persistence mechanisms
   - Rebuild from known-good backups if needed
5. Hunt for other indicators of compromise

Prevention:
- Secure krbtgt hash (it's the keys to the kingdom)
- Detect DCSync attacks before Golden Ticket creation
- Monitor for ticket anomalies
- Regular krbtgt password rotation (annual)

PowerShell Reset krbtgt:
# Use Microsoft script for safe krbtgt reset
# https://github.com/microsoft/New-KrbtgtKeys.ps1
.\New-KrbtgtKeys.ps1 -WhatIf  # Test first
.\New-KrbtgtKeys.ps1 -SkipRODC  # First reset
# Wait 24 hours
.\New-KrbtgtKeys.ps1 -SkipRODC  # Second reset
```

**🔥 Critical Alert: DCShadow**

```
Alert: Suspected DCShadow attack (domain controller promotion)

Detected Activity:
- Fake DC registered: ROGUE-DC
- Service: CN=ROGUE-DC,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=contoso,DC=com
- Source: 192.168.1.100 (not a real DC)
- Time: 2025-10-22 20:00:00

Explanation:
A non-domain controller machine registered itself as a DC
in Active Directory configuration. This allows attacker to:
1. Inject malicious AD changes
2. Modify objects without detection
3. Elevate privileges
4. Create backdoor accounts

MITRE Technique: T1207 (DCShadow)

Attack Requirements:
- Attacker needs:
  * Domain admin OR
  * Specific permissions on Configuration partition
- Uses legitimate AD replication to inject changes

Recommended Actions:
1. Immediately identify and remove fake DC registration
2. Review ALL AD changes in timeframe (replication metadata)
3. Look for suspicious object modifications:
   - New admin accounts
   - SID History modifications
   - ACL changes
   - Hidden accounts
4. Investigate source machine (192.168.1.100)
5. Reset passwords for admin accounts
6. Enable 4662 auditing for Configuration partition

Detection Requirement:
Event 4662 auditing on CN=Configuration required!

Cleanup:
# Remove fake DC registration
# Identify in Sites and Services
# Manual removal required
```

### 6.3 Alert Severity Levels

**MDI assigns severity based on risk:**

| Severity | Color | Meaning | Response SLA | Examples |
|----------|-------|---------|--------------|----------|
| **Critical** | Red | Immediate domain compromise | < 15 min | DCSync, Golden Ticket |
| **High** | Orange | Active attack in progress | < 1 hour | Pass-the-hash, Kerberoasting |
| **Medium** | Yellow | Suspicious but not confirmed attack | < 4 hours | Unusual behavior, anomalies |
| **Low** | Gray | Informational, low risk | < 24 hours | Reconnaissance attempts |
| **Informational** | Blue | FYI, not necessarily malicious | Review weekly | Config changes |

### 6.4 Alert Components

**Every MDI Alert Contains:**

```
Alert Structure:
│
├─ Alert Title
│  └─ Clear description of detected activity
│
├─ Severity
│  └─ Critical / High / Medium / Low / Informational
│
├─ Status
│  └─ New / In Progress / Resolved / Closed
│
├─ Description
│  └─ What happened, why it's suspicious
│
├─ Impacted Entities
│  ├─ Source user/computer
│  ├─ Target user/computer
│  └─ Additional context
│
├─ Timeline
│  └─ When attack occurred, duration
│
├─ Evidence
│  ├─ Network traffic details
│  ├─ Event log entries
│  ├─ Authentication details
│  └─ Technical indicators
│
├─ MITRE ATT&CK Mapping
│  └─ Technique ID and name
│
├─ Recommended Actions
│  └─ Step-by-step remediation
│
└─ Related Activity
   └─ Links to related alerts, entities
```

### 6.5 Alert Tuning

**🆕 2025 - Improved Alert Tuning:**

Microsoft improved MDI detection accuracy in Sept-Oct 2025. However, some tuning may still be needed.

#### **Test Mode (🆕 Updated Oct 2025)**

**Purpose:** Reduce false positives during initial deployment.

```
Configuration:
1. Settings → Identities → Detection tuning
2. Enable "Recommended test mode"
3. Set expiration: Up to 60 days (mandatory as of Oct 2025)
4. Alerts will show "Test mode" banner
5. Automatically expires after set duration

What Test Mode Does:
- Raises alert thresholds
- Reduces noise from normal behavior
- Allows learning period
- Still logs all activity

When to Use:
- New MDI deployment (first 30-60 days)
- Major environment changes
- Post-migration tuning
- After AD restructure
```

#### **Exclusions**

**When to Exclude:**
- Known false positives
- Authorized security tools (e.g., vulnerability scanners)
- Service accounts with legitimate unusual behavior

```
1. Settings → Identities → Exclusions
2. Click "+ Add exclusion"
3. Configure:
   - Alert type: "Account enumeration reconnaissance"
   - Exclude entity: CONTOSO\VulnScanner
   - Reason: "Authorized Nessus scanner"
   - Expiration: 365 days
4. Save
```

**⚠️ Warning:** Use exclusions sparingly. Document all exclusions.

#### **Custom Alert Thresholds**

Some alerts support custom thresholds:

```
Example: Brute Force Alerts

Default: 10 failed attempts in 2 minutes triggers alert
Custom: Adjust to 20 attempts in 5 minutes

Configuration:
Settings → Identities → Detection tuning → Adjust thresholds
```

### 6.6 Alert Lifecycle

**From Detection to Resolution:**

```
1. Alert Generated
   ├─ MDI detects suspicious activity
   ├─ Alert appears in Incidents queue
   └─ Status: New

2. Triage
   ├─ SOC analyst reviews alert
   ├─ Determines if true positive or false positive
   └─ Status: In Progress

3. Investigation
   ├─ Analyze impacted entities
   ├─ Review timeline and evidence
   ├─ Hunt for related activity
   └─ Determine scope

4. Containment
   ├─ Disable compromised accounts
   ├─ Reset passwords
   ├─ Isolate affected systems
   └─ Block attacker access

5. Remediation
   ├─ Remove persistence mechanisms
   ├─ Fix vulnerabilities
   ├─ Restore from backups if needed
   └─ Strengthen security controls

6. Recovery
   ├─ Re-enable accounts (with new passwords)
   ├─ Restore normal operations
   └─ Monitor for recurrence

7. Closure
   ├─ Document lessons learned
   ├─ Update playbooks
   └─ Status: Resolved/Closed
```

**🎯 Exam Tip:** Know the major alert types (Golden Ticket, DCSync, Pass-the-Hash, Kerberoasting, AS-REP Roasting) and their MITRE ATT&CK mappings. These are heavily tested on SC-200.

---

## 7. Lateral Movement Path Analysis

### 7.1 Overview

**What are Lateral Movement Paths (LMPs)?**

Lateral Movement Paths show **potential routes** an attacker could take to compromise sensitive accounts (like Domain Admins) after gaining initial access to a less-privileged account or computer.

**Why LMPs Matter:**

```
Attacker Compromises Low-Value Target
│
├─ Standard User Account
├─ OR: Workstation
├─ OR: Member Server
│
Attacker Looks for Path to High-Value Target
│
├─ Domain Admin Account
├─ Enterprise Admin
├─ Tier 0 Administrators
│
MDI Maps All Possible Paths
│
└─ Shows organization WHERE weaknesses exist
   └─ Allows PROACTIVE remediation
```

**🎯 Key Concept:** LMPs are about **PREVENTION**, not detection. They show vulnerabilities BEFORE an attack.

### 7.2 How LMP Analysis Works

**Data Sources:**

MDI continuously analyzes:

1. **Active Sessions**
   - Who is logged in where
   - RDP sessions
   - Interactive logons
   - Saved credentials

2. **Local Admin Rights**
   - Which users are local admins on which machines
   - Group membership
   - Nested groups

3. **Credential Exposure**
   - Where credentials are cached
   - Saved RDP credentials
   - Service accounts running on machines

4. **Network Topology**
   - Trusts between domains
   - Network connectivity
   - Firewall rules (not directly, but inferred from traffic)

**Graph Analysis:**

```
MDI Builds Attack Graph:
│
├─ Nodes (Entities)
│  ├─ Users
│  ├─ Computers
│  └─ Groups
│
└─ Edges (Relationships)
   ├─ "Has session on"
   ├─ "Is admin on"
   ├─ "Credentials cached on"
   └─ "Member of"

Then MDI Searches:
- All paths from compromised entity
- To sensitive accounts
- Via logical connections
```

**🆕 2025 Update - SAM-R Deprecation:**

**⚠️ IMPORTANT CHANGE (May 2025):**

Microsoft is disabling remote SAM-R queries for local administrator group enumeration by mid-May 2025.

**Impact:**
- MDI previously used SAM-R to discover local admin group members remotely
- This data was used to build LMPs
- **After May 2025:** LMPs will no longer update with this data
- Alternative method being explored by Microsoft

**What This Means:**
- Existing LMP data before May 2025: Retained but not updated
- New LMP discovery: Will use alternative methods (TBD)
- Recommendation: Use Microsoft Defender for Endpoint + MDI integration for endpoint data

### 7.3 Viewing Lateral Movement Paths

**Access LMPs:**

```
Method 1: Sensitive Users Page
1. Microsoft Defender Portal → Identities
2. Click "Lateral movement paths"
3. See all sensitive accounts with:
   - Number of paths TO this account
   - Risk level
   - Exposure timeframe

Method 2: Entity Profile
1. Search for sensitive user (e.g., domain admin)
2. Open user profile
3. Click "Lateral movement paths" tab
4. See visual graph of attack paths
```

**LMP Interface:**

```
Lateral Movement Path Visualization:

[Attacker Entry Point] → [Hop 1] → [Hop 2] → [Target]

Example:
[Workstation WKS-001] → [Server SRV-001] → [Domain Admin]

Explanation:
1. Attacker compromises WKS-001
2. Domain Admin has active session on WKS-001
3. Attacker extracts credentials from memory
4. Attacker uses credentials to access SRV-001
5. Full domain admin access achieved
```

### 7.4 Understanding LMP Components

#### **Entry Points (Low-Value Targets)**

These are where attackers typically start:

- Standard user workstations
- Member servers
- Non-sensitive user accounts
- Service accounts with network access

#### **Hops (Intermediate Steps)**

Connections between entry points and targets:

**Type 1: Active Sessions**
```
Sensitive User has Active Session on Machine
├─ RDP session
├─ Interactive logon
├─ Saved credentials
└─ Credentials in memory (LSASS)

Risk: Attacker on machine can extract credentials
```

**Type 2: Local Admin Rights**
```
User is Local Admin on Machine
├─ Can access machine remotely
├─ Can install tools
├─ Can extract credentials
└─ Can pivot to other systems

Risk: Lateral movement capability
```

**Type 3: Saved Credentials**
```
Credentials Saved on Machine
├─ RDP credential manager
├─ Windows Credential Manager
├─ LSA secrets
└─ Service account passwords

Risk: Credentials can be extracted and reused
```

#### **Targets (High-Value Accounts)**

MDI considers these as **sensitive by default:**

- Domain Admins
- Enterprise Admins
- Schema Admins
- Backup Operators (can backup domain database)
- Account Operators
- Server Operators
- Print Operators
- Administrators (built-in local admin group)

**Custom Sensitive Accounts:**
You can manually tag additional accounts as sensitive:

```
1. Find user/group
2. Entity profile
3. Click "..." → Manage tags
4. Add tag: "Sensitive"
5. Now included in LMP analysis
```

### 7.5 Example Lateral Movement Scenarios

#### **Scenario 1: Admin Logged into Workstation**

```
LMP Alert: "Sensitive account exposed on non-secure machine"

Attack Path:
┌──────────────────┐
│ WKS-001          │ ← Domain Admin logged in here
│ (Workstation)    │
└──────────────────┘
        ↓
 Attacker compromises WKS-001
        ↓
 Extracts Domain Admin credentials from memory (Mimikatz)
        ↓
 Uses credentials to access Domain Controllers
        ↓
 Full Domain Compromise

Remediation:
1. Prevent admin accounts from logging into workstations
2. Use jump servers/PAWs for admin tasks
3. Implement Protected Users security group
4. Enable Credential Guard
```

#### **Scenario 2: Service Account with Admin Rights**

```
LMP Alert: "Service account with excessive privileges"

Attack Path:
┌──────────────────┐
│ SRV-001          │ ← SQL Service account runs here
│ (SQL Server)     │    (has Domain Admin rights)
└──────────────────┘
        ↓
 Attacker compromises SRV-001
        ↓
 Extracts SQL service account credentials
        ↓
 Service account is Domain Admin
        ↓
 Instant domain compromise

Remediation:
1. Remove Domain Admin rights from service account
2. Use least privilege (only SQL-specific permissions)
3. Use gMSA for service accounts
4. Isolate SQL server (separate VLAN, firewall rules)
```

#### **Scenario 3: Cached Credentials Chain**

```
LMP Alert: "Complex lateral movement path detected"

Attack Path:
┌──────────────────┐
│ WKS-001          │ ← StandardUser works here
│ (Workstation)    │
└──────────────────┘
        ↓ (StandardUser has local admin on SRV-001)
┌──────────────────┐
│ SRV-001          │ ← ITAdmin has session here
│ (File Server)    │
└──────────────────┘
        ↓ (ITAdmin has local admin on DC-001)
┌──────────────────┐
│ DC-001           │ ← Full access
│ (Domain Ctrl)    │
└──────────────────┘

Steps:
1. Attacker phishes StandardUser
2. Uses StandardUser's local admin on SRV-001 to access it
3. Extracts ITAdmin credentials from SRV-001 memory
4. Uses ITAdmin to access DC-001
5. Complete domain compromise

Remediation:
1. Implement tiered admin model:
   - Tier 0: Domain admins → Only login to DCs
   - Tier 1: Server admins → Only login to servers
   - Tier 2: Workstation admins → Only login to workstations
2. Use LAPS for local admin passwords (unique per machine)
3. Limit who has local admin on servers
4. Monitor for unusual authentication patterns
```

### 7.6 Remediating Lateral Movement Paths

**General Strategies:**

1. **Reduce Admin Accounts**
   - Minimize who has admin rights
   - Use Just-In-Time (JIT) admin access
   - Implement Privileged Access Management (PAM)

2. **Implement Credential Hygiene**
   - No admin accounts logging into workstations
   - Use jump servers for admin tasks
   - Clear credentials after logoff

3. **Use Privileged Access Workstations (PAWs)**
   - Dedicated workstations for admin tasks
   - Locked down, cannot browse internet
   - Cannot access email

4. **Deploy LAPS**
   - Local Administrator Password Solution
   - Unique local admin password per machine
   - Breaks lateral movement chains

5. **Enable Credential Guard**
   - Windows 10/11, Server 2016+
   - Protects credentials in memory
   - Prevents pass-the-hash

**Example Remediation Plan:**

```
LMP Found: 50 paths to Domain Admins

Priority 1 (High Risk - 10 paths):
- Remove admin logon sessions from workstations
- Action: GPO to deny interactive logon for admins to workstations
- Timeline: Immediate (this week)

Priority 2 (Medium Risk - 25 paths):
- Service accounts with excessive permissions
- Action: Review and reduce service account permissions
- Timeline: 30 days

Priority 3 (Low Risk - 15 paths):
- Nested group memberships
- Action: Flatten AD group structure
- Timeline: 90 days
```

### 7.7 Monitoring LMP Changes

**Track Over Time:**

```
1. Export current LMP state (baseline)
2. Implement remediations
3. Wait 24-48 hours for MDI to update
4. Compare:
   - Previous: 50 paths
   - Current: 20 paths
   - Improvement: 60% reduction
5. Continue until acceptable level
```

**Acceptable Risk Level:**

- **Zero paths:** Ideal but often not realistic
- **< 10 paths:** Good security posture
- **10-50 paths:** Needs improvement
- **> 50 paths:** High risk, urgent remediation needed

**🎯 Exam Tip:** LMPs show POTENTIAL attack paths, not actual attacks. They are part of **security posture** (proactive) not **threat detection** (reactive). Understand how to remediate LMPs by implementing admin tier model and credential hygiene.

---

*[Due to length limits, I'll continue with remaining sections in next response. Let me know if you want me to continue!]*

**Note:** We've completed 7 out of 15 sections so far. The document is comprehensive and detailed. Would you like me to:
1. Continue with remaining sections (8-15)?
2. Create this as Part 1 and make Part 2 separately?
3. Or adjust the depth/length?

Let me know how you'd like to proceed!
