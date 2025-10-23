# SC-200 Study Notes - Module 3: Microsoft Defender for Office 365 (MDO)
## 📧 Complete Email & Collaboration Security Guide - Updated for SC-200 Exam (April 21, 2025)

**Exam Weight:** This content supports ~20-25% of the SC-200 exam
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest MDO Updates (Sept-Oct 2025)

---

## 🎯 SC-200 Exam Objectives Covered in This Module

### **From "Manage incident response" (25-30%)**
- ✅ Investigate and remediate threats to email by using Defender for Office 365
- ✅ Investigate and remediate compromised entities identified by Microsoft Purview DLP
- ✅ Manage actions and submissions in the Microsoft Defender portal

### **From "Configure protections and detections" (15-20%)**
- ✅ Configure Safe Links and Safe Attachments policies
- ✅ Configure anti-phishing policies
- ✅ Configure anti-spam and anti-malware policies
- ✅ Configure security policies for Microsoft Defender for Office 365

### **From "Manage security threats" (15-20%)**
- ✅ Hunt for threats by using Microsoft Defender XDR (email threats)
- ✅ Analyze threat intelligence and threat analytics (email campaigns)
- ✅ Use Threat Explorer for email threat hunting

### **Cross-Module Integration:**
- ✅ Microsoft 365 Defender unified incidents (email + endpoint + identity)
- ✅ Automatic attack disruption (email-based initial access)
- ✅ Advanced hunting (EmailEvents, UrlClickEvents, etc.)

---

## 📚 Table of Contents

1. [MDO Overview and Architecture](#1-mdo-overview-and-architecture)
2. [Licensing and Plans (Plan 1 vs Plan 2)](#2-licensing-and-plans-plan-1-vs-plan-2)
3. [Safe Attachments](#3-safe-attachments)
4. [Safe Links](#4-safe-links)
5. [Anti-Phishing Policies](#5-anti-phishing-policies)
6. [Anti-Spam and Anti-Malware](#6-anti-spam-and-anti-malware)
7. [Quarantine and User Submissions](#7-quarantine-and-user-submissions)
8. [Threat Explorer and Real-Time Detections](#8-threat-explorer-and-real-time-detections)
9. [Priority Account Protection](#9-priority-account-protection)
10. [Email Authentication (SPF, DKIM, DMARC)](#10-email-authentication-spf-dkim-dmarc)
11. [Investigation and Response](#11-investigation-and-response)
12. [Advanced Hunting for Email Threats](#12-advanced-hunting-for-email-threats)
13. [Attack Simulation Training](#13-attack-simulation-training)
14. [Configuration Best Practices](#14-configuration-best-practices)
15. [Exam Tips and Practice Questions](#15-exam-tips-and-practice-questions)

---

## 1. MDO Overview and Architecture

### 1.1 What is Microsoft Defender for Office 365?

**Microsoft Defender for Office 365 (MDO)**, formerly Office 365 Advanced Threat Protection (ATP), is a **cloud-based email security service** that protects organizations from:

- **Email-based threats** (phishing, malware, ransomware)
- **Malicious links** (Safe Links)
- **Malicious attachments** (Safe Attachments)
- **Business email compromise (BEC)**
- **Account compromise**

### 1.2 Core Capabilities

```
Microsoft Defender for Office 365
│
├─ 1️⃣ Email Protection
│   ├─ Anti-phishing (credential theft, impersonation)
│   ├─ Anti-spam (bulk email, junk)
│   ├─ Anti-malware (viruses, trojans)
│   └─ Zero-hour auto purge (ZAP) - retroactive cleanup
│
├─ 2️⃣ Safe Attachments
│   ├─ Sandbox detonation of suspicious files
│   ├─ Zero-day malware protection
│   ├─ SharePoint/OneDrive/Teams file protection
│   └─ Dynamic delivery (emails not delayed)
│
├─ 3️⃣ Safe Links
│   ├─ Time-of-click URL verification
│   ├─ URL rewriting and tracking
│   ├─ Protection in email, Teams, Office apps
│   └─ Block malicious sites
│
├─ 4️⃣ Threat Intelligence & Investigation
│   ├─ Threat Explorer (Plan 2) / Real-time detections (Plan 1)
│   ├─ Email entity page
│   ├─ Threat campaigns
│   └─ Automated investigation & response (AIR)
│
└─ 5️⃣ Reporting & Simulation
    ├─ Email security reports
    ├─ Attack simulation training
    ├─ Threat analytics
    └─ Secure Score recommendations
```

### 1.3 Protection Layers

**Defense in Depth:**

```
Incoming Email → Microsoft 365
│
├─ Layer 1: Connection Filtering
│   ├─ IP reputation check
│   ├─ Allow/Block lists
│   └─ Safe senders/domains
│
├─ Layer 2: Email Authentication
│   ├─ SPF (Sender Policy Framework)
│   ├─ DKIM (DomainKeys Identified Mail)
│   └─ DMARC (Domain-based Message Authentication)
│
├─ Layer 3: Anti-Spam
│   ├─ Spam confidence level (SCL)
│   ├─ Bulk complaint level (BCL)
│   └─ Content filtering
│
├─ Layer 4: Anti-Malware
│   ├─ Common Attachment Filter
│   ├─ Malware detection engine
│   └─ File type blocking
│
├─ Layer 5: Safe Attachments (MDO)
│   ├─ Detonation in sandbox
│   ├─ Zero-day malware detection
│   └─ Dynamic delivery
│
├─ Layer 6: Safe Links (MDO)
│   ├─ URL rewriting
│   ├─ Time-of-click verification
│   └─ Block malicious URLs
│
└─ Layer 7: Anti-Phishing (MDO)
    ├─ Impersonation protection
    ├─ Mailbox intelligence
    ├─ Spoof intelligence
    └─ Advanced phishing thresholds

If Malicious → Quarantine or Delete
If Suspicious → User's Junk folder
If Clean → Inbox
```

### 1.4 Architecture Components

**Cloud Service Architecture:**

```
User's Email Client
│
├─ Outlook Desktop/Web/Mobile
├─ Third-party clients (Gmail app, Thunderbird)
└─ Mobile email apps
│
↓ SMTP/HTTPS
│
Microsoft 365 Exchange Online
│
├─ Exchange Online Protection (EOP)
│   ├─ Built-in anti-spam/malware
│   ├─ Connection filtering
│   ├─ Policy filtering
│   └─ Content filtering
│
└─ Microsoft Defender for Office 365
    ├─ Safe Attachments engine
    │   └─ Sandbox detonation (isolated VMs)
    ├─ Safe Links engine
    │   └─ URL reputation service
    ├─ Anti-phishing engine
    │   └─ ML models for impersonation
    ├─ Automated Investigation & Response (AIR)
    │   └─ Automated remediation
    └─ Threat Intelligence
        └─ Global threat data + Microsoft Security Graph

↓
│
Defender XDR Portal (security.microsoft.com)
├─ Alerts & Incidents
├─ Threat Explorer
├─ Reports
└─ Investigations
```

### 1.5 Data Flow

**Email Processing Pipeline:**

```
1. Email arrives at Microsoft 365
   ├─ From: attacker@evil.com
   ├─ To: user@contoso.com
   └─ Attachment: invoice.docx (malicious)

2. Exchange Online Protection (EOP) scans
   ├─ IP reputation: Check sender IP
   ├─ SPF/DKIM/DMARC: Validate email authentication
   ├─ Anti-spam: Check for spam indicators
   ├─ Anti-malware: Scan attachment with AV engine
   └─ Result: Passes EOP (malware not detected by signature)

3. Safe Attachments (MDO Plan 1/2)
   ├─ Attachment sent to sandbox
   ├─ invoice.docx opened in isolated VM
   ├─ Behavior analysis: Drops ransomware payload!
   └─ Result: MALICIOUS detected

4. Action Taken
   ├─ Email moved to quarantine
   ├─ Attachment replaced with warning message
   ├─ Alert generated in M365 Defender
   └─ AIR (Plan 2): Automatically checks other emails

5. Notification
   ├─ Admin gets alert
   ├─ User gets notification (optional)
   └─ Incident created in Defender portal
```

### 1.6 Key Differentiators

**MDO vs Traditional Email Security:**

| Feature | Traditional Gateway | Exchange Online Protection (EOP) | MDO Plan 1 | MDO Plan 2 |
|---------|---------------------|----------------------------------|------------|------------|
| **Anti-spam** | ✅ Yes | ✅ Yes (built-in) | ✅ Yes | ✅ Yes |
| **Anti-malware** | ✅ Yes | ✅ Yes (built-in) | ✅ Yes | ✅ Yes |
| **Basic anti-phishing** | ✅ Yes | ✅ Yes (built-in) | ✅ Yes | ✅ Yes |
| **Advanced anti-phishing** | ⚠️ Limited | ⚠️ Basic | ✅ Yes | ✅ Yes |
| **Safe Attachments** | ❌ No | ❌ No | ✅ Yes | ✅ Yes |
| **Safe Links** | ❌ No | ❌ No | ✅ Yes | ✅ Yes |
| **Threat Explorer** | ❌ No | ❌ No | ⚠️ Real-time detections | ✅ Full Explorer |
| **Automated Investigation** | ❌ No | ❌ No | ❌ No | ✅ Yes (AIR) |
| **Attack Simulation** | ❌ No | ❌ No | ❌ No | ✅ Yes |
| **Threat Hunting** | ⚠️ Limited | ⚠️ Basic reports | ⚠️ Limited | ✅ Advanced |

**🎯 Exam Tip:** EOP is included FREE with all Exchange Online subscriptions. MDO Plan 1/2 are add-ons providing advanced protection. Know the differences between Plan 1 and Plan 2!

---

## 2. Licensing and Plans (Plan 1 vs Plan 2)

### 2.1 Licensing Overview

**Microsoft Defender for Office 365 is available in two plans:**

| Plan | What's Included | Best For |
|------|----------------|----------|
| **Plan 1** | Prevention & protection features | Organizations needing real-time protection |
| **Plan 2** | Plan 1 + investigation, hunting, response | SOC teams, advanced threat hunting |

### 2.2 Plan 1 Features

**Microsoft Defender for Office 365 Plan 1:**

✅ **Core Protection:**
- Safe Attachments (email, SharePoint, OneDrive, Teams)
- Safe Links (email, Office apps, Teams)
- Anti-phishing protection (advanced)
- Real-time detections (basic threat visibility)
- Reports and message trace

✅ **Included In:**
- Microsoft 365 Business Premium
- Microsoft 365 E3 + MDO Plan 1 add-on
- Office 365 E5
- Microsoft 365 E5

**Cost (Approximate):**
- ~$2-3 USD per user/month (add-on to E3)
- Included in E5/Business Premium

### 2.3 Plan 2 Features

**Microsoft Defender for Office 365 Plan 2:**

✅ **All Plan 1 features, PLUS:**

**Investigation & Response:**
- **Threat Explorer** (full version) - advanced email threat hunting
- **Automated Investigation & Response (AIR)** - automated threat remediation
- **Email entity page** - deep email analysis
- **Campaign views** - see coordinated attack campaigns

**Threat Hunting:**
- **Advanced hunting** - KQL queries across email data
- **Threat trackers** - track emerging threats
- **Threat analytics** - analyst reports on campaigns

**Training & Simulation:**
- **Attack simulation training** - phish employees safely
- **Payload automation** - create custom simulations

✅ **Included In:**
- Microsoft 365 E5
- Microsoft 365 E5 Security
- Microsoft 365 Defender Suite (🆕 add-on to Business Premium)

**Cost (Approximate):**
- ~$5 USD per user/month (add-on to E3)
- Included in E5

### 2.4 Feature Comparison Matrix

**Detailed Feature Breakdown:**

| Feature | EOP (Free) | MDO Plan 1 | MDO Plan 2 | Exam Importance |
|---------|------------|------------|------------|-----------------|
| **Anti-spam** | ✅ Yes | ✅ Yes | ✅ Yes | ⭐⭐⭐ |
| **Anti-malware** | ✅ Yes | ✅ Yes | ✅ Yes | ⭐⭐⭐ |
| **Basic anti-phishing** | ✅ Yes | ✅ Yes | ✅ Yes | ⭐⭐⭐ |
| **Advanced anti-phishing** | ❌ No | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐⭐ |
| **Safe Attachments** | ❌ No | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐⭐ |
| **Safe Links** | ❌ No | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐⭐ |
| **Zero-hour auto purge (ZAP)** | ✅ Yes | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐ |
| **Real-time detections** | ❌ No | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐ |
| **Threat Explorer** | ❌ No | ❌ No | ✅ Yes | ⭐⭐⭐⭐⭐ |
| **Automated Investigation & Response (AIR)** | ❌ No | ❌ No | ✅ Yes | ⭐⭐⭐⭐⭐ |
| **Attack simulation training** | ❌ No | ❌ No | ✅ Yes | ⭐⭐⭐⭐ |
| **Threat trackers** | ❌ No | ❌ No | ✅ Yes | ⭐⭐⭐ |
| **Campaign views** | ❌ No | ❌ No | ✅ Yes | ⭐⭐⭐⭐ |
| **Priority account protection** | ❌ No | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐ |
| **Safe Documents** | ❌ No | ❌ No | ✅ E5 only | ⭐⭐⭐ |

### 2.5 Licensing Scenarios

**Scenario 1: Small Business (50 users)**

```
Need: Email protection from phishing and malware
Budget: Limited

Recommendation: Microsoft 365 Business Premium
- Includes MDO Plan 1
- Cost: ~$22/user/month
- Good balance of security and productivity tools
```

**Scenario 2: Enterprise (5,000 users)**

```
Need: Advanced threat protection, no SOC team
Budget: Moderate

Recommendation: Microsoft 365 E3 + MDO Plan 1
- E3: $36/user/month
- MDO Plan 1: +$2/user/month
- Total: ~$38/user/month
- Provides real-time protection without complex hunting tools
```

**Scenario 3: Enterprise with SOC (10,000 users)**

```
Need: Full threat hunting and investigation capabilities
Budget: Substantial

Recommendation: Microsoft 365 E5
- All-in-one: ~$57/user/month
- Includes MDO Plan 2, MDE, MDI, MDCA
- Full Threat Explorer, AIR, attack simulation
- Best for mature security teams
```

**Scenario 4: Upgrading from E3**

```
Current: Microsoft 365 E3
Goal: Add advanced email security and threat hunting

Option 1: Add MDO Plan 2
- E3: $36/user/month
- + MDO Plan 2: $5/user/month
- Total: $41/user/month

Option 2: Upgrade to E5
- E5: $57/user/month
- Includes MDO Plan 2 + MDE + MDI + more
- Better value if needing multiple advanced security products
```

### 2.6 License Assignment

**How to Assign Licenses:**

```
Method 1: Microsoft 365 Admin Center
1. Navigate to admin.microsoft.com
2. Users → Active users
3. Select user(s)
4. Licenses and apps
5. Check: "Microsoft Defender for Office 365 (Plan 1/2)"
6. Save

Method 2: Group-Based Licensing (Azure AD)
1. Azure AD → Groups
2. Create security group (e.g., "MDO-Licensed-Users")
3. Add members
4. Licenses → Assign
5. Select MDO Plan 1 or 2
6. Save
7. Users inherit license automatically

Method 3: PowerShell (Bulk)
# Connect
Connect-MsolService

# Assign MDO Plan 2 to all users
$AccountSkuId = "contoso:ATP_ENTERPRISE"  # Plan 2 SKU
Get-MsolUser -All | Set-MsolUserLicense -AddLicenses $AccountSkuId
```

**Verify License Assignment:**

```powershell
# Check if user has MDO license
Get-MsolUser -UserPrincipalName user@contoso.com | Select-Object DisplayName, Licenses

# Output shows:
# ATP_ENTERPRISE (Plan 2) or THREAT_INTELLIGENCE (Plan 1)
```

### 2.7 License SKUs (for Exam)

**Know These SKU Identifiers:**

| Product | SKU ID | Display Name |
|---------|--------|--------------|
| MDO Plan 1 | THREAT_INTELLIGENCE | Threat Intelligence |
| MDO Plan 2 | ATP_ENTERPRISE | Defender for Office 365 (Plan 2) |
| M365 E5 | SPE_E5 | Includes MDO Plan 2 |
| M365 Business Premium | SPB | Includes MDO Plan 1 |

**🎯 Exam Tip:** You don't need to memorize SKU IDs for exam, but understand:
- Plan 1 = Prevention (Safe Attachments, Safe Links, Real-time detections)
- Plan 2 = Plan 1 + Investigation/Hunting (Threat Explorer, AIR, Attack simulation)

---

## 3. Safe Attachments

### 3.1 Overview

**What is Safe Attachments?**

Safe Attachments protects against **unknown malware and viruses** by:
- Opening suspicious email attachments in a sandbox (isolated virtual environment)
- Observing behavior for malicious intent
- Blocking files that exhibit malicious behavior
- Allowing clean files through

**Why It's Needed:**

Traditional anti-malware relies on **signatures** (known virus patterns). Attackers can create **zero-day malware** with no known signature. Safe Attachments uses **behavioral analysis** to detect these threats.

### 3.2 How Safe Attachments Works

**Detonation Process:**

```
1. Email with Attachment Arrives
   └─ From: unknown@external.com
      Attachment: invoice.pdf

2. EOP Scans (Traditional AV)
   └─ Result: No known malware signature found
      → Passes to Safe Attachments

3. Safe Attachments Activated
   ├─ Policy check: Is sender/attachment covered?
   └─ If yes → Send to sandbox

4. Sandbox Detonation
   ├─ Attachment opened in isolated Windows VM
   ├─ PDF reader opens invoice.pdf
   ├─ Behavioral analysis runs (5-10 minutes):
   │  ├─ Does it drop files?
   │  ├─ Does it modify registry?
   │  ├─ Does it create network connections?
   │  └─ Does it execute suspicious code?
   └─ Machine learning analyzes behavior

5. Verdict
   ├─ If MALICIOUS detected:
   │  ├─ Attachment blocked/removed
   │  ├─ Email quarantined or warning added
   │  └─ Alert generated
   │
   └─ If CLEAN:
       └─ Attachment delivered normally

6. Delivery (with Dynamic Delivery if configured)
   ├─ Email body delivered immediately (no delay)
   ├─ Attachment replaced with placeholder
   └─ Once detonation completes:
       ├─ Clean → Original attachment restored
       └─ Malicious → Warning message instead
```

### 3.3 Safe Attachments Policies

**Policy Structure:**

```
Safe Attachments Policy
│
├─ Name: "Executive Protection"
├─ Applied to: VIP users group
│
├─ Settings:
│  ├─ Safe Attachments unknown malware response:
│  │  ├─ Monitor (detect only, no blocking) [REMOVED June 2025]
│  │  ├─ Block (quarantine email with malicious attachment)
│  │  ├─ Replace (remove attachment, deliver email body)
│  │  └─ Dynamic Delivery (deliver email, scan attachment)
│  │
│  ├─ Redirect attachment on detection:
│  │  └─ Send to: security@contoso.com
│  │
│  └─ Apply if malware scanning times out or error occurs:
│     └─ Enable (block even if scan fails)
│
└─ Priority: 1 (higher priority than default)
```

**Safe Attachments Response Actions:**

**🆕 June 2025 Update:** "Monitor" option **removed** - now defaults to blocking.

| Action | Description | When to Use | Exam Importance |
|--------|-------------|-------------|-----------------|
| **Block** | Block email, send to quarantine | Production (most secure) | ⭐⭐⭐⭐⭐ |
| **Replace** | Remove attachment, deliver email body | Users need email content ASAP | ⭐⭐⭐⭐ |
| **Dynamic Delivery** | Deliver email with placeholder, scan attachment | Best of both worlds (recommended) | ⭐⭐⭐⭐⭐ |
| ~~Monitor~~ | ~~Detect but allow~~ | ~~Testing/piloting~~ (REMOVED) | ⭐⭐⭐ |

**Dynamic Delivery (Recommended):**

```
User Experience with Dynamic Delivery:

1. Email arrives in inbox immediately
   Subject: Invoice from vendor
   Body: Please review attached invoice...
   Attachment: [Scanning in progress...]

2. User can read email, reply, forward
   → No delay waiting for scan

3. Attachment scanning completes (5-10 min)
   → Clean: [Download invoice.pdf] link appears
   → Malicious: [Attachment removed - security threat detected]

Benefits:
✅ No email delivery delay
✅ User productivity maintained  
✅ Full protection retained
✅ Smooth user experience
```

### 3.4 Coverage Scope

**Where Safe Attachments Protects:**

✅ **Email (Exchange Online)**
- Incoming email
- Internal email (optional)
- Outbound email (optional)

✅ **SharePoint Online**
- Files uploaded to SharePoint libraries
- Files in Teams channels (stored in SharePoint)
- Scanned asynchronously

✅ **OneDrive for Business**
- Files uploaded to OneDrive
- Files shared via OneDrive links

✅ **Microsoft Teams**
- Files shared in Teams chats/channels
- Files attached to Teams messages

**🆕 September 2025 Update:** Safe Attachments now extends to calendar invites!

### 3.5 Creating Safe Attachments Policies

**Method 1: Microsoft Defender Portal**

```
1. Navigate to: security.microsoft.com
2. Email & collaboration → Policies & rules
3. Threat policies → Safe Attachments
4. Click "+ Create"
5. Configure policy:

Step 1: Name policy
- Name: "Executive Email Protection"
- Description: "Enhanced protection for executive team"

Step 2: Users and domains
- Users: executives@contoso.com
- Groups: Executive Team
- Domains: (optional)
- Exclude: (optional exceptions)

Step 3: Settings
- Unknown malware response: Dynamic Delivery
- Redirect on detection: ✓ Enable
  - Redirect to: security@contoso.com
- Apply if scanning times out: ✓ Enable

Step 4: Review and submit
- Review settings
- Submit

6. Set priority (if multiple policies)
```

**Method 2: PowerShell**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Create Safe Attachments policy
New-SafeAttachmentPolicy -Name "Executive Protection" `
  -Action DynamicDelivery `
  -Redirect $true `
  -RedirectAddress security@contoso.com `
  -ActionOnError $true

# Create rule to apply policy
New-SafeAttachmentRule -Name "Executive Protection Rule" `
  -SafeAttachmentPolicy "Executive Protection" `
  -RecipientDomainIs "contoso.com" `
  -SentTo "executives@contoso.com" `
  -Priority 1
```

### 3.6 Built-in Safe Attachments Protection

**Default Policy (All Users):**

```
MDO includes built-in Safe Attachments for all users:

Policy: "Built-in protection policy (Microsoft managed)"
Settings:
- Action: Block
- Applies to: All recipients in organization
- Cannot be modified or deleted
- Always lowest priority (custom policies take precedence)

Purpose:
- Baseline protection for all users
- Ensures no email bypasses Safe Attachments
- Custom policies can override for specific users
```

### 3.7 Safe Attachments for SharePoint/OneDrive/Teams

**File Protection:**

```
Configuration:
1. Settings → Email & collaboration → Safe Attachments
2. Toggle ON: "Turn on Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams"
3. Save

What happens:
- Files uploaded to SharePoint/OneDrive/Teams scanned
- Malicious files blocked from download
- File marked with warning icon
- Admins notified
- Users see: "This file is malicious and has been blocked"

Behavior:
- Scan happens asynchronously (after upload)
- File initially downloadable (brief window)
- Once detected as malicious:
  → Download blocked
  → Admin can delete or allow (false positive)
```

**⚠️ Important Limitation:**
- Only scans files **< 400 MB**
- Larger files not scanned by Safe Attachments
- Use other protections (DLP, AIP) for large files

### 3.8 Exceptions and Exclusions

**When to Exclude:**

```
Scenarios for Exclusions:
1. Trusted partner domains
   - Vendor sending legitimate attachments
   - Known false positive source

2. Internal testing
   - Security team testing malware samples
   - Development environments

3. Performance reasons
   - High-volume automated systems
   - Not recommended for general use

How to Exclude:
- Policy settings → Exceptions
- Add user/group/domain to exclude
- Document reason for exception
- Review quarterly
```

### 3.9 Monitoring Safe Attachments

**Reports:**

```
View Safe Attachments Activity:

1. Defender Portal → Reports → Email & collaboration
2. Safe Attachments report shows:
   - Files scanned
   - Malicious files detected
   - False positives
   - Top targeted users
   - File types scanned

3. Threat Explorer (Plan 2):
   - Filter: Attachment
   - View: Malware detections
   - Drill into specific emails
   - See sandbox detonation results
```

**Alerts:**

```
Safe Attachments generates alerts:
- Malware detected in attachment
- Severity: Medium-High
- Action: Review and remediate
- Investigate: Check for other emails from sender
```

### 3.10 Troubleshooting

**Issue 1: Attachments Not Being Scanned**

```
Symptoms:
- Malicious attachment delivered
- Safe Attachments not triggered

Causes & Solutions:

1. No policy applied to user
   Check: User's license and policy assignment
   Fix: Ensure user covered by Safe Attachments policy

2. Attachment type excluded
   Check: File type (e.g., .zip, encrypted files may bypass)
   Fix: Review policy exceptions

3. File too large (> 400 MB)
   Check: Attachment size
   Fix: Educate users, implement file size limits

4. Sender on allow list
   Check: Connection filter allow list
   Fix: Remove if no longer trusted

5. Built-in protection disabled
   Check: Organization settings
   Fix: Ensure Safe Attachments globally enabled
```

**Issue 2: Too Many False Positives**

```
Symptoms:
- Legitimate attachments blocked
- User complaints

Solutions:

1. Submit false positive to Microsoft
   - Admin submission portal
   - Microsoft improves detection

2. Create exception for sender/domain
   - Last resort (reduces security)
   - Document business justification

3. Use "Replace" instead of "Block"
   - Delivers email body
   - Users can request attachment release

4. Check attachment file type
   - Some file types more prone to FPs
   - Educate users on alternative delivery methods
```

**🎯 Exam Tip:** 
- **Dynamic Delivery** is the **recommended** action (best user experience + security)
- **Block** is the **most secure** (but may delay emails)
- **Monitor** mode was **removed in June 2025** (exam may still reference it)

---

## 4. Safe Links

### 4.1 Overview

**What is Safe Links?**

Safe Links provides **time-of-click protection** against malicious URLs by:
- Rewriting URLs in emails (proxy through Microsoft)
- Checking URL reputation when user clicks
- Blocking access to known malicious sites
- Warning users about suspicious links

**Why It's Needed:**

Attackers can:
- Send clean email with legitimate-looking URL
- LATER compromise that URL (weaponize it)
- Traditional email scanning misses this (link was clean at delivery time)

Safe Links protects at **click-time**, not just **delivery-time**.

### 4.2 How Safe Links Works

**URL Rewriting & Time-of-Click Verification:**

```
Original Email:
───────────────
From: attacker@phish.com
Click here to view invoice:
https://malicious-site.com/invoice

After Safe Links Rewriting:
───────────────────────────
Click here to view invoice:
https://*.safelinks.protection.outlook.com/?url=https%3A%2F%2Fmalicious-site.com...

What Happens:

1. Email arrives → Safe Links rewrites all URLs
   - Original URL encoded in Safe Links wrapper
   - Transparent to user (looks normal in most clients)

2. User clicks link → Request goes to Microsoft
   ├─ Microsoft checks URL reputation in real-time
   ├─ URL reputation sources:
   │  ├─ Microsoft threat intelligence
   │  ├─ Global detonation data
   │  ├─ URL reputation database
   │  └─ Machine learning models
   │
   ├─ Verdict determined:
   │  ├─ CLEAN → Redirect to original URL
   │  ├─ SUSPICIOUS → Show warning page
   │  └─ MALICIOUS → Block access
   │
   └─ Action taken based on verdict

3. If Malicious → Warning Page Displayed
   ┌─────────────────────────────────┐
   │  ⚠️ THIS SITE HAS BEEN BLOCKED  │
   │                                 │
   │  This website has been          │
   │  identified as malicious and    │
   │  could harm your device.        │
   │                                 │
   │  [Go Back]  [More Info]        │
   └─────────────────────────────────┘

4. Admin notified via alert
   - URL blocked
   - User affected
   - Email details
   - Incident created
```

### 4.3 Safe Links Policies

**Policy Structure:**

```
Safe Links Policy
│
├─ Name: "Corporate Users"
├─ Applied to: All users
│
├─ Email Settings:
│  ├─ URL & click protection settings:
│  │  ├─ On: URLs will be rewritten ✓
│  │  ├─ Apply real-time URL scanning ✓
│  │  ├─ Apply Safe Links to email messages ✓
│  │  ├─ Apply Safe Links to Teams messages ✓
│  │  ├─ Apply Safe Links to Office apps ✓
│  │  ├─ Wait for URL scanning before delivering ⚠️
│  │  ├─ Do not rewrite URLs, do checks via API ⚠️
│  │  └─ Do not rewrite certain URLs:
│  │     └─ internal.contoso.com/*
│  │
│  ├─ Notification:
│  │  ├─ Use custom notification text ✓
│  │  └─ Custom message: "Blocked by IT Security..."
│  │
│  └─ Click protection:
│     ├─ Track user clicks ✓
│     └─ Let users click through to original URL ❌
│
└─ Priority: 1
```

**Key Settings Explained:**

| Setting | Description | Recommended | Exam Importance |
|---------|-------------|-------------|-----------------|
| **On: URLs will be rewritten** | Enable URL rewriting | ✅ On | ⭐⭐⭐⭐⭐ |
| **Apply real-time URL scanning** | Check URL at click-time | ✅ On | ⭐⭐⭐⭐⭐ |
| **Apply to Teams messages** | Protect Teams links | ✅ On | ⭐⭐⭐⭐ |
| **Apply to Office apps** | Protect Word/Excel/PPT links | ✅ On | ⭐⭐⭐⭐ |
| **Wait for URL scanning** | Delay email delivery until scan completes | ⚠️ Off (causes delays) | ⭐⭐⭐ |
| **Track user clicks** | Log click activity | ✅ On (for threat hunting) | ⭐⭐⭐⭐ |
| **Let users click through** | Allow users to proceed despite warning | ❌ Off (reduce risk) | ⭐⭐⭐⭐⭐ |

### 4.4 URL Rewriting Behavior

**What Gets Rewritten:**

```
✅ Rewritten (Protected):
- http:// and https:// links
- Links in email body
- Links in Teams messages
- Links in Office documents (if policy enabled)

❌ NOT Rewritten:
- Links in attachments (PDFs, Word docs in email)
  → Use Safe Documents for this
- Links from trusted domains (if excluded in policy)
- mailto: links
- ftp:// links
- File shares (\\server\share)
```

**User Experience:**

```
In Outlook Desktop/Web:
- User hovers over link
- Status bar shows safelinks.protection.outlook.com URL
- When clicked, briefly redirects through Microsoft
- If clean, lands on destination site
- Process takes ~100-500ms (imperceptible to user)

In Mobile Outlook:
- Links show normally
- Tap opens in-app browser
- Microsoft checks URL
- If clean, loads destination
```

### 4.5 Protection Scope

**Where Safe Links Protects:**

✅ **Email (Exchange Online)**
- Incoming email
- Internal email
- Email in Quarantine (when user clicks link in quarantine)

✅ **Microsoft Teams**
- Links in chat messages
- Links in channel posts
- Links in meeting notes
- 🆕 September 2025: Enhanced Teams protection

✅ **Office 365 Apps**
- Word, Excel, PowerPoint (desktop and web)
- Outlook (when opening embedded Word docs)
- OneNote (🆕 2024-2025)
- Requires: Office 365 ProPlus

### 4.6 Creating Safe Links Policies

**Method 1: Microsoft Defender Portal**

```
1. security.microsoft.com
2. Email & collaboration → Policies & rules
3. Threat policies → Safe Links
4. Click "+ Create"

Step 1: Name policy
- Name: "Executive Protection"
- Description: "Enhanced URL protection for executives"

Step 2: Users and domains
- Users: executives@contoso.com
- Groups: Executive Team
- Domains: (optional)

Step 3: URL & click protection settings
- ✓ On: URLs will be rewritten
- ✓ Apply real-time URL scanning
- ✓ Apply Safe Links to email messages sent within organization
- ✓ Apply Safe Links to Microsoft Teams
- ✓ Apply Safe Links to Office applications
- ☐ Wait for URL scanning to complete before delivering (not recommended)
- ☐ Do not rewrite URLs, check via Safe Links API only
- ✓ Track user clicks
- ☐ Let users click through to original URL

Step 4: Notification
- ✓ Use custom notification text
- Message: "This link has been blocked by IT Security. Contact helpdesk if legitimate."

Step 5: Review and submit
```

**Method 2: PowerShell**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Create Safe Links policy
New-SafeLinksPolicy -Name "Executive Protection" `
  -IsEnabled $true `
  -EnableSafeLinksForEmail $true `
  -EnableSafeLinksForTeams $true `
  -EnableSafeLinksForOffice $true `
  -TrackClicks $true `
  -AllowClickThrough $false `
  -ScanUrls $true `
  -EnableForInternalSenders $true `
  -DeliverMessageAfterScan $true

# Create rule to apply policy
New-SafeLinksRule -Name "Executive Protection Rule" `
  -SafeLinksPolicy "Executive Protection" `
  -RecipientDomainIs "contoso.com" `
  -SentTo "executives@contoso.com" `
  -Priority 1
```

### 4.7 Do Not Rewrite List

**Excluding URLs from Rewriting:**

```
When to Exclude:
1. Internal SharePoint/OneDrive links
   - Already protected by Safe Attachments
   - No need to rewrite

2. Trusted partner sites
   - Known, reputable partners
   - Reduces user friction

3. Single Sign-On (SSO) links
   - May break authentication flow
   - Test before excluding!

How to Configure:
1. Safe Links policy → Settings
2. "Do not rewrite the following URLs"
3. Add entries (supports wildcards):
   - https://sharepoint.contoso.com/*
   - https://partner-portal.trustedvendor.com
   - *.internal.company.net

Format:
- Full URLs: https://site.com/path
- Wildcards: https://*.domain.com/*
- No http:// → Won't match
```

**⚠️ Security Warning:**
- Excluding URLs **reduces protection**
- Only exclude well-known, trusted sites
- Review quarterly
- Document business justification

### 4.8 Safe Links for Office Apps

**Office 365 ProPlus Protection:**

```
Requirement:
- Office 365 ProPlus (Microsoft 365 Apps)
- Version 1809 or later
- Safe Links policy with "Office apps" enabled
- User must be signed in with work account

Protected Apps:
- Word
- Excel
- PowerPoint
- Visio
- Outlook (embedded documents)
- OneNote (🆕 2024)

What Happens:
1. User opens Word document with hyperlink
2. User clicks hyperlink
3. Safe Links checks URL before opening browser
4. If malicious → Warning dialog box
5. If clean → Browser opens to destination

User Experience:
- Brief delay (~100-300ms) before browser opens
- Warning dialog if malicious:
  ┌───────────────────────────────┐
  │  ⚠️ Microsoft Defender        │
  │                                │
  │  This link may not be safe.   │
  │                                │
  │  [Cancel]  [More Info]        │
  └───────────────────────────────┘
```

### 4.9 Monitoring Safe Links

**URLClickEvents Table (🆕 2025):**

Microsoft introduced dedicated **UrlClickEvents** table in Advanced Hunting:

```kql
// Find all blocked URLs in last 7 days
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| project Timestamp, AccountUpn, Url, ThreatTypes, ClickSource
| order by Timestamp desc

// Top blocked URLs
UrlClickEvents
| where Timestamp > ago(30d)
| where ActionType == "ClickBlocked"
| summarize BlockedClicks = count() by Url
| top 10 by BlockedClicks
```

**Reports:**

```
1. Defender Portal → Reports → Email & collaboration
2. Safe Links report shows:
   - URLs clicked
   - Malicious URLs blocked
   - Warnings displayed
   - Top targeted users
   - Top malicious domains

3. Threat Explorer (Plan 2):
   - Filter: URL clicks
   - View: Blocked clicks
   - Drill into specific emails
   - See user click behavior
```

### 4.10 Troubleshooting

**Issue 1: Links Not Being Rewritten**

```
Symptoms:
- URLs in email not wrapped with safelinks.protection.outlook.com
- Users clicking directly to destination

Causes & Solutions:

1. Policy not applied to user
   Check: User covered by Safe Links policy?
   Fix: Assign policy or include in default policy

2. URL on "Do Not Rewrite" list
   Check: Policy exceptions
   Fix: Remove from exclusion list if not needed

3. Link format not supported
   Check: Is it mailto:, ftp://, or file share?
   Fix: These link types aren't supported by Safe Links

4. Email sent before policy activated
   Check: Email timestamp vs policy creation
   Fix: Only affects NEW emails after policy active
```

**Issue 2: Users Can Click Through Warning**

```
Symptoms:
- Users bypass malicious URL warnings
- Clicking "Continue anyway" button

Cause:
- "Let users click through to original URL" enabled in policy

Solution:
1. Edit Safe Links policy
2. Uncheck "Let users click through to original URL"
3. Save
4. Users now see "Go Back" only (no bypass option)
```

**Issue 3: SSO Links Breaking**

```
Symptoms:
- Single Sign-On not working after clicking link
- Authentication loops or failures

Cause:
- Safe Links rewriting breaks SSO authentication flow

Solution:
Option 1: Add SSO domain to "Do Not Rewrite" list
- https://sso.partner.com/*

Option 2: Use "API check only" mode
- Enables: "Do not rewrite URLs, do checks via API"
- URL not rewritten, but still checked when clicked
- More compatible with SSO flows
```

**🎯 Exam Tip:**
- Safe Links = **Time-of-click** protection (not just delivery)
- URLs **rewritten** to proxy through Microsoft
- Protects in **Email, Teams, and Office apps**
- **Do NOT** enable "Let users click through" (reduces security)
- 🆕 **UrlClickEvents** table for hunting (introduced 2025)

---

## 5. Anti-Phishing Policies

### 5.1 Overview

**What is Anti-Phishing?**

Anti-phishing protects against **phishing attacks** where attackers:
- Impersonate trusted users or domains
- Steal credentials via fake login pages
- Conduct business email compromise (BEC)
- Use social engineering tactics

**Phishing Types Detected:**

```
1. User Impersonation
   └─ Attacker pretends to be CEO, executive, or colleague
      Example: From: "CEO John Smith" <ceo-john-smith@evil.com>

2. Domain Impersonation
   └─ Attacker uses similar-looking domain
      Example: contoso.com → cont0so.com (zero instead of O)
      Example: contoso.com → contoso-secure.com

3. Spoof (Unauthenticated Email)
   └─ Attacker sends email appearing to come from your domain
      Example: From: admin@contoso.com (but not really)
      Failed: SPF, DKIM, or DMARC

4. Credential Phishing
   └─ Email contains fake login page to steal passwords
      Example: "Your password will expire, click here to reset"

5. Mailbox Intelligence
   └─ ML-based detection of unusual sender patterns
      Example: User normally gets emails from finance@ but now from
      CEO with urgent wire transfer request
```

### 5.2 Anti-Phishing Protection Levels

**Comparison:**

| Feature | EOP (Basic) | MDO Plan 1/2 (Advanced) |
|---------|-------------|-------------------------|
| **Spoof intelligence** | ✅ Yes | ✅ Yes |
| **Anti-spoofing protection** | ✅ Yes | ✅ Yes |
| **Safety tips** | ✅ Yes | ✅ Yes |
| **User impersonation protection** | ❌ No | ✅ Yes |
| **Domain impersonation protection** | ❌ No | ✅ Yes |
| **Mailbox intelligence** | ❌ No | ✅ Yes |
| **Mailbox intelligence impersonation** | ❌ No | ✅ Yes |
| **Advanced phishing thresholds** | ❌ No | ✅ Yes |

**🎯 Key Difference:** MDO adds **impersonation protection** (user & domain) that EOP doesn't have.

### 5.3 Anti-Phishing Policy Structure

**Policy Components:**

```
Anti-Phishing Policy: "Executive Protection"
│
├─ Phishing Email Threshold
│  └─ Level: 2 - Aggressive (most sensitive detection)
│
├─ Impersonation
│  ├─ User Protection (Users to protect)
│  │  ├─ CEO: ceo@contoso.com
│  │  ├─ CFO: cfo@contoso.com
│  │  └─ [Up to 350 users]
│  │
│  ├─ Domain Protection (Domains to protect)
│  │  ├─ contoso.com
│  │  ├─ contoso-partners.com
│  │  └─ [Up to 50 domains]
│  │
│  ├─ Trusted Senders/Domains (Exclusions)
│  │  ├─ partner@vendor.com (legitimate similar name)
│  │  └─ automated@c0ntos0.com (legacy system)
│  │
│  └─ Mailbox Intelligence
│     ├─ Enable mailbox intelligence ✓
│     └─ Enable intelligence-based impersonation ✓
│
├─ Spoof Intelligence
│  └─ Enable spoof intelligence ✓
│
├─ Actions
│  ├─ If email detected as impersonated USER:
│  │  └─ Quarantine message
│  ├─ If email detected as impersonated DOMAIN:
│  │  └─ Quarantine message
│  ├─ If mailbox intelligence detects impersonation:
│  │  └─ Move to Junk folder
│  └─ If email detected as spoof:
│     └─ Move to Junk folder
│
└─ Safety Tips & Indicators
   ├─ Show first contact safety tip ✓
   ├─ Show user impersonation safety tip ✓
   ├─ Show domain impersonation safety tip ✓
   ├─ Show user impersonation unusual characters tip ✓
   └─ Show (via) tag for unauthenticated senders ✓
```

### 5.4 Phishing Threshold

**Threshold Levels:**

| Level | Sensitivity | False Positives | False Negatives | Best For |
|-------|-------------|-----------------|-----------------|----------|
| **1 - Standard** | Low | Low FPs | Higher FNs | General users, balanced approach |
| **2 - Aggressive** | Medium | Medium FPs | Lower FNs | Important users (executives, finance) |
| **3 - More Aggressive** | High | Higher FPs | Low FNs | VIPs, high-risk targets |
| **4 - Most Aggressive** | Very High | Highest FPs | Lowest FNs | Testing only, not for production |

**Choosing Threshold:**

```
Decision Tree:

Are users frequent targets (executives, finance)?
├─ Yes → Use Level 2 (Aggressive) or Level 3 (More Aggressive)
└─ No → Use Level 1 (Standard)

Do you have security team to handle FPs?
├─ Yes → Can use higher levels
└─ No → Stick with Level 1 (Standard)

Recommendation:
- Default policy: Level 1 (Standard)
- Executive policy: Level 2 (Aggressive)
- VIP policy (CEO, CFO): Level 3 (More Aggressive)
```

### 5.5 Impersonation Protection

**User Impersonation:**

Protects specific users from being impersonated.

```
Configuration:

1. Add users to protect (up to 350):
   - CEO: ceo@contoso.com
   - CFO: cfo@contoso.com
   - HR Director: hr-director@contoso.com

2. MDO watches for:
   - Display names similar to protected users
   - Example: "CEO" vs "CE0" (zero), "ĈĒŎ" (unicode)

3. Detection example:
   Email arrives:
   ┌────────────────────────────────┐
   │ From: "CEO John Smith"         │
   │ <ceo-imposter@evil.com>        │
   │                                │
   │ Please wire $50,000 to vendor  │
   │ Account: ...                   │
   └────────────────────────────────┘
   
   MDO detects:
   - Display name "CEO John Smith" matches protected user
   - But email domain is evil.com (not contoso.com)
   - Verdict: User impersonation attack
   - Action: Quarantine (per policy)

4. User sees (if moved to Junk):
   ⚠️ This sender may be impersonating ceo@contoso.com
```

**Domain Impersonation:**

Protects your domains from look-alike attacks.

```
Configuration:

1. Add domains to protect (up to 50):
   - contoso.com
   - contoso-partners.com

2. MDO watches for similar domains:
   - contoso.com → cont0so.com (zero instead of O)
   - contoso.com → c0ntoso.com
   - contoso.com → contoso-secure.com
   - contoso.com → contosо.com (Cyrillic O)

3. Detection example:
   Email arrives:
   ┌────────────────────────────────┐
   │ From: admin@cont0so.com        │  ← Impersonation
   │                                │
   │ Your account has been locked.  │
   │ Click here to unlock: [link]   │
   └────────────────────────────────┘
   
   MDO detects:
   - Domain "cont0so.com" visually similar to "contoso.com"
   - Edit distance algorithm: 1 character different
   - Verdict: Domain impersonation attack
   - Action: Quarantine (per policy)
```

**Mailbox Intelligence Impersonation:**

Uses ML to learn normal communication patterns.

```
How It Works:

1. Machine Learning Baseline (60-90 days)
   - Learns who user normally emails
   - Learns communication patterns
   - Learns typical sender domains

2. Anomaly Detection
   - New sender pretending to be known contact
   - Unusual urgency or financial request
   - Pattern doesn't match baseline

3. Example Detection:
   User's baseline:
   - Regularly emails finance@vendor.com
   - Never emails from CEO about wire transfers
   - CEO usually emails from ceo@contoso.com
   
   Suspicious email arrives:
   ┌────────────────────────────────┐
   │ From: CEO <ceo-urgent@gmail.com> │ ← Unusual!
   │                                │
   │ Urgent wire transfer needed!   │ ← Unusual!
   │ Account: [external bank]       │
   └────────────────────────────────┘
   
   Mailbox intelligence detects:
   - CEO never uses Gmail
   - CEO never requests wire transfers via email
   - Urgent tone is unusual
   - Verdict: Likely impersonation
   - Action: Move to Junk folder
```

### 5.6 Spoof Intelligence

**What is Spoofing?**

Sending email that appears to come from someone else:
- From header: shows victim@contoso.com
- But really sent from: attacker@evil.com
- Email authentication (SPF/DKIM/DMARC) fails

**Spoof Intelligence Features:**

```
1. Composite Authentication (compauth)
   Combines multiple signals:
   - SPF: Did email come from authorized server?
   - DKIM: Is email signed by sending domain?
   - DMARC: What does domain owner want us to do?
   - Additional ML signals
   
   Verdict: pass, softfail, fail, none

2. Spoof Intelligence Insight
   Dashboard showing:
   - Allowed spoofed senders (legitimate)
   - Blocked spoofed senders (malicious)
   - Review and take action

3. Automatic Learning
   - Learns legitimate spoofing scenarios
   - Example: Mailing list that forwards emails
   - Example: Ticketing system sending on behalf of users
```

**Managing Spoof Intelligence:**

```
1. Defender Portal → Email & collaboration → Policies
2. Threat policies → Anti-phishing
3. Spoof intelligence
4. Review spoofed senders:

Example:
┌────────────────────────────────────────────────┐
│ Spoofed Sender        | True Sender   | Action │
├────────────────────────────────────────────────┤
│ hr@contoso.com        | mailinglist   | Allow  │ ← Legitimate
│ ceo@contoso.com       | attacker.com  | Block  │ ← Malicious
│ noreply@contoso.com   | helpdesk.com  | Allow  │ ← Legitimate
└────────────────────────────────────────────────┘

Actions:
- Allow: Legitimate spoofing (mailing lists, ticketing)
- Block: Malicious spoofing
```

### 5.7 Safety Tips

**Built-in Visual Warnings:**

```
Safety Tip Types:

1. First Contact Safety Tip
   ┌────────────────────────────────┐
   │ ⓘ First time sender            │
   │                                │
   │ You haven't received email     │
   │ from this sender before.       │
   └────────────────────────────────┘
   
   Shows: When receiving email from new sender
   Purpose: Make users cautious with unknown senders

2. User Impersonation Tip
   ┌────────────────────────────────┐
   │ ⚠️ Impersonation Warning        │
   │                                │
   │ This sender may be             │
   │ impersonating CEO@contoso.com  │
   └────────────────────────────────┘
   
   Shows: When display name matches protected user
   Purpose: Alert user to potential CEO fraud

3. Domain Impersonation Tip
   ┌────────────────────────────────┐
   │ ⚠️ Suspicious Domain            │
   │                                │
   │ This domain looks similar to   │
   │ contoso.com but isn't the same │
   └────────────────────────────────┘
   
   Shows: When sender domain is similar to protected domain
   Purpose: Alert user to typosquatting

4. Unusual Characters Tip
   ┌────────────────────────────────┐
   │ ⚠️ Unusual Characters           │
   │                                │
   │ This sender's name contains    │
   │ unusual characters             │
   └────────────────────────────────┘
   
   Shows: Unicode or mixed-script characters in sender name
   Purpose: Detect homograph attacks

5. Via Tag (Unauthenticated Sender)
   From: admin@contoso.com via mail.attacker.com
   
   Shows: When SPF/DKIM checks show actual sender differs
   Purpose: Show true sending infrastructure
```

### 5.8 Creating Anti-Phishing Policies

**Method 1: Microsoft Defender Portal**

```
1. security.microsoft.com
2. Email & collaboration → Policies & rules
3. Threat policies → Anti-phishing
4. Click "+ Create"

Step 1: Policy name
- Name: "Executive Anti-Phishing"
- Description: "Enhanced phishing protection for executives"

Step 2: Users, groups, and domains
- Users: ceo@contoso.com, cfo@contoso.com
- Groups: Executive Team
- Domains: (optional)

Step 3: Phishing threshold & protection
- Phishing email threshold: 2 - Aggressive

Step 4: Impersonation
- Users to protect:
  * Add: CEO <ceo@contoso.com>
  * Add: CFO <cfo@contoso.com>
  
- Domains to protect:
  * Add: contoso.com
  * Add: contoso-partners.com

- Trusted senders and domains:
  * (Add known exceptions if needed)

- ✓ Enable mailbox intelligence
- ✓ Enable mailbox intelligence-based impersonation protection

Step 5: Actions
- User impersonation: Quarantine message
- Domain impersonation: Quarantine message
- Mailbox intelligence impersonation: Move to Junk
- Spoof: Move to Junk

Step 6: Safety tips
- ✓ Show first contact safety tip
- ✓ Show user impersonation safety tip
- ✓ Show domain impersonation safety tip
- ✓ Show user impersonation unusual characters tip
- ✓ Show (via) tag for unauthenticated senders

Step 7: Review and submit
```

**Method 2: PowerShell**

```powershell
# Connect
Connect-ExchangeOnline

# Create anti-phishing policy
New-AntiPhishPolicy -Name "Executive Protection" `
  -PhishThresholdLevel 2 `
  -EnableTargetedUserProtection $true `
  -TargetedUsersToProtect "ceo@contoso.com","cfo@contoso.com" `
  -TargetedUserProtectionAction Quarantine `
  -EnableTargetedDomainsProtection $true `
  -TargetedDomainsToProtect "contoso.com" `
  -TargetedDomainProtectionAction Quarantine `
  -EnableMailboxIntelligence $true `
  -EnableMailboxIntelligenceProtection $true `
  -MailboxIntelligenceProtectionAction MoveToJmf `
  -EnableSpoofIntelligence $true `
  -EnableFirstContactSafetyTips $true `
  -EnableSimilarUsersSafetyTips $true `
  -EnableSimilarDomainsSafetyTips $true `
  -EnableUnusualCharactersSafetyTips $true `
  -EnableUnauthenticatedSender $true

# Create rule to apply policy
New-AntiPhishRule -Name "Executive Protection Rule" `
  -AntiPhishPolicy "Executive Protection" `
  -SentTo "ceo@contoso.com","cfo@contoso.com" `
  -Priority 0
```

### 5.9 Priority Account Protection (🆕 2024-2025)

**What is Priority Account Protection?**

Differentiated protection for priority accounts was introduced in Microsoft Defender for Office 365, providing **stricter security controls** for VIPs.

```
Priority Account Features:

1. Tag Accounts as Priority
   - Mark up to 250 accounts as "Priority"
   - CEO, CFO, executives, board members
   - High-value targets

2. Enhanced Protection
   - More aggressive phishing detection
   - Faster alert escalation
   - Higher investigation priority
   - Dedicated reports

3. Visibility
   - Priority account tag visible in:
     * Threat Explorer
     * Incident queue
     * Reports
   - Easy filtering by priority accounts

4. Differentiated Policies
   - Apply stricter anti-phishing policies
   - Higher Safe Links/Attachments scrutiny
   - Lower tolerance for risk
```

**Configuring Priority Accounts:**

```
Method 1: Microsoft 365 Admin Center
1. admin.microsoft.com
2. Users → Active users
3. Select user
4. Manage account settings
5. Priority account: Toggle ON
6. Save

Method 2: PowerShell
Set-User -Identity "ceo@contoso.com" -IsPriorityAccount $true
Get-User -IsPriorityAccount | Select DisplayName, UserPrincipalName

Method 3: Bulk via CSV
Import-Csv "C:\priority-accounts.csv" | ForEach-Object {
    Set-User -Identity $_.Email -IsPriorityAccount $true
}
```

**🆕 GCC/GCC-H/DoD Availability (2024):**

Priority account protection is now available in government clouds (GCC, GCC-H, and DoD), extending VIP protection to government organizations.

### 5.10 Monitoring Anti-Phishing

**Reports:**

```
1. Defender Portal → Reports → Email & collaboration
2. Threat protection status report shows:
   - Phishing emails detected
   - User impersonation blocks
   - Domain impersonation blocks
   - Spoofed emails
   - Top targeted users

3. Threat Explorer (Plan 2):
   - Filter: Phish
   - View: All email, Malware, Phish
   - Drill into specific campaigns
   - See impersonation attempts

4. Priority Account Report:
   - Dedicated report for priority accounts
   - Shows threats targeting VIPs
   - Enhanced visibility
```

**Alerts:**

```
Anti-phishing generates alerts:
- User impersonation detected
- Domain impersonation detected
- Spoof detected
- Mailbox intelligence anomaly

Alert actions:
- Review sender
- Check if legitimate (add to trusted list)
- Hunt for similar emails
- User education if fell for phish
```

**🎯 Exam Tip:**
- **Impersonation protection** = MDO feature (not in EOP)
- **User impersonation** = Protect specific individuals (CEO, CFO)
- **Domain impersonation** = Protect your domains from look-alikes
- **Mailbox intelligence** = ML-based detection of unusual patterns
- **Phishing threshold** = Level 1 (Standard) to 4 (Most Aggressive)
- **Priority accounts** = VIP tagging for enhanced protection (🆕 2024-2025)

---

*[Continuing to next section in a moment due to length...]*

Tôi đã tạo xong **50% của Module 3** với 5 sections đầu tiên chi tiết về MDO core features. Do giới hạn length, tôi sẽ tạo phần 2 riêng với 10 sections còn lại. 

Bạn muốn tôi:
1. **Tiếp tục tạo Part 2 ngay** (sections 6-15) ✅ Recommended
2. Xem Part 1 trước rồi quyết định

Tôi recommend làm luôn Part 2 để có full module! Làm tiếp nhé? 🚀
