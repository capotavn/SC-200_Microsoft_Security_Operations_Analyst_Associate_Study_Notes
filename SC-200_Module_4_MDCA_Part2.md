# SC-200 Study Notes - Module 4: Microsoft Defender for Cloud Apps (MDCA)
## ☁️ Part 2 (FINAL): Advanced Features and Exam Mastery

**Continuation from Part 1** - Sections 5-15
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest MDCA Updates

---

## 5. Information Protection

### 5.1 Overview

**Information Protection in MDCA:**

MDCA integrates with **Microsoft Purview Information Protection** to:
- Apply sensitivity labels automatically
- Encrypt files in cloud apps
- Control file sharing based on labels
- Enforce DLP policies across cloud apps

**Integration Points:**

```
Microsoft Purview Information Protection
│
├─ Sensitivity Labels (Confidential, Internal, Public)
├─ DLP Policies (prevent data leaks)
├─ Encryption (Azure RMS)
└─ Classification (manual + auto)

↓ Integration

Microsoft Defender for Cloud Apps
├─ Scan files for sensitive content
├─ Apply labels automatically
├─ Enforce sharing restrictions
├─ Alert on policy violations
└─ Quarantine non-compliant files
```

### 5.2 Sensitivity Labels

**Label Classification:**

```
Typical Label Hierarchy:

📁 Public
├─ No protection
├─ Anyone can access
└─ Example: Marketing materials

📁 Internal
├─ Company employees only
├─ Cannot share externally
└─ Example: Internal memos

📁 Confidential
├─ Specific departments only
├─ Encrypted
├─ No external sharing
└─ Example: Financial reports

📁 Highly Confidential
├─ Senior leadership only
├─ Encrypted + watermarked
├─ No download, no print
└─ Example: M&A documents
```

**Label Actions in MDCA:**

```
What MDCA Can Do with Labels:

1. Inspect (Read existing labels)
   - Scan files in cloud apps
   - Identify label: "This file is Confidential"

2. Apply (Auto-label files)
   - Policy: If file contains SSN → Apply "Confidential"
   - MDCA scans content → Applies label

3. Remove (Downgrade protection)
   - Policy: If file mislabeled → Remove label
   - Requires justification

4. Enforce (Control based on labels)
   - Policy: If label = "Confidential" → Block external sharing
   - User tries to share → Blocked

5. Quarantine (Isolate non-compliant)
   - Policy: If "Highly Confidential" + no encryption → Quarantine
   - File access blocked until remediated
```

### 5.3 Automatic Labeling

**Auto-Classification Policies:**

```
Example: Auto-label files with credit card numbers

Policy Configuration:
1. MDCA → Policies → File policy → Create
2. Policy name: "Auto-label files with credit cards"
3. Files matching:
   - Content inspection: Credit card numbers (regex)
   - App: Office 365 (SharePoint, OneDrive)
   - Owner: All users
4. Apply governance action:
   - Apply sensitivity label: "Confidential"
   - Notify file owner: Yes

Workflow:
1. User uploads "customer_data.xlsx" to SharePoint
2. MDCA scans file (via API connector)
3. Detects: 50 credit card numbers in file
4. Action: Applies "Confidential" label
5. Notification sent to user:
   "Your file was automatically labeled as Confidential
    due to sensitive content (credit card numbers).
    Do not share externally."
6. Label visible in SharePoint (metadata + visual marker)

Result:
- File now protected by "Confidential" label
- Sharing restrictions enforced
- Encryption applied (if label configured for encryption)
```

### 5.4 Content Inspection

**Supported Content Inspection Methods:**

```
1. Built-in DLP (Data Loss Prevention)
   ├─ Pre-defined sensitive info types:
   │  ├─ Credit card numbers
   │  ├─ Social Security Numbers (SSN)
   │  ├─ IBAN (bank account numbers)
   │  ├─ Passport numbers
   │  ├─ IP addresses
   │  └─ 100+ types
   │
   └─ Microsoft Purview DLP integration

2. Custom Regular Expressions (Regex)
   ├─ Define custom patterns
   ├─ Example: Internal employee ID (EMP-\d{6})
   └─ Example: Custom product codes

3. Document Fingerprinting
   ├─ Create fingerprint of template document
   ├─ Detect similar documents
   └─ Example: Detect all contracts based on template

4. Exact Data Match (EDM)
   ├─ Upload database of sensitive values
   ├─ Hash and store securely
   ├─ Detect exact matches in files
   └─ Example: Entire customer database

5. Optical Character Recognition (OCR)
   ├─ Scan text in images
   ├─ Extract text from screenshots
   └─ Example: Detect SSN in photo of document
```

**Content Inspection Configuration:**

```
Example: Detect files with SSN

Policy: File Policy
- Name: "Detect SSN in files"
- File filters:
  * App: Office 365
  * File type: All
  * Content inspection:
    └─ Sensitive info type: U.S. Social Security Number (SSN)
    └─ Minimum instances: 1
    └─ Confidence: High
- Alert: Create alert
- Governance:
  * Quarantine file
  * Notify file owner
  * Apply label: "Confidential - PII"

Result:
- All files scanned for SSN pattern (###-##-####)
- If found → Alert + Quarantine
```

### 5.5 Encryption and Rights Management

**Azure Rights Management (RMS) Integration:**

```
Encryption Scenarios:

Scenario 1: Auto-encrypt Confidential files

Policy:
- If file label = "Confidential"
- Apply encryption:
  * Viewers: Employees only
  * Rights: View, Edit (no print, no copy)
  * Expiration: 90 days

Result:
- File encrypted with Azure RMS
- Only authorized users can decrypt
- Cannot be opened outside organization
- Tracks all access attempts

Scenario 2: Protect files on download (Session Control)

Policy:
- Conditional Access App Control enabled
- On download of "Highly Confidential" file:
  * Apply encryption
  * Rights: Read-only (no edit, print, share)
  * Watermark: Username + timestamp

Result:
- User downloads file from SharePoint
- File auto-encrypted during download
- Watermarked with user identity
- File tracks back to original downloader
```

### 5.6 File Sharing Controls

**Prevent Unauthorized Sharing:**

```
Sharing Control Policies:

Policy 1: Block external sharing of Confidential files

Configuration:
- File policy: "Prevent external sharing"
- Filters:
  * Sensitivity label: Confidential
  * Sharing: External domain
- Action: Remove external collaborators

Workflow:
1. User shares "Report.docx" (label: Confidential) with partner@external.com
2. MDCA detects violation
3. Action: Removes partner@external.com from file permissions
4. User notified: "External sharing removed. File is Confidential."
5. Alert created for admin review

Policy 2: Restrict sharing links (anyone with link)

Configuration:
- File policy: "Remove public links"
- Filters:
  * File label: Internal OR Confidential
  * Sharing: Anyone with link (anonymous)
- Action: Remove sharing link

Workflow:
1. User creates "Anyone with link" for "Strategy.pptx" (Internal)
2. MDCA detects public link
3. Action: Removes anonymous link
4. Creates organization-only link instead
5. User notified: "Public link removed. Created internal link instead."
```

### 5.7 Monitoring and Reporting

**Information Protection Reports:**

```
MDCA → Information Protection Dashboard

Metrics:
├─ Files by sensitivity label:
│  ├─ Public: 5,000 (10%)
│  ├─ Internal: 30,000 (60%)
│  ├─ Confidential: 13,000 (26%)
│  └─ Highly Confidential: 2,000 (4%)
│
├─ Files shared externally:
│  ├─ Total: 1,500
│  ├─ Confidential shared externally: 50 ⚠️ (investigate!)
│  └─ Public shared externally: 1,450 ✅
│
├─ Encryption status:
│  ├─ Encrypted: 15,000 (30%)
│  ├─ Unencrypted: 35,000 (70%)
│  └─ Should be encrypted: 13,000 ⚠️ (Confidential files)
│
└─ Top policy violations:
   ├─ External sharing of Confidential: 50 incidents
   ├─ Public links created: 200 incidents
   └─ Unencrypted sensitive files: 13,000 files

Actions:
- Drill into violations
- View affected files
- Apply bulk remediation
- Export report for compliance
```

**🎯 Exam Tip:**
- **Information Protection** = MDCA + **Microsoft Purview** integration
- **Sensitivity labels**: Public, Internal, Confidential, Highly Confidential (hierarchy)
- **Auto-labeling**: Apply labels based on content inspection (SSN, credit cards, etc.)
- **Content inspection**: Built-in DLP, Regex, Fingerprinting, EDM, OCR
- **Encryption**: Azure RMS integration (encrypt files, control rights)
- **Sharing controls**: Block external sharing, Remove public links, Restrict by label
- **Governance actions**: Apply label, Quarantine file, Remove collaborators, Encrypt

---

## 6. Threat Detection Policies

### 6.1 Overview

**Threat Detection in MDCA:**

MDCA uses **machine learning** and **behavioral analytics** to detect threats:
- Compromised accounts
- Insider threats
- Data exfiltration
- Ransomware
- Malicious OAuth apps

**Detection Methods:**

```
1. Anomaly Detection (ML-based)
   ├─ Learns normal user behavior (baseline)
   ├─ Detects deviations from baseline
   └─ Auto-adapts to changes

2. Rule-Based Detection
   ├─ Pre-defined threat scenarios
   ├─ Configurable thresholds
   └─ Customizable actions

3. Threat Intelligence
   ├─ Microsoft Intelligent Security Graph
   ├─ Known malicious IPs
   ├─ Threat actor TTPs
   └─ Global threat data
```

### 6.2 Anomaly Detection Policies

**🆕 November 2025: Dynamic Threat Detection Model**

Microsoft is **migrating legacy policies** to a new **dynamic threat detection model**:
- More accurate (better signal-to-noise ratio)
- Research-driven (continuously updated)
- Enabled by default (no configuration needed)
- Faster adaptation to emerging threats

**Built-in Anomaly Detection Policies:**

```
1. Impossible Travel
   ├─ Detection: User activity from geographically distant locations in short time
   ├─ Example: Login from New York → Login from Beijing (1 hour later)
   ├─ Risk: Account compromise
   └─ Action: Alert, Require MFA, Suspend user

2. Activity from Infrequent Country
   ├─ Detection: User activity from country rarely used by organization
   ├─ Example: Login from North Korea (org has no employees there)
   ├─ Risk: Account compromise or VPN use
   └─ Action: Alert, Require re-authentication

3. Activity from Anonymous IP Address
   ├─ Detection: Activity from Tor, VPN, proxy services
   ├─ Example: User accesses files via Tor exit node
   ├─ Risk: Hiding activity, data exfiltration
   └─ Action: Alert, Block session

4. Suspicious Email Forwarding (🆕 Dynamic Model)
   ├─ Detection: User creates inbox rule to forward emails externally
   ├─ Example: Forward all emails to attacker@evil.com
   ├─ Risk: Data exfiltration, account compromise
   └─ Action: Alert, Delete inbox rule, Require password reset

5. Mass Download
   ├─ Detection: User downloads unusually large number of files
   ├─ Example: Download 500 files in 1 hour (normal: 10/day)
   ├─ Risk: Data theft, insider threat
   └─ Action: Alert, Suspend user, Review downloaded files

6. Ransomware Activity
   ├─ Detection: High rate of file modifications + file extensions changed
   ├─ Example: 100 files renamed to .encrypted in 5 minutes
   ├─ Risk: Ransomware infection
   └─ Action: Alert, Suspend user, Isolate device (MDE integration)

7. Unusual File Deletion
   ├─ Detection: User deletes large number of files
   ├─ Example: Delete 200 files in 10 minutes
   ├─ Risk: Sabotage, insider threat, ransomware
   └─ Action: Alert, Suspend user, Restore files

8. Unusual Administrative Activity
   ├─ Detection: Admin performs unusual high-risk actions
   ├─ Example: Admin downloads all mailbox data
   ├─ Risk: Insider threat, compromised admin account
   └─ Action: Alert, Require MFA, Notify CISO

9. Multiple Failed Login Attempts
   ├─ Detection: Repeated login failures from same user/IP
   ├─ Example: 50 failed logins in 1 hour
   ├─ Risk: Brute force attack, password spray
   └─ Action: Alert, Lockout account, Block IP

10. Unusual File Share
    ├─ Detection: User shares files with unusual recipients
    ├─ Example: Share 50 files with external domain (never done before)
    ├─ Risk: Data exfiltration, account compromise
    └─ Action: Alert, Remove sharing, Require justification
```

### 6.3 Impossible Travel Detection

**How Impossible Travel Works:**

```
Scenario: Account Compromise

Timeline:
09:00 AM - User signs in from New York, USA
          ├─ IP: 198.51.100.5
          ├─ Location: New York (via IP geolocation)
          └─ Activity: Normal email access

09:30 AM - User signs in from Shanghai, China
          ├─ IP: 203.0.113.50
          ├─ Location: Shanghai
          └─ Distance: 7,000 miles

Calculation:
- Time elapsed: 30 minutes
- Distance: 7,000 miles
- Required speed: 14,000 mph (impossible!)
- Flight time needed: ~14 hours

MDCA Detection:
⚠️ IMPOSSIBLE TRAVEL ALERT
├─ User: john@contoso.com
├─ Risk: High
├─ Confidence: 95%
├─ Locations: New York → Shanghai
├─ Time: 30 minutes (physically impossible)
└─ Likely cause: Account compromise

Automated Response:
1. Alert created (High severity)
2. User marked as "Compromised" in Azure AD Identity Protection
3. Require MFA on next sign-in
4. Optionally: Suspend user account
5. Notify security team
6. Create incident in Defender XDR

SOC Investigation:
1. Review user activities in Shanghai session
2. Check for data exfiltration (downloads, shares)
3. Review sign-in details (device, browser, app)
4. Correlate with other alerts (email forwarding rule?)
5. Take action:
   - Reset password
   - Revoke all sessions
   - Review recent activities for damage
   - Restore deleted emails/files if needed
```

**Tuning Impossible Travel:**

```
Adjustable Settings:

1. Sensitivity
   ├─ Low: Only detect extreme impossibilities (14,000 mph)
   ├─ Medium: Detect unlikely travel (200 mph)
   └─ High: Detect any unusual travel (50 mph)

2. Excluded IPs
   ├─ Corporate VPN exit IPs
   ├─ Cloud proxy IPs
   └─ Trusted partner networks

3. Excluded Users
   ├─ Service accounts
   ├─ Frequent travelers (executives)
   └─ IT admins (remote support)

Configuration:
MDCA → Settings → Cloud Discovery → Anomaly detection policy
→ Impossible travel → Adjust sensitivity slider
```

### 6.4 Activity from Suspicious IPs

**Suspicious IP Categories:**

```
1. Anonymous IP Addresses
   ├─ Tor exit nodes
   ├─ Commercial VPN services (NordVPN, ExpressVPN)
   ├─ Public proxies
   └─ Risk: Hiding identity, evading security

2. Botnet IPs
   ├─ Known command and control (C2) servers
   ├─ Malware distribution points
   └─ Risk: Malware infection, compromised device

3. Darknet IPs
   ├─ IPs associated with dark web marketplaces
   ├─ Hacking forums
   └─ Risk: Malicious intent

4. Malicious IPs
   ├─ Known attack sources (Microsoft Threat Intelligence)
   ├─ Recently involved in attacks
   └─ Risk: Active threat actor

Detection:
User activity from 45.140.xx.xx (Tor exit node)
└─ Alert: "Activity from anonymous IP"
   ├─ Risk: High
   ├─ IP: 45.140.xx.xx (Tor exit node in Russia)
   ├─ Activity: Downloaded 50 files from SharePoint
   └─ Action: Block session, Alert admin, Require MFA
```

### 6.5 Ransomware Detection

**How MDCA Detects Ransomware:**

```
Ransomware Behavioral Indicators:

1. High File Modification Rate
   ├─ Normal: User edits 5-10 files/day
   ├─ Ransomware: Encrypts 100+ files/minute
   └─ Threshold: >50 files modified in <10 minutes

2. File Extension Changes
   ├─ Normal: Files keep original extensions (.docx, .xlsx)
   ├─ Ransomware: Changes to .encrypted, .locked, .crypto
   └─ Pattern: Multiple files with same new extension

3. Ransom Note Files Created
   ├─ Files: README.txt, HOW_TO_DECRYPT.txt
   ├─ Content: "Your files have been encrypted. Pay Bitcoin..."
   └─ Pattern: Same file created in multiple folders

4. Unusual File Access Patterns
   ├─ Access many files quickly (scanning for encryption)
   ├─ Then modify all accessed files
   └─ No user interaction (automated)

Detection Example:

Timeline of Ransomware Attack:
14:00:00 - User clicks malicious email attachment
14:00:15 - Malware executes (not detected by AV yet - zero-day)
14:00:20 - Malware begins encrypting files on device
14:00:30 - Malware connects to cloud (OneDrive sync)
14:00:35 - MDCA detects:
           ├─ 150 files modified in 5 seconds
           ├─ All files renamed to .locked extension
           ├─ RANSOM_NOTE.txt created
14:00:36 - MDCA Alert: RANSOMWARE ACTIVITY DETECTED
14:00:37 - Automated Response:
           ├─ Suspend user account (stop sync)
           ├─ Revoke all sessions
           ├─ Create Defender XDR incident
           ├─ Isolate device (via MDE if integrated)
14:00:40 - Security team notified

Result:
- Attack detected in 35 seconds (from initial execution)
- OneDrive sync stopped (only 150 files affected)
- Remaining 10,000 files protected
- Device isolated, malware contained
- Files can be restored from OneDrive version history

Prevention Measures:
✅ File versioning enabled (OneDrive keeps 500 versions)
✅ Automated response (immediate user suspension)
✅ MDE integration (device isolation)
✅ Backup strategy (all files recoverable)
```

### 6.6 Insider Threat Detection

**Risky User Behavior:**

```
Insider Threat Indicators:

1. Data Hoarding
   ├─ User downloads large volumes of files
   ├─ Especially before known departure (resignation)
   └─ Example: Employee downloads 500 customer records 1 week before leaving

2. Unusual Access Patterns
   ├─ Access to resources not needed for job role
   ├─ After-hours access to sensitive data
   └─ Example: HR employee accessing financial reports at 2 AM

3. Sharing with Personal Accounts
   ├─ User shares files to personal Gmail/Dropbox
   ├─ Potential data theft
   └─ Example: Share company IP to personal cloud storage

4. Use of Personal Devices
   ├─ Access from unmanaged devices
   ├─ No corporate security controls
   └─ Example: Access via personal phone from home network

5. Bypassing Security Controls
   ├─ Use of anonymization tools (Tor, VPN)
   ├─ Disabling security features
   └─ Example: Disable Microsoft Defender on device, then download data

MDCA Detection:
- Combines multiple weak signals
- ML models detect anomalies
- Risk scoring (low/medium/high)

Example Alert: High-Risk User
User: john@contoso.com
Risk Score: 85/100 (High Risk)
Indicators:
├─ Resignation submitted (HR system integration)
├─ Downloaded 500 customer files (3x normal)
├─ Shared 50 files with personal Gmail
├─ Accessed financial data (not in job role)
├─ Activity from anonymous IP (Tor)
└─ Mass file deletion (covering tracks?)

Recommended Actions:
1. Suspend user account immediately
2. Review all downloaded files
3. Check for data exfiltration (email, USB, cloud)
4. Legal review (potential IP theft)
5. Escort user out of building (physical security)
6. Preserve evidence (eDiscovery hold)
```

### 6.7 Activity Policies vs Anomaly Detection

**Comparison:**

| Feature | Activity Policies | Anomaly Detection Policies |
|---------|------------------|---------------------------|
| **Detection Method** | Rule-based (defined criteria) | ML-based (behavioral) |
| **Configuration** | Manual (create rules) | Automatic (built-in) |
| **Baseline** | Not needed | Learns normal behavior |
| **Threshold** | Fixed (set by admin) | Dynamic (adapts) |
| **False Positives** | Higher (rigid rules) | Lower (context-aware) |
| **Use Case** | Specific known threats | Unknown/emerging threats |
| **Example** | "Alert if download >100 files" | "Alert if unusual download pattern" |

**When to Use Each:**

```
Use Activity Policies:
✅ Known threat scenarios (specific actions to monitor)
✅ Compliance requirements (audit specific activities)
✅ Custom use cases (org-specific risks)
✅ Testing (before enabling anomaly detection)

Use Anomaly Detection:
✅ Unknown threats (zero-day attacks)
✅ Evolving threats (attackers change tactics)
✅ User behavior analytics (insider threats)
✅ Reduce SOC workload (fewer false positives)

Best Practice: Use BOTH
- Anomaly Detection: Catch unknown threats (broad coverage)
- Activity Policies: Catch specific known threats (targeted)
```

**🎯 Exam Tip:**
- **Anomaly Detection** = **ML-based**, learns normal behavior, detects deviations
- **10 Built-in Anomaly Policies**: Impossible travel, Infrequent country, Anonymous IP, Mass download, Ransomware, etc.
- 🆕 **Dynamic Threat Detection Model** (Nov 2025): Research-driven, enabled by default, auto-adapts
- **Impossible Travel**: Detects physically impossible geographic movement (e.g., US → China in 30 min)
- **Ransomware Detection**: High file modification rate + extension changes + ransom note
- **Insider Threat**: Data hoarding, unusual access, sharing to personal accounts
- **Activity Policies** = Rule-based, **Anomaly Detection** = ML-based

---

## 7. OAuth App Governance

### 7.1 Overview

**What is OAuth App Governance?**

**OAuth App Governance** provides visibility and control over **third-party apps** that users connect to Microsoft 365, Google Workspace, and other platforms.

**The OAuth Problem:**

```
Scenario: User grants app access

User: "This looks like a useful app!"
├─ App: "FakeProductivityTool"
├─ Permission request:
│  "This app wants to:
│   - Read all your emails ✓
│   - Read all your files ✓
│   - Send email on your behalf ✓"
├─ User clicks: "Accept" (without reading!)
└─ Result: App now has full access to user's data

Risks:
❌ Overprivileged apps (more access than needed)
❌ Malicious apps (steal data, send spam)
❌ Abandoned apps (no longer maintained, security gaps)
❌ Unvetted apps (not approved by IT)
❌ Data exfiltration (apps extract data to attacker servers)

OAuth App Governance Solution:
✅ Discover all OAuth apps in use
✅ Assess app risk
✅ Identify overprivileged or malicious apps
✅ Disable or ban risky apps
✅ Monitor app activity
✅ Prevent future risky app consent
```

### 7.2 App Discovery

**Discovering OAuth Apps:**

```
MDCA automatically discovers OAuth apps connected to:
- Microsoft 365 (Azure AD registered apps)
- Google Workspace
- Salesforce
- Other connected cloud apps

Discovery Method:
1. MDCA reads OAuth app registrations via API
2. Identifies all apps users have consented to
3. Collects app metadata:
   - App name and publisher
   - Permissions requested
   - Users who consented
   - Last activity
   - Community usage (how many orgs use this app)

🆕 October 2025: OAuthAppInfo Table in Advanced Hunting
- New table for querying OAuth apps
- Enables proactive threat hunting
- Cross-reference app activity with user behavior
```

**OAuth App Dashboard:**

```
MDCA → App Governance → OAuth apps

Dashboard View:
┌────────────────────────────────────────────────────┐
│ Total Apps: 234                                    │
│ High Risk: 12 ⚠️                                    │
│ Medium Risk: 85                                    │
│ Low Risk: 137                                      │
│ Banned Apps: 5                                     │
└────────────────────────────────────────────────────┘

App List:
┌────────────────────────────────────────────────────┐
│ App Name       | Risk | Users | Permissions       │
├────────────────────────────────────────────────────┤
│ Salesforce     | Low  | 450   | Contacts, Email   │
│ Zoom           | Low  | 320   | Calendar          │
│ FakeMailer     | High | 5     | All Mailbox ⚠️     │
│ ProductivityX  | Med  | 80    | Files, Sites      │
│ Unknown App    | High | 2     | All Data ⚠️        │
└────────────────────────────────────────────────────┘

Filters:
- By risk level
- By permission level (High privilege, Medium, Low)
- By publisher (Verified, Unverified)
- By usage (Number of users)
- By certification (Microsoft 365 Certified, Not certified)
```

### 7.3 App Risk Assessment

**Risk Scoring Criteria:**

```
App Risk Factors:

1. Permissions Requested (50% weight)
   ├─ High Risk:
   │  ├─ Mail.ReadWrite (read/send all mail)
   │  ├─ Files.ReadWrite.All (access all files)
   │  ├─ Directory.ReadWrite.All (modify users/groups)
   │  ├─ MailboxSettings.ReadWrite (create inbox rules)
   │  └─ Mail.Send (send email on behalf of user)
   │
   ├─ Medium Risk:
   │  ├─ Mail.Read (read emails)
   │  ├─ Files.Read.All (read files)
   │  ├─ Calendars.ReadWrite (modify calendar)
   │  └─ Contacts.ReadWrite (modify contacts)
   │
   └─ Low Risk:
      ├─ User.Read (basic profile)
      ├─ Calendars.Read (view calendar)
      └─ openid, email (authentication only)

2. Publisher Reputation (20% weight)
   ├─ Verified publisher (Microsoft Partner): ✅ Low risk
   ├─ Known publisher (popular app): ⚠️ Medium risk
   ├─ Unknown/new publisher: ❌ High risk
   └─ No publisher info: ❌ Highest risk

3. Community Usage (15% weight)
   ├─ Used by 1,000+ orgs: ✅ Low risk (crowdsourced trust)
   ├─ Used by 10-100 orgs: ⚠️ Medium risk
   ├─ Used by <10 orgs: ❌ High risk
   └─ Only used in your org: ❌ Highest risk (unique threat)

4. App Activity (10% weight)
   ├─ Recent activity: ✅ Lower risk (active maintenance)
   ├─ No activity in 6+ months: ⚠️ Medium risk (abandoned?)
   └─ No activity ever: ❌ High risk (malicious registration?)

5. Certification (5% weight)
   ├─ Microsoft 365 Certified: ✅ Lowest risk
   ├─ Not certified: ⚠️ Higher risk
   └─ Failed certification: ❌ Highest risk

Risk Score Output:
- 0-30: High Risk (investigate immediately)
- 31-70: Medium Risk (review periodically)
- 71-100: Low Risk (acceptable)

Example: "FakeMailer" App
├─ Permissions: Mail.ReadWrite, MailboxSettings.ReadWrite (HIGH RISK)
├─ Publisher: Unknown (HIGH RISK)
├─ Community: Used by 2 orgs only (HIGH RISK)
├─ Activity: Created 2 days ago, high activity (SUSPICIOUS)
├─ Certification: Not certified (HIGH RISK)
└─ Risk Score: 15/100 → HIGH RISK ⚠️ INVESTIGATE
```

### 7.4 App Governance Actions

**Available Actions:**

```
1. Investigate (Low-Risk Apps)
   - Review app details
   - View permissions
   - Check user list
   - Monitor activity
   - No action needed

2. Notify Users (Medium-Risk Apps)
   - Send email to users who consented
   - Warn about risks
   - Recommend revoking access
   - User decision (optional: revoke)

3. Disable App (High-Risk Apps)
   - Disable app for organization
   - Existing consents remain but app can't run
   - Users can't consent to app anymore
   - Reversible (can re-enable)

4. Ban App (Critical Risk)
   - Ban app organization-wide
   - Revoke all existing consents
   - Prevent future consents
   - Not reversible (requires unban)

5. Mark as Sanctioned (Approved Apps)
   - Approve app for organization use
   - Encourage users to use this app
   - May integrate with Conditional Access
```

**Example Workflow:**

```
Scenario: Malicious OAuth App Detected

Discovery:
- App: "FreeMailTool"
- Risk: High (95/100)
- Permissions: Mail.ReadWrite, Mail.Send
- Users: 3 users consented
- Activity: Sending spam emails!

Investigation:
1. MDCA → App Governance → OAuth apps → "FreeMailTool"
2. Click app → View details:
   - Publisher: Unknown (domain registered 1 week ago)
   - Community: Only in your org (red flag!)
   - Permissions: Full mailbox access
   - Activity log:
     ├─ Sent 500 emails in last hour (spam!)
     ├─ Read all emails for 3 users
     └─ Created inbox forwarding rules ⚠️

Remediation:
1. Ban app immediately
   - MDCA → OAuth apps → "FreeMailTool" → Ban
   - Result: All consents revoked, app disabled

2. Investigate affected users
   - Check: Emails sent by app
   - Check: Inbox rules created
   - Check: Data exfiltrated

3. Clean up damage
   - Delete spam emails sent by app
   - Remove inbox forwarding rules
   - Reset user passwords (precaution)
   - Revoke all user sessions

4. Post-incident
   - Block domain at firewall (prevent phishing site)
   - User education (how to spot malicious apps)
   - Implement app consent policy (require admin approval)
```

### 7.5 App Permissions Deep Dive

**Common Dangerous Permissions:**

```
⚠️ RED FLAGS (High Risk Permissions):

1. Mail.ReadWrite
   - Read and modify all mailboxes
   - Can delete emails, create rules
   - Risk: Data exfiltration, cover tracks

2. Mail.Send
   - Send email on behalf of users
   - No user interaction needed
   - Risk: Spam, phishing, BEC attacks

3. MailboxSettings.ReadWrite
   - Create inbox rules
   - Set up email forwarding
   - Risk: Data exfiltration (forward to attacker)

4. Files.ReadWrite.All
   - Access ALL files in SharePoint/OneDrive
   - Can modify, delete files
   - Risk: Ransomware, data theft

5. Directory.ReadWrite.All
   - Read/write all directory objects
   - Can create users, modify groups, elevate privileges
   - Risk: Privilege escalation, persistent access

6. User.ReadWrite.All
   - Modify all users
   - Can reset passwords, disable MFA
   - Risk: Account takeover

7. Application.ReadWrite.All
   - Create/modify app registrations
   - Can create new malicious apps
   - Risk: Persistence, backdoor

Principle of Least Privilege:
- Apps should only request permissions they NEED
- Example: Calendar app should NOT need Mail.ReadWrite
- If app requests excessive permissions → DENY
```

### 7.6 Preventing Risky App Consent

**App Consent Policies (Azure AD):**

```
Configuration: Azure AD → Enterprise Applications → Consent and permissions

Policy Options:

1. Do not allow user consent (Most Secure)
   - Users CANNOT consent to any apps
   - All apps require admin approval
   - Pro: Maximum control
   - Con: Admin bottleneck

2. Allow user consent for apps from verified publishers
   - Users can consent to verified publishers only
   - Unverified apps require admin approval
   - Pro: Balance security and usability
   - Con: Trusted publishers can still be risky (recommended)

3. Allow user consent for low-risk permissions
   - Users can consent if app only requests low-risk perms
   - High-risk permissions require admin
   - Pro: Least disruptive
   - Con: Attackers can still abuse low-risk perms

4. Allow user consent for all apps (Least Secure - NOT RECOMMENDED)
   - Users can consent to any app
   - No restrictions
   - Pro: No admin overhead
   - Con: High risk of malicious apps

Recommended: Option 2 (Verified publishers only)
```

**Admin Consent Workflow:**

```
If user consent blocked, users see:

┌────────────────────────────────────────┐
│  🔒 Administrator Approval Required    │
│                                        │
│  This app requires permissions that    │
│  must be approved by an administrator. │
│                                        │
│  [Request Admin Approval]              │
└────────────────────────────────────────┘

Workflow:
1. User clicks "Request Admin Approval"
2. Request sent to IT admin
3. Admin reviews:
   - App name and publisher
   - Permissions requested
   - Business justification
4. Admin decision:
   - Approve: User can now use app
   - Deny: User notified, app blocked

Admin Considerations:
✅ Is publisher verified?
✅ Are permissions reasonable for app's function?
✅ Is there a legitimate business need?
✅ Is there an alternative approved app?
❌ Deny if excessive permissions or unknown publisher
```

### 7.7 OAuth App Activity Monitoring

**Monitoring App Behavior:**

```
MDCA → Activity Log → Filter by OAuth app

Suspicious Activities:

1. High-Volume Email Send
   - App sends 1,000+ emails suddenly
   - Potential spam or phishing campaign

2. Mass File Access
   - App accesses 500 files in 1 hour
   - Potential data exfiltration

3. Unusual API Calls
   - App makes 10,000 API calls in 10 minutes
   - Potential scraping or DoS

4. Permission Escalation
   - App requests new permissions after initial consent
   - Potential privilege escalation attack

5. After-Hours Activity
   - App active at 3 AM (user normally works 9-5)
   - Potential compromised credentials

Alert Example:
┌────────────────────────────────────────┐
│  ⚠️ Suspicious OAuth App Activity      │
│                                        │
│  App: ProductivityBot                 │
│  Activity: Sent 500 emails in 1 hour  │
│  Users: All employees                 │
│  Time: 2:00 AM                        │
│  Risk: HIGH                           │
│                                        │
│  Recommended Action: Disable app      │
└────────────────────────────────────────┘
```

**🎯 Exam Tip:**
- **OAuth App Governance** = Visibility and control over **third-party apps** connected to cloud services
- **Discovery**: Automatic (via API), no user action needed
- **Risk Scoring**: Based on permissions, publisher, community usage, activity, certification
- **Governance Actions**: Investigate, Notify, Disable, Ban, Sanction
- **Dangerous Permissions**: Mail.ReadWrite, Mail.Send, Files.ReadWrite.All, Directory.ReadWrite.All
- **App Consent Policy** (Azure AD): Block user consent, require admin approval
- 🆕 **OAuthAppInfo table** (Oct 2025): Advanced Hunting for OAuth apps
- **Best Practice**: Only allow verified publishers, require admin approval for high-risk permissions

---

*[Due to length, I need to continue with sections 8-15 in next response. We're at ~50% of Module 4 Part 2!]*

Tôi đã hoàn thành **7/15 sections của Part 2** (sections 5-7). Do length limit, tôi cần tiếp tục phần còn lại riêng.

**Đã hoàn thành:**
- Sections 1-4 (Part 1)
- Sections 5-7 (Part 2): Information Protection, Threat Detection, OAuth Governance

**Còn lại (8 sections):**
- Sections 8-15: Policies, Investigation, Advanced Hunting, Integration, Best Practices, Exam Prep

Làm tiếp phần cuối (sections 8-15) không? 🚀
