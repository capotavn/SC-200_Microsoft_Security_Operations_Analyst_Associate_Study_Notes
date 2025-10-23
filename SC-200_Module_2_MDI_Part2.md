# SC-200 Study Notes - Module 2: Microsoft Defender for Identity (MDI)
## 📘 Part 2: Advanced Configuration and Exam Preparation

**Continuation from Part 1** - Sections 8-15
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest MDI Updates

---

## 8. Honeytoken Accounts (Deception)

### 8.1 Overview of Honeytokens

**What are Honeytokens?**

Honeytokens are **decoy accounts** specifically designed to:
- Lure attackers
- Detect unauthorized access
- Provide early warning of compromise
- Track attacker behavior

**How Honeytokens Work:**

```
Deception Strategy:

1. Create Fake Accounts
   ├─ Look valuable (e.g., "admin_backup", "svc_prod")
   ├─ Have no legitimate use
   └─ Tagged as honeytoken in MDI

2. Distribute "Credentials"
   ├─ Save in credential managers
   ├─ Place in scripts (commented out)
   ├─ Store in "secure" locations
   └─ Make them discoverable by attackers

3. Monitor for Any Usage
   ├─ ANY authentication = Immediate alert
   ├─ 100% accuracy (no false positives)
   └─ Early warning of breach

4. Alert Triggers Instantly
   ├─ High severity alert
   ├─ SOC investigates immediately
   └─ Attacker detected early in kill chain
```

**Why Honeytokens Are Powerful:**

✅ **Zero False Positives**
- These accounts should NEVER be used
- Any activity = Confirmed compromise

✅ **Early Detection**
- Attackers often discover honeytokens early
- Detection before major damage

✅ **Attack Intelligence**
- See what attackers target
- Understand their techniques
- Track their movements

✅ **Low Cost**
- No infrastructure needed
- Just fake accounts in AD
- Managed by MDI

### 8.2 Types of Honeytokens

**1. Honeytoken Users**

Fake user accounts that look valuable to attackers:

```
Examples:
- admin_backup
- svc_prod_sql
- test_admin
- vendor_support
- emergency_access
```

**Characteristics:**
- Disabled or never-logged-in status
- Realistic names
- Member of interesting groups (but not actually privileged)
- Credentials "accidentally" exposed

**2. Honeytoken Computers**

Fake computer accounts:

```
Examples:
- BACKUP-SERVER
- PROD-DC-DR
- VAULT-01
- ADMIN-WORKSTATION
```

**Characteristics:**
- Non-existent machines
- Appear in AD but don't exist
- Realistic naming convention

### 8.3 Creating Honeytokens

#### **Step 1: Create Honeytoken Account**

**PowerShell Method:**

```powershell
# Create honeytoken user account
New-ADUser -Name "admin_backup" `
  -SamAccountName "admin_backup" `
  -UserPrincipalName "admin_backup@contoso.com" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd!ComplexEnough123" -AsPlainText -Force) `
  -Enabled $true `
  -Description "Backup administrator account (DO NOT USE - Honeytoken)" `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true

# IMPORTANT: Don't give it any real permissions!
# Make it look valuable but not actually privileged

# Optionally: Make it look like it was used before
Set-ADUser -Identity admin_backup -Replace @{
  lastLogon = (Get-Date).AddDays(-180).ToFileTime()
  lastLogonTimestamp = (Get-Date).AddDays(-180).ToFileTime()
}
```

**GUI Method (AD Users and Computers):**

```
1. Open Active Directory Users and Computers
2. Navigate to appropriate OU (maybe "Service Accounts" to blend in)
3. Right-click → New → User
4. Name: admin_backup
5. Configure:
   - User cannot change password: ✓
   - Password never expires: ✓
   - Account is enabled: ✓
6. Set description: "Backup administrator account"
7. Create
```

#### **Step 2: Tag as Honeytoken in MDI**

**Critical Step - This is what makes it work:**

```
1. Microsoft Defender Portal → Identities
2. Search for "admin_backup"
3. Open entity profile
4. Click "..." → Manage tags
5. Select "Honeytoken account"
6. Save

Now MDI knows:
- This account should NEVER authenticate
- Any activity = High severity alert
- No false positive possible
```

**Verify Tagging:**

```
1. Entity profile shows "Honeytoken" badge
2. Settings → Identities → Entity tags
3. See list of all honeytoken accounts
```

#### **Step 3: "Expose" Credentials**

**Make credentials discoverable by attackers:**

**Method 1: Saved Credentials on Workstations**

```powershell
# Save credential in Windows Credential Manager
# (Run on select workstations, maybe IT admin machines)
cmdkey /add:SERVER01 /user:admin_backup /pass:P@ssw0rd!ComplexEnough123

# Attacker tools like Mimikatz will discover this
```

**Method 2: In Scripts (Commented Out)**

```powershell
# Place in common script locations
# C:\Scripts\maintenance.ps1

<#
Production database connection:
Server: SQLPROD01
Username: svc_prod_sql
Password: ProductionP@ss2024!
#>

# Connect-Database -Server SQLPROD01
# ... actual script ...
```

**Method 3: In Group Policy Preferences (Historical)**

```
Old vulnerability: Passwords in GPP were encrypted but crackable
Modern honeytoken: Place fake credentials in GPP comments
Attackers still check these locations
```

**Method 4: In Password Managers (Weak)**

```
Store honeytoken credentials in poorly secured password managers:
- Shared Excel spreadsheets
- OneNote notebooks
- Text files in network shares
```

**⚠️ Warning:** Don't give honeytoken accounts real access! They're bait only.

### 8.4 Honeytoken Alert Behavior

**When Honeytoken is Used:**

```
Alert: Honeytoken account authentication detected

Severity: High (always)

Details:
- Account: admin_backup (Honeytoken)
- Activity: Kerberos authentication
- Source: 192.168.1.150 (WKS-001)
- Target: DC01.contoso.com
- Time: 2025-10-22 14:30:00

Explanation:
A honeytoken account attempted to authenticate. This account
should NEVER be used for legitimate purposes. This indicates
an attacker has discovered and attempted to use the credential.

Recommended Actions:
1. IMMEDIATE: Investigate source machine (WKS-001)
2. Identify all activity from source IP
3. Isolate source machine
4. Hunt for other compromised credentials
5. Reset honeytoken password (but keep it as honeytoken)
6. Investigate how attacker discovered credential
7. Review all authentication from source in last 30 days
```

**What MDI Detects:**

✅ **Any authentication attempt:**
- Kerberos pre-authentication
- NTLM authentication
- LDAP bind
- SMB connection using honeytoken
- RDP attempt
- Service ticket request

✅ **Any enumeration:**
- LDAP queries targeting honeytoken
- Kerberoasting against honeytoken
- AS-REP roasting attempts

✅ **Any modification:**
- Password changes
- Group membership changes
- Account property modifications

### 8.5 Honeytoken Best Practices

**1. Use Realistic Names**

❌ **Bad Examples:**
```
honeypot_user
fake_admin
do_not_use_account
decoy123
```
These are obvious to sophisticated attackers.

✅ **Good Examples:**
```
admin_backup
svc_prod_db
test_admin
vendor_access
john.smith_admin (looks like a real person's admin account)
```

**2. Strategic Placement**

**Where to "Expose" Credentials:**

```
High-Value Targets (Attackers Look Here First):
├─ IT Administrator workstations
├─ Jump servers
├─ System admin home directories
├─ Script repositories
└─ Shared "secure" folders

Medium-Value Targets:
├─ Developer workstations
├─ File servers
└─ Management workstations

Low-Value Targets (Less Effective):
├─ Standard user workstations
└─ Rarely accessed servers
```

**3. Create a Web of Honeytokens**

```
Honeytoken Strategy:

Tier 0 (Critical - Domain Level):
- Honeytoken domain admin account
- Honeytoken enterprise admin account

Tier 1 (High - Server Level):
- Honeytoken SQL service account
- Honeytoken Exchange service account
- Honeytoken backup account

Tier 2 (Medium - Workstation Level):
- Honeytoken local admin accounts
- Honeytoken help desk accounts

Goal: At least 5-10 honeytokens across tiers
```

**4. Make Them Look Legitimate**

```powershell
# Set realistic attributes
Set-ADUser -Identity admin_backup -Replace @{
  title = "Systems Administrator"
  department = "IT Operations"
  telephoneNumber = "+1-555-0123"
  office = "Building A, Room 205"
  manager = "CN=IT Manager,OU=Managers,DC=contoso,DC=com"
}

# Set last logon timestamp (make it look used)
# But not too recently (would be suspicious if recently used but you don't know password)
Set-ADUser -Identity admin_backup -Replace @{
  lastLogonTimestamp = (Get-Date).AddDays(-90).ToFileTime()
}
```

**5. Don't Give Real Permissions**

```
Common Mistake:
- Adding honeytoken to Domain Admins
- To make it "look" valuable
- But this gives it REAL power!

Problem:
- If attacker uses it, they actually get admin access
- Defeats the purpose (detection, not actual access)

Solution:
- NO group memberships except Domain Users
- Maybe "Backup Operators" (limited real power)
- Rely on NAME to make it look valuable
```

**6. Monitor and Maintain**

```
Regular Tasks:
1. Weekly: Verify honeytoken tags are still applied
2. Monthly: Review if any honeytokens were accessed
3. Quarterly: 
   - Rotate honeytoken passwords (but keep discoverable)
   - Add new honeytokens
   - Remove old/discovered ones
4. Annually:
   - Review honeytoken strategy
   - Ensure they still look realistic
   - Update placement based on threats
```

### 8.6 Honeytoken Scenarios

#### **Scenario 1: Phishing to Honeytoken Use**

```
Timeline of Attack (Detected Early):

Day 1, 09:00: Phishing email sent to StandardUser
Day 1, 09:15: StandardUser clicks malicious link
Day 1, 09:20: Attacker gains access to WKS-001
Day 1, 09:30: Attacker runs Mimikatz on WKS-001
Day 1, 09:31: Discovers honeytoken "admin_backup" in credential manager
Day 1, 09:32: Attempts authentication with admin_backup
Day 1, 09:32: 🚨 MDI ALERT - Honeytoken usage detected!
Day 1, 09:35: SOC responds, isolates WKS-001
Day 1, 09:40: Investigation begins
Day 1, 10:00: StandardUser password reset, machine reimaged

Result: Attack detected and stopped within 1 hour!
```

#### **Scenario 2: Insider Threat**

```
Timeline:

Month 1: Disgruntled employee (ITAdmin) plans data theft
Month 2: ITAdmin searches for high-privilege accounts
Month 2: Discovers "svc_prod_backup" in script comments
Month 2: Tests credential authentication
Month 2: 🚨 MDI ALERT - Honeytoken usage!
Month 2: HR investigation launched
Month 3: Employee terminated with evidence

Result: Insider threat detected before data loss!
```

### 8.7 Combining with Other Deception

**Honeytokens are part of broader deception strategy:**

```
Deception in Depth:

1. Honeytokens (MDI)
   └─ Fake accounts in AD

2. Decoy Files (MDE/AIP)
   └─ Fake sensitive documents with DLP tracking

3. Decoy Servers (Network)
   └─ Fake servers that log all access

4. Decoy Shares (File Server)
   └─ Fake network shares with fake data

5. Decoy DNS Records
   └─ Fake internal DNS entries (e.g., vault.contoso.com → honeypot)

6. Lure Documents (MDI/MDE)
   └─ Documents with honeytoken credentials embedded
```

**Example Combined Strategy:**

```
1. Create honeytoken: "vault_admin"
2. Create Word document: "Vault_Access_Credentials.docx"
3. Document contains:
   - Server: vault.contoso.com
   - Username: vault_admin
   - Password: VaultP@ss2024!
4. Place document in:
   - IT admin's desktop
   - Shared "Secure Files" folder
   - Script repository
5. Configure DLP to alert on document access
6. Configure MDI to alert on vault_admin usage
7. Configure network IDS to alert on access to vault.contoso.com

Result: Multi-layer detection of attacker!
```

### 8.8 Exam Tips for Honeytokens

**What to Know for SC-200:**

✅ **Core Concepts:**
- Honeytoken = Fake account that should never be used
- Tagged in MDI via entity tags
- Any usage = High severity alert
- Zero false positives

✅ **Configuration:**
- Created in AD like normal account
- Tagged as "Honeytoken account" in MDI portal
- Credentials "exposed" in discoverable locations

✅ **Detection:**
- MDI detects ANY activity involving honeytoken
- Immediate high-severity alert
- Part of reconnaissance/credential theft detection

✅ **Common Exam Scenarios:**

**Question Type 1:**
```
Q: You need to configure several accounts for attackers to exploit.
   What should you do?

A: From Entity tags, add the accounts as Honeytoken accounts
```

**Question Type 2:**
```
Q: A honeytoken account authentication was detected. What does this indicate?

A: An attacker has discovered and attempted to use a decoy credential.
   This confirms unauthorized access and credential theft.
```

**Question Type 3:**
```
Q: You want to detect attackers early in the kill chain. What should you deploy?

A: Honeytoken accounts with credentials exposed in IT admin workstations.
   Any usage will trigger immediate alerts.
```

**🎯 Exam Tip:** Honeytokens are a detection technique, not a security control. They don't PREVENT attacks, they DETECT attackers early. This is a key distinction for exam questions.

---

## 9. Investigate and Remediate Identity Threats

### 9.1 Investigation Workflow

**Exam Objective:** *Investigate and remediate security alerts from Microsoft Defender for Identity*

**Standard Investigation Process:**

```
1. Alert Review (1-5 minutes)
   ├─ Read alert description
   ├─ Check severity
   ├─ Review impacted entities
   └─ Determine if true positive or false positive

2. Initial Triage (5-10 minutes)
   ├─ Is this a known false positive?
   ├─ Is the behavior authorized?
   ├─ Is this part of a larger attack?
   └─ Assign priority and owner

3. Deep Investigation (15-60 minutes)
   ├─ Review entity timelines
   ├─ Analyze related alerts
   ├─ Check lateral movement paths
   ├─ Hunt for related activity
   └─ Determine scope

4. Containment (5-30 minutes)
   ├─ Disable compromised accounts
   ├─ Reset passwords
   ├─ Isolate affected systems
   └─ Block attacker access

5. Remediation (30 minutes - days)
   ├─ Remove persistence
   ├─ Fix vulnerabilities
   ├─ Restore from clean backups
   └─ Strengthen security

6. Recovery (Variable)
   ├─ Re-enable accounts (new passwords)
   ├─ Restore services
   └─ Resume normal operations

7. Post-Incident (1-4 hours)
   ├─ Document lessons learned
   ├─ Update runbooks
   ├─ Improve detection
   └─ Train team
```

### 9.2 Investigating Common Alerts

#### **Alert 1: Suspected Brute Force Attack**

**Alert Details:**

```
Alert: Suspected brute force attack (Kerberos, NTLM)

Severity: Medium

Description:
Multiple failed authentication attempts from single source
to multiple accounts or single account.

Evidence:
- Source: 192.168.1.150
- Failed attempts: 45 in 10 minutes
- Targeted accounts: 15 different users
- Protocol: Kerberos pre-authentication
```

**Investigation Steps:**

```powershell
# Step 1: Identify source machine
$sourceIP = "192.168.1.150"
Get-ADComputer -Filter {IPv4Address -eq $sourceIP} -Properties *

# Or find by hostname if you know it
Resolve-DnsName -Name $sourceIP

# Step 2: Check if any attempts succeeded
# In MDI portal:
# - Timeline for source IP
# - Look for successful logon after failed attempts

# Step 3: Review targeted accounts
# Are they all high-privilege?
# Are they following alphabetical pattern? (password spray)

# Step 4: Check for other activity from source
# Advanced Hunting query:
```

```kql
// Find all authentication from source in last 24 hours
IdentityLogonEvents
| where Timestamp > ago(1d)
| where IPAddress == "192.168.1.150"
| project Timestamp, AccountName, LogonType, ActionType, Application
| order by Timestamp desc
```

**Containment Actions:**

```
If Compromised:
1. Isolate source machine (if endpoint)
   OR
   Block source IP at firewall (if external/unknown)

2. Force password reset for all targeted accounts
   (Attacker may have succeeded on some)

3. Review for follow-on activity:
   - Lateral movement
   - Data access
   - Privilege escalation

4. Enable MFA for targeted accounts
```

**Remediation:**

```powershell
# Block the account if it's the attacker's account
Disable-ADAccount -Identity "AttackerAccount"

# Enable account lockout policy (if not already)
# Default Domain Policy → Account Lockout Policy
# - Account lockout threshold: 5 invalid attempts
# - Account lockout duration: 30 minutes
# - Reset counter after: 30 minutes

# For high-privilege accounts:
# Add to Protected Users group (no NTLM, no delegation, etc.)
Add-ADGroupMember -Identity "Protected Users" -Members "DomainAdmin1"
```

#### **Alert 2: Suspected DCSync Attack**

**Alert Details:**

```
Alert: Suspected DCSync attack (replication of directory services)

Severity: Critical

Description:
Non-DC account requested directory replication,
extracting password hashes for domain.

Evidence:
- Account: CONTOSO\compromised-admin
- Target DC: DC01.contoso.com
- Objects replicated: krbtgt, Administrator, 500+ user accounts
- Time: 2025-10-22 18:00:00
- Source IP: 192.168.1.200
```

**Investigation Steps:**

```
Step 1: Verify it's malicious (not legitimate admin tool)

Questions:
- Is this account authorized to replicate AD?
  (Only DCs should have this permission)
- Is there a scheduled backup or sync running?
- Is this a known admin tool or attacker tool?

Check:
- Source IP/machine
- User account context
- Time of day (off-hours suspicious)
- Replication partners (should only be DCs)

Step 2: Determine scope

MDI Alert shows:
- Which objects were replicated
- If krbtgt was replicated (CRITICAL!)
- Password hashes extracted

Step 3: Check for follow-on attacks

Hunt for:
- Golden Ticket usage (if krbtgt compromised)
- Pass-the-hash attacks
- Lateral movement using extracted credentials
- Data exfiltration
```

**Advanced Hunting:**

```kql
// Find all DCSync attempts
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Service Replication"
| where InitiatingAccountName !endswith "$" // Exclude computer accounts (DCs)
| project Timestamp, InitiatingAccountName, DestinationDeviceName, AdditionalFields
| order by Timestamp desc

// Find Golden Ticket usage after DCSync
AlertEvidence
| where Timestamp > ago(7d)
| where RemediationStatus != "Prevented"
| where EntityType == "User"
| where AlertId has "GoldenTicket"
| project Timestamp, AccountName, DeviceName, AlertTitle
```

**Containment Actions (CRITICAL!):**

```
IMMEDIATE Actions (Within 15 minutes):

1. Disable compromised admin account
   Disable-ADAccount -Identity "compromised-admin"

2. Reset krbtgt password TWICE (if compromised)
   ⚠️ This is the nuclear option - impacts entire domain!
   
   # First reset
   .\New-KrbtgtKeys.ps1 -SkipRODC
   
   # Wait 24 hours for replication
   
   # Second reset (invalidates any tickets from interim)
   .\New-KrbtgtKeys.ps1 -SkipRODC

3. Force password reset for ALL admin accounts
   
4. Investigate how attacker gained replication permissions
   
5. Hunt for Golden Tickets (if krbtgt compromised)
```

**Remediation:**

```powershell
# Remove replication permissions from all non-DC accounts
# Check who has DS-Replication-Get-Changes permissions

$rootDSE = Get-ADRootDSE
$defaultNamingContext = $rootDSE.defaultNamingContext

# Get ACL for domain root
$acl = Get-Acl "AD:\$defaultNamingContext"

# Find accounts with replication rights
$acl.Access | Where-Object {
    $_.ActiveDirectoryRights -like "*ExtendedRight*" -and
    $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes
} | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType

# Remove unauthorized accounts
# (Manual via AD Users and Computers → Delegate Control)
# Or PowerShell (advanced)
```

**Post-Incident:**

```
1. Review ALL admin accounts and their permissions
2. Implement Privileged Access Management (PAM)
3. Enable 4662 auditing if not already (CRITICAL for DCSync detection!)
4. Deploy MDI sensors on all DCs if not already
5. Implement JIT (Just-In-Time) admin access
6. Use Azure AD PIM for cloud admin access
```

#### **Alert 3: Suspected Golden Ticket Usage**

**Alert Details:**

```
Alert: Suspected Golden Ticket usage (encryption downgrade)

Severity: Critical

Description:
Kerberos TGT with anomalous properties detected,
indicating forged ticket created with stolen krbtgt hash.

Evidence:
- Account in ticket: Administrator
- Encryption: RC4 (account configured for AES256)
- Lifetime: 10 years (policy is 10 hours)
- Issuer: Not a legitimate DC
- Source: 192.168.1.250
- First seen: 2025-10-22 19:00:00
```

**Investigation Steps:**

```
Step 1: Confirm Golden Ticket

Golden Ticket Indicators:
✓ Encryption downgrade (AES → RC4)
✓ Excessive lifetime (10 years vs 10 hours)
✓ Ticket for deleted/non-existent user
✓ Forged PAC data
✓ Ticket not issued by real DC

Step 2: Determine when krbtgt was compromised

Hunt backwards:
- When was DCSync attack? (preceded Golden Ticket)
- Who had admin access at that time?
- What systems were compromised?

Step 3: Identify all affected systems

Questions:
- Where was Golden Ticket used?
- What resources were accessed?
- Were backdoors installed?
- Was data exfiltrated?

Advanced Hunting:
```

```kql
// Find all activity from source IP
let suspiciousIP = "192.168.1.250";
IdentityLogonEvents
| where Timestamp > ago(30d)
| where IPAddress == suspiciousIP
| project Timestamp, AccountName, DeviceName, LogonType, Application
| order by Timestamp desc

// Find other potential Golden Tickets
AlertInfo
| where Timestamp > ago(30d)
| where Title has "Golden Ticket"
| join kind=inner (
    AlertEvidence
    | where EntityType == "User"
) on AlertId
| project Timestamp, Title, AccountName, DeviceName, Severity
```

**Containment Actions (CRITICAL!):**

```
URGENT - Full Domain Compromise Response:

1. Assume COMPLETE domain compromise
   
2. Activate Incident Response Plan
   
3. Reset krbtgt password TWICE
   # Invalidates all TGTs (including forged ones)
   .\New-KrbtgtKeys.ps1 -SkipRODC
   # Wait 24 hours
   .\New-KrbtgtKeys.ps1 -SkipRODC

4. Force password reset for ALL privileged accounts
   
5. Review ALL admin actions in timeframe
   
6. Hunt for:
   - Backdoor accounts created
   - Persistence mechanisms (scheduled tasks, services, WMI)
   - Data exfiltration
   - Lateral movement
   
7. Consider domain rebuild if heavily compromised
```

**Remediation (Long-term):**

```
1. Post-incident investigation (full forensics)

2. Harden environment:
   - Implement Admin Tiering
   - Deploy PAWs (Privileged Access Workstations)
   - Enable Credential Guard
   - Add admins to Protected Users group
   - Implement JIT admin access
   
3. Detection improvements:
   - Enable ALL Windows event auditing
   - Deploy MDI on all DCs
   - Enable 4662 auditing (DCSync detection)
   - Create custom detection rules
   - Implement honeytokens
   
4. Prevent recurrence:
   - Security awareness training
   - Phishing simulations
   - Regular AD security reviews
   - Penetration testing
   - Red team exercises
```

### 9.3 Entity Investigation

**Entity Profile Page:**

Every user and computer has a profile page in MDI:

```
Entity Profile Components:

1. Overview
   ├─ Account details (SID, UPN, groups)
   ├─ Last seen activity
   ├─ Risk level
   └─ Tags (Sensitive, Honeytoken, etc.)

2. Timeline
   ├─ All activity for this entity
   ├─ Logons, queries, changes
   ├─ Filter by time range
   └─ Export for analysis

3. Alerts
   ├─ All alerts involving this entity
   ├─ As source or target
   └─ Historical trends

4. Lateral Movement Paths
   ├─ Paths TO this entity (if sensitive)
   ├─ Paths FROM this entity (if compromised)
   └─ Visual graph

5. Security Posture (🆕 2025)
   ├─ ISPMs specific to this entity
   ├─ Recommendations
   └─ Remediation status
```

**Investigate User Timeline:**

```
Scenario: Investigate user "john.doe" after suspicious alert

1. Search for "john.doe" in MDI portal
2. Open entity profile
3. Click "Timeline" tab
4. Set date range: Last 7 days
5. Review activity:
```

**Sample Timeline:**

```
Timeline for john.doe (Last 7 days)

2025-10-22 19:00 - Logon via Kerberos to WKS-001 ✓ Normal
2025-10-22 18:45 - Service ticket request for CIFS/FILESERVER ✓ Normal
2025-10-22 18:30 - Logon via NTLM to SERVER-01 ⚠️ Unusual (NTLM)
2025-10-22 18:29 - Password change ⚠️ Unusual (user rarely changes pwd)
2025-10-22 18:15 - 50 failed logon attempts 🚨 SUSPICIOUS
2025-10-22 17:00 - Logon to WKS-001 ✓ Normal
...

Analysis:
- Failed logon attempts at 18:15 → Possible compromise
- Password changed at 18:29 → Attacker changed password!
- NTLM logon at 18:30 → Attacker using stolen credential
- Normal activity resumed at 19:00 → Real user back (new password)

Conclusion: Account was compromised from 18:15-18:30
```

**Actions to Take:**

```
1. Force password reset (again, to be sure)
2. Revoke all active sessions
3. Review what attacker accessed during compromise window
4. Check for:
   - Data exfiltration
   - Lateral movement
   - Persistence mechanisms
5. Enable MFA for this user
6. Security awareness training for user
```

### 9.4 Cross-Product Investigation

**Microsoft 365 Defender Integration:**

MDI alerts are part of unified incidents across:
- Microsoft Defender for Endpoint (MDE)
- Microsoft Defender for Office 365 (MDO)
- Microsoft Defender for Cloud Apps (MDCA)
- Microsoft Defender for Identity (MDI)

**Example Unified Incident:**

```
Incident #12345: Multi-stage Attack Detected

Severity: High
Status: Active
Impacted: 3 users, 5 devices

Attack Story (Correlated):

1. Initial Access (MDO)
   └─ Phishing email to john.doe@contoso.com
      Subject: "Urgent: IT Security Update"
      Attachment: SecurityUpdate.xlsm (malicious macro)

2. Execution (MDE)
   └─ Macro executed on WKS-001
      Process: EXCEL.EXE → PowerShell.exe
      Downloaded: implant.exe from attacker server

3. Credential Access (MDI)
   └─ Mimikatz executed on WKS-001
      Extracted credentials for:
      - john.doe (victim)
      - admin_local (local admin)
      - service_sql (service account)

4. Lateral Movement (MDI + MDE)
   └─ Used service_sql credentials to access SQL-01
      Pass-the-hash attack detected
      MDI Alert: Suspected identity theft (pass-the-hash)

5. Collection (MDCA)
   └─ Accessed SharePoint site: "Finance Documents"
      Downloaded 50 files
      MDCA Alert: Mass file download detected

6. Exfiltration (MDCA + MDE)
   └─ Files uploaded to external cloud storage
      Dropbox.com
      500 MB uploaded

Timeline: 2 hours from phish to exfiltration

Recommended Actions:
1. Disable john.doe and service_sql accounts
2. Isolate WKS-001 and SQL-01
3. Reset passwords for all accessed accounts
4. Review all downloaded SharePoint files
5. Contact users whose data was exfiltrated
6. File takedown request with Dropbox
7. Conduct full incident response
```

**Investigation Across Products:**

```
Use Advanced Hunting to Correlate:

// Find user's activity across all products
let suspiciousUser = "john.doe@contoso.com";
let timeRange = ago(7d);

// Identity activity (MDI)
IdentityLogonEvents
| where Timestamp > timeRange
| where AccountUpn == suspiciousUser

| union (
    // Endpoint activity (MDE)
    DeviceProcessEvents
    | where Timestamp > timeRange
    | where AccountUpn == suspiciousUser
)

| union (
    // Email activity (MDO)
    EmailEvents
    | where Timestamp > timeRange
    | where RecipientEmailAddress == suspiciousUser
)

| union (
    // Cloud app activity (MDCA)
    CloudAppEvents
    | where Timestamp > timeRange
    | where AccountObjectId == suspiciousUser
)

| project Timestamp, TableName, ActionType, DeviceName, Application
| order by Timestamp asc
```

### 9.5 Response Actions for Identity Threats

**Available Actions in MDI:**

| Action | When to Use | Impact | Reversible |
|--------|-------------|--------|------------|
| **Disable user account** | Confirmed compromise | User cannot authenticate | ✅ Yes (re-enable) |
| **Force password reset** | Suspected compromise | Invalidates current sessions | ✅ Yes (user sets new) |
| **Require MFA re-registration** | MFA bypass suspected | User must re-register MFA | ✅ Yes |
| **Revoke refresh tokens** | Azure AD token theft | Logs out all sessions | ⚠️ User must re-login |
| **Mark as compromised** | Investigation in progress | Tracking/reporting only | ✅ Yes (unmark) |

**Execute Actions:**

```
Method 1: From Alert
1. Open MDI alert
2. Click on impacted user
3. Entity profile → "..." menu
4. Select action:
   - Disable user account
   - Force password change
   - etc.
5. Confirm action
6. Action executes immediately

Method 2: From Incident (M365 Defender)
1. Open incident
2. Select multiple impacted users
3. Bulk actions:
   - Disable accounts
   - Force password resets
   - etc.

Method 3: PowerShell (AD)
# Disable account
Disable-ADAccount -Identity "john.doe"

# Force password change at next logon
Set-ADUser -Identity "john.doe" -ChangePasswordAtLogon $true

# Reset password
Set-ADAccountPassword -Identity "john.doe" -Reset -NewPassword (ConvertTo-SecureString "TempP@ssw0rd!" -AsPlainText -Force)
```

**Response Playbook Example:**

```
Playbook: Response to Compromised Identity

Trigger: MDI alert for credential theft or pass-the-hash

Step 1: Validate (5 min)
- Review alert details
- Check if true positive
- Identify scope (single user or multiple)

Step 2: Contain (10 min)
- Disable compromised account(s)
- Revoke active sessions
- Block source IP if external

Step 3: Investigate (30 min)
- Review user timeline
- Identify what attacker accessed
- Hunt for lateral movement
- Check for data exfiltration

Step 4: Remediate (Variable)
- Remove persistence mechanisms
- Fix vulnerability that allowed compromise
- Reset passwords for all potentially affected accounts
- Enable MFA

Step 5: Recover (30 min)
- Re-enable accounts with new passwords
- Notify users
- Resume normal operations
- Continue monitoring

Step 6: Lessons Learned (1 hour)
- Document incident
- Update detections
- Improve prevention
- Train team

Total Time: ~2-3 hours for single user compromise
```

**🎯 Exam Tip:** For exam scenarios about MDI alert response, remember the order: **Validate → Contain → Investigate → Remediate → Recover**. Containment (disable account, reset password) comes BEFORE full investigation to prevent further damage.

---

## 10. Integration with Microsoft 365 Defender

### 10.1 Unified Security Operations

**Microsoft 365 Defender Portal:**

MDI is fully integrated into the Microsoft 365 Defender (M365D) portal, providing:

```
Unified Experience:
│
├─ Single Pane of Glass
│  └─ All Defender products in one portal
│
├─ Unified Incidents
│  └─ Correlated alerts across products
│
├─ Unified Advanced Hunting
│  └─ Query data from all products
│
├─ Unified Actions
│  └─ Respond across products
│
└─ Unified Reporting
   └─ Cross-product insights
```

**Benefits:**

✅ **Reduced Context Switching**
- No need to jump between portals
- All data in one place

✅ **Better Attack Visibility**
- See complete attack chain
- Understand cross-domain attacks

✅ **Faster Response**
- Single workflow
- Bulk actions across products

✅ **Improved Collaboration**
- Shared incident queue
- Unified assignments

### 10.2 Incident Correlation

**How M365D Correlates Incidents:**

```
Correlation Engine:
│
├─ Analyzes alerts from all products
│  ├─ MDI (identity attacks)
│  ├─ MDE (endpoint attacks)
│  ├─ MDO (email attacks)
│  └─ MDCA (cloud app attacks)
│
├─ Identifies relationships
│  ├─ Same user
│  ├─ Same device
│  ├─ Same time window
│  ├─ Same attack pattern
│  └─ Same attacker infrastructure
│
└─ Creates Unified Incident
   ├─ Groups related alerts
   ├─ Builds attack story
   ├─ Prioritizes severity
   └─ Suggests response actions
```

**Example Correlation:**

```
Individual Alerts (Before Correlation):
├─ MDI Alert: Account enumeration reconnaissance
├─ MDI Alert: Suspected AS-REP Roasting attack
├─ MDE Alert: Mimikatz execution detected
├─ MDI Alert: Pass-the-hash attack
├─ MDE Alert: Lateral movement via PsExec
└─ MDCA Alert: Unusual cloud access

After Correlation → Single Incident:
Incident: Credential theft and lateral movement

Attack Story:
1. Attacker enumerated accounts (MDI reconnaissance)
2. Performed AS-REP roasting to crack passwords (MDI)
3. Executed Mimikatz on compromised workstation (MDE)
4. Used stolen credentials for pass-the-hash (MDI)
5. Moved laterally to servers via PsExec (MDE)
6. Accessed sensitive SharePoint from unusual location (MDCA)

Result: Security team sees COMPLETE attack, not isolated events
```

### 10.3 Advanced Hunting Across Products

**Unified Advanced Hunting Tables:**

MDI contributes several tables to Advanced Hunting:

| Table | Data Source | Contains |
|-------|-------------|----------|
| **IdentityLogonEvents** | MDI | Authentication events (Kerberos, NTLM, LDAP) |
| **IdentityQueryEvents** | MDI | LDAP queries, AD reconnaissance |
| **IdentityDirectoryEvents** | MDI | AD changes (object creation, modification, deletion) |
| **AADSignInEventsBeta** | Azure AD | Cloud authentication (preview table) |
| **AADSpnSignInEventsBeta** | Azure AD | Service principal sign-ins |

**Cross-Product Hunting Queries:**

**Query 1: Find user's complete activity across ALL products**

```kql
// User to investigate
let user = "john.doe@contoso.com";
let timeframe = ago(7d);

// Identity authentication (MDI)
IdentityLogonEvents
| where Timestamp > timeframe
| where AccountUpn == user
| project Timestamp, Source="MDI", Activity="Authentication", Details=ActionType, DeviceName, IPAddress

| union (
    // Endpoint activity (MDE)
    DeviceLogonEvents
    | where Timestamp > timeframe
    | where AccountUpn == user
    | project Timestamp, Source="MDE", Activity="Endpoint Logon", Details=LogonType, DeviceName, RemoteIP
)

| union (
    // Email activity (MDO)
    EmailEvents
    | where Timestamp > timeframe
    | where RecipientEmailAddress == user or SenderFromAddress == user
    | project Timestamp, Source="MDO", Activity="Email", Details=Subject, DeviceName="N/A", IPAddress=SenderIPv4
)

| union (
    // Cloud app activity (MDCA)
    CloudAppEvents
    | where Timestamp > timeframe
    | where AccountObjectId == user
    | project Timestamp, Source="MDCA", Activity="Cloud App", Details=ActionType, DeviceName="N/A", IPAddress
)

| order by Timestamp asc
```

**Query 2: Detect pass-the-hash attack with subsequent lateral movement**

```kql
// Find pass-the-hash attacks (MDI)
let PtHAlerts = AlertEvidence
| where Timestamp > ago(24h)
| where Title has "pass-the-hash"
| project AlertTime=Timestamp, AccountName, SourceDevice=DeviceName;

// Find lateral movement on endpoints (MDE)
let LateralMovement = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (445, 135, 139) // SMB, RPC
| where InitiatingProcessFileName in~ ("psexec.exe", "wmic.exe", "powershell.exe")
| project NetworkTime=Timestamp, AccountName, SourceDevice=DeviceName, TargetDevice=RemoteIPAddress;

// Correlate: PtH followed by lateral movement
PtHAlerts
| join kind=inner (
    LateralMovement
) on AccountName, SourceDevice
| where NetworkTime > AlertTime // Lateral movement after PtH
| project AlertTime, NetworkTime, AccountName, SourceDevice, TargetDevice
| extend TimeDifference = NetworkTime - AlertTime
```

**Query 3: Find accounts targeted by both phishing and credential attacks**

```kql
// Find phishing targets (MDO)
let PhishingTargets = EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where EmailDirection == "Inbound"
| distinct RecipientEmailAddress;

// Find credential attack targets (MDI)
let CredentialAttackTargets = AlertEvidence
| where Timestamp > ago(7d)
| where Title has_any ("brute force", "password spray", "Kerberoasting", "AS-REP")
| distinct AccountUpn;

// Find overlap
PhishingTargets
| join kind=inner (
    CredentialAttackTargets
) on $left.RecipientEmailAddress == $right.AccountUpn
| project EmailAddress=RecipientEmailAddress
| extend Recommendation = "High priority - targeted by multiple attack vectors"
```

### 10.4 Automatic Attack Disruption

**🆕 Identity Containment in Attack Disruption:**

Microsoft 365 Defender's automatic attack disruption includes identity-based containment:

```
Attack Disruption for Identity Threats:

When MDI Detects Critical Attack:
│
├─ Golden Ticket usage
├─ DCSync attack
├─ Pass-the-hash to privileged account
├─ Honeytoken usage
└─ Domain dominance attempts

Automatic Actions Triggered:
│
├─ 1. Disable compromised accounts (MDI action)
├─ 2. Isolate affected devices (MDE action)
├─ 3. Block malicious emails (MDO action)
├─ 4. Revoke cloud sessions (MDCA/Azure AD action)
└─ 5. Create unified incident for investigation

Benefits:
├─ Stops attack within seconds
├─ Prevents lateral movement
├─ Limits damage
└─ Buys time for investigation
```

**Example Attack Disruption Scenario:**

```
Attack Timeline with Automatic Disruption:

14:00:00 - Attacker compromises user account (phishing)
14:05:00 - Attacker executes Mimikatz on workstation
14:05:30 - MDI detects: Pass-the-hash attack
14:05:31 - 🚨 Automatic attack disruption triggers!

Automatic Actions (within seconds):
├─ User account disabled (MDI)
├─ Workstation isolated from network (MDE)
├─ All active sessions revoked (Azure AD)
├─ Source IP blocked (Network Protection)
└─ Incident created and assigned to SOC

Result: Attack stopped in 31 seconds!

Without Attack Disruption:
- Attacker could lateral move for hours
- Could access domain controller
- Could exfiltrate sensitive data
- Could create persistence
```

**Configure Attack Disruption:**

```
1. Settings → Microsoft 365 Defender → Attack disruption
2. Toggle ON: "Enable automatic attack disruption"
3. Configure:
   - Scope: All devices or specific groups
   - Actions: Select which automatic actions to enable
     ☑ Disable user accounts (high-confidence attacks)
     ☑ Isolate devices
     ☑ Contain identities
     ☑ Revoke sessions
4. Exclusions:
   - Add VIP users (with approval)
   - Add critical service accounts
   - Add known safe IPs
5. Save

Recommendation: Enable all actions for maximum protection
```

### 10.5 Security Copilot Integration

**🆕 Microsoft Security Copilot with MDI:**

Security Copilot provides AI-powered assistance for identity investigations:

**Use Cases:**

**1. Incident Summarization**

```
Analyst: "Summarize incident #12345"

Copilot Response:
"This incident involves a suspected DCSync attack detected by Microsoft
Defender for Identity. The account 'CONTOSO\compromised-admin' requested
directory replication from DC01.contoso.com at 2025-10-22 18:00:00,
extracting password hashes for 500+ accounts including the krbtgt account.

Key Timeline:
- 17:45: Account logged in from unusual location (Russia)
- 18:00: DCSync attack executed
- 18:15: Golden Ticket usage detected (using stolen krbtgt hash)
- 18:30: Lateral movement to file servers

Impact: Critical - Full domain compromise assumed due to krbtgt theft.

Recommended Actions (Urgent):
1. Reset krbtgt password twice (24 hours apart)
2. Disable compromised account immediately
3. Force password reset for all admin accounts
4. Hunt for Golden Ticket usage
5. Investigate how account was initially compromised

Would you like me to execute any of these actions?"
```

**2. Guided Investigation**

```
Analyst: "How do I investigate a Golden Ticket alert?"

Copilot Response:
"To investigate a Golden Ticket alert from Microsoft Defender for Identity:

Step 1: Verify the alert (2 minutes)
- Review alert details in the unified incident
- Check for indicators:
  * Encryption downgrade (RC4 instead of AES)
  * Excessive ticket lifetime (years instead of hours)
  * Ticket for non-existent/deleted user
- Confirm it's a true positive

Step 2: Determine when krbtgt was compromised (5 minutes)
- Search for DCSync alerts in last 30 days
- Query: 'Show me all DCSync alerts in the last month'
- Identify when krbtgt hash was stolen

Step 3: Find all affected systems (10 minutes)
- I can run this Advanced Hunting query:
[Query provided by Copilot]
- Shows everywhere Golden Ticket was used

Step 4: Containment (Immediate)
- Disable compromised accounts
- I can help you execute these actions

Step 5: Remediation (Critical!)
- Reset krbtgt password TWICE
- This is critical - shall I guide you through the process?

Would you like me to proceed with any of these steps?"
```

**3. Threat Intelligence Lookup**

```
Analyst: "Tell me about MITRE technique T1558.001"

Copilot Response:
"T1558.001 is 'Steal or Forge Kerberos Tickets: Golden Ticket' from the
MITRE ATT&CK framework.

Description:
Adversaries who compromise the krbtgt account password hash can forge
Kerberos Ticket Granting Tickets (TGT), also known as Golden Tickets.
These tickets allow unlimited access to the domain.

Detection Methods (MDI):
- Encryption downgrades (RC4 when account uses AES)
- Abnormal ticket lifetimes
- Tickets for non-existent users
- Forged PAC data

Prevention:
- Protect krbtgt account
- Regular password rotation (annually)
- Detect DCSync attacks (prevents Golden Ticket creation)
- Use Protected Users group
- Implement Credential Guard

Related Techniques:
- T1003.006: DCSync (often precedes Golden Ticket)
- T1558.003: Kerberoasting
- T1558.004: AS-REP Roasting

Your environment: I can see 2 Golden Ticket alerts in the last 30 days.
Would you like me to investigate them?"
```

**4. Query Generation**

```
Analyst: "Find all authentication from unusual locations for admin accounts"

Copilot Response:
"I'll create an Advanced Hunting query for you:

// Find admin authentications from unusual locations
let AdminAccounts = IdentityInfo
| where AssignedRoles has_any ("Global Administrator", "Domain Administrator")
| distinct AccountUpn;

let BaselineLocations = IdentityLogonEvents
| where Timestamp > ago(90d)
| where AccountUpn in (AdminAccounts)
| summarize Countries=make_set(Location) by AccountUpn;

IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountUpn in (AdminAccounts)
| join kind=inner (BaselineLocations) on AccountUpn
| where Location !in (Countries) // Not in baseline
| project Timestamp, AccountUpn, Location, IPAddress, DeviceName, ActionType
| order by Timestamp desc

Shall I run this query for you? I found 3 matches."
```

### 10.6 Microsoft Sentinel Integration

**MDI + Sentinel Integration:**

Many organizations use both MDI and Microsoft Sentinel:

```
Architecture:

Microsoft Defender for Identity
├─ Detects identity threats
├─ Generates alerts
└─ Sends data to Sentinel (optional)

Microsoft Sentinel
├─ Receives MDI alerts
├─ Correlates with other data sources
├─ Enriches with threat intelligence
├─ Runs custom analytics rules
└─ Orchestrates response (SOAR)
```

**Data Connector:**

```
Configure MDI → Sentinel:

1. Microsoft Sentinel → Data connectors
2. Search for "Microsoft Defender for Identity"
3. Click "Open connector page"
4. Select "Connect"
5. Choose:
   - Connect alerts: Yes
   - Connect audit logs: Optional
6. Wait for data (15-30 minutes)
7. Verify:
   SecurityAlert table
   | where ProviderName == "IPC" // IPC = Identity Protection Cloud (MDI)
```

**Benefits of Sentinel Integration:**

✅ **Custom Analytics Rules**
```
Create Sentinel rules on top of MDI data:
- Threshold alerts (e.g., 5+ brute force in 1 hour)
- Correlation with other data sources
- Enrichment with threat intel
```

✅ **SOAR Orchestration**
```
Automate response with Logic Apps:
- MDI alert → Logic App trigger
- Enrich with asset data
- Notify via Teams/Email
- Create ServiceNow ticket
- Execute remediation script
```

✅ **Long-term Retention**
```
MDI alerts retained 30 days in M365 Defender
Sentinel can retain for 1-2+ years
Useful for compliance and historical analysis
```

**Example Sentinel Analytics Rule:**

```
// Custom Sentinel rule: Multiple identity attacks on single user

IdentityEvents
| where TimeGenerated > ago(1h)
| where AlertSeverity in ("High", "Critical")
| summarize AlertCount = count(), 
            AlertTypes = make_set(AlertType),
            FirstAlert = min(TimeGenerated),
            LastAlert = max(TimeGenerated)
    by AccountName
| where AlertCount >= 3 // 3+ alerts in 1 hour
| extend Severity = "High"
| project AccountName, AlertCount, AlertTypes, FirstAlert, LastAlert, Severity
```

**🎯 Exam Tip:** Know that MDI integrates with BOTH Microsoft 365 Defender (native integration) AND Microsoft Sentinel (via data connector). M365D is for real-time operations, Sentinel for long-term retention and custom automation.

---

## 11. Advanced Hunting for Identity Threats

### 11.1 MDI Advanced Hunting Tables

**Key Tables:**

| Table | Description | Row Count (Typical) | Retention |
|-------|-------------|---------------------|-----------|
| **IdentityLogonEvents** | Authentication events | High volume | 30 days |
| **IdentityQueryEvents** | LDAP/AD queries | Very high volume | 30 days |
| **IdentityDirectoryEvents** | AD object changes | Medium volume | 30 days |
| **IdentityInfo** | Entity information (users, devices) | Static snapshot | Current state |

### 11.2 IdentityLogonEvents Table

**Schema:**

```kql
// View schema
IdentityLogonEvents
| getschema

// Key columns:
Timestamp             - When authentication occurred
ActionType            - Type of authentication
Application           - Service used
Protocol              - Kerberos, NTLM, LDAP
LogonType             - Interactive, Network, Service, etc.
AccountUpn            - User authenticating
AccountName           - DOMAIN\Username
AccountDomain         - Domain
DeviceName            - Device authenticated to
IPAddress             - Source IP
Location              - Geographic location
ISP                   - Internet Service Provider
FailureReason         - Why auth failed (if failed)
AdditionalFields      - JSON with extra details
```

**Common Queries:**

**Query 1: Find failed logons (brute force detection)**

```kql
// Failed logon attempts
IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| summarize FailureCount = count(), 
            Accounts = make_set(AccountName),
            FirstFailure = min(Timestamp),
            LastFailure = max(Timestamp)
    by IPAddress, FailureReason
| where FailureCount > 10
| order by FailureCount desc
```

**Query 2: Detect authentication from unusual locations**

```kql
// Build baseline of normal locations (last 90 days)
let Baseline = IdentityLogonEvents
| where Timestamp between (ago(90d) .. ago(7d))
| where ActionType == "LogonSuccess"
| summarize Locations = make_set(Location) by AccountUpn;

// Find authentications from NEW locations in last 7 days
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| join kind=inner (Baseline) on AccountUpn
| where Location !in (Locations) // New location
| project Timestamp, AccountUpn, Location, IPAddress, DeviceName
| order by Timestamp desc
```

**Query 3: Find NTLM usage (should migrate to Kerberos)**

```kql
// NTLM authentication (outdated protocol)
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "NTLM"
| summarize NTLMCount = count() by AccountUpn, DeviceName, Application
| order by NTLMCount desc
| extend Recommendation = "Migrate to Kerberos or investigate legacy app"
```

**Query 4: Detect impossible travel**

```kql
// Find same user authenticating from distant locations in short time
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess"
| where isnotempty(Location)
| extend LocationParts = split(Location, ", ")
| extend Country = tostring(LocationParts[-1])
| summarize Locations = make_set(Country), 
            IPAddresses = make_set(IPAddress),
            Times = make_list(Timestamp)
    by AccountUpn, bin(Timestamp, 1h)
| where array_length(Locations) > 1 // Multiple countries in same hour
| extend ImpossibleTravel = "Likely - multiple countries in 1 hour"
| project AccountUpn, Locations, IPAddresses, Times, ImpossibleTravel
```

### 11.3 IdentityQueryEvents Table

**Purpose:** Tracks LDAP queries to Active Directory (reconnaissance detection).

**Schema:**

```kql
// Key columns:
Timestamp             - When query occurred
ActionType            - Type of query (LDAP search, etc.)
Query                 - LDAP query string
QueryTarget           - What was queried
QueryType             - Search, Modification, etc.
AccountName           - Who ran query
DeviceName            - Device query came from
Protocol              - LDAP, LDAPS
DestinationDeviceName - DC that handled query
```

**Common Queries:**

**Query 1: Detect LDAP reconnaissance**

```kql
// Excessive LDAP queries (reconnaissance)
IdentityQueryEvents
| where Timestamp > ago(1h)
| where ActionType == "LDAP query"
| summarize QueryCount = count(), 
            UniqueQueries = dcount(Query),
            Targets = make_set(QueryTarget)
    by AccountName, DeviceName
| where QueryCount > 100 or UniqueQueries > 50
| order by QueryCount desc
| extend Suspicious = "Possible reconnaissance activity"
```

**Query 2: Find queries for sensitive groups**

```kql
// Queries targeting sensitive groups
let SensitiveGroups = dynamic([
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators"
]);

IdentityQueryEvents
| where Timestamp > ago(7d)
| where QueryTarget has_any (SensitiveGroups)
| project Timestamp, AccountName, DeviceName, QueryTarget, Query
| order by Timestamp desc
```

**Query 3: Detect BloodHound/SharpHound activity**

```kql
// BloodHound-style queries (AD relationship mapping)
IdentityQueryEvents
| where Timestamp > ago(1h)
| where Query has_any (
    "objectClass=group",
    "objectClass=user",
    "objectClass=computer",
    "memberOf",
    "servicePrincipalName"
)
| summarize QueryCount = count(),
            UniqueObjectClasses = dcount(Query),
            Queries = make_set(Query)
    by AccountName, DeviceName, bin(Timestamp, 5m)
| where QueryCount > 50 // Many queries in short time
| order by QueryCount desc
| extend Suspicious = "Possible BloodHound/AD enumeration tool"
```

### 11.4 IdentityDirectoryEvents Table

**Purpose:** Tracks changes to Active Directory objects.

**Schema:**

```kql
// Key columns:
Timestamp             - When change occurred
ActionType            - Created, Modified, Deleted
Application           - Tool used
DestinationDeviceName - DC where change was made
TargetAccountUpn      - Account modified
TargetDeviceName      - Computer modified (if computer object)
AdditionalFields      - JSON with change details
Protocol              - LDAP, LDAPS, etc.
```

**Common Queries:**

**Query 1: Track privileged group membership changes**

```kql
// Changes to sensitive groups
let SensitiveGroups = dynamic([
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins"
]);

IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType in ("Group Membership changed")
| extend GroupName = tostring(parse_json(AdditionalFields).["TO.GROUP"])
| where GroupName has_any (SensitiveGroups)
| extend MemberAdded = tostring(parse_json(AdditionalFields).["TO.MEMBER"])
| project Timestamp, GroupName, MemberAdded, ActionType, AccountName
| order by Timestamp desc
```

**Query 2: Detect service account creation**

```kql
// New service accounts created
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "User account created"
| extend NewAccountName = tostring(parse_json(AdditionalFields).["TARGET_OBJECT.USER"])
| where NewAccountName startswith "svc_" or NewAccountName contains "service"
| project Timestamp, NewAccountName, CreatedBy=AccountName, DeviceName
```

**Query 3: Find accounts with SPN modifications (Kerberoasting prep)**

```kql
// SPN changes (attackers may add SPNs for Kerberoasting)
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where AdditionalFields has "ServicePrincipalName"
| extend TargetAccount = tostring(parse_json(AdditionalFields).["TARGET_OBJECT.USER"])
| extend SPNChange = tostring(parse_json(AdditionalFields).["ServicePrincipalName"])
| project Timestamp, TargetAccount, SPNChange, ModifiedBy=AccountName
| order by Timestamp desc
```

### 11.5 IdentityInfo Table

**Purpose:** Current state of all identities (users, computers, groups).

**Schema:**

```kql
// Key columns:
AccountUpn            - User principal name
AccountName           - DOMAIN\Username
AccountObjectId       - Unique ID
AccountDisplayName    - Display name
Department            - Department
JobTitle              - Job title
Manager               - Manager UPN
City, Country         - Location
IsAccountEnabled      - Enabled/Disabled
AssignedRoles         - Azure AD roles
GroupMembership       - Group memberships (partial)
Tags                  - MDI tags (Sensitive, Honeytoken, etc.)
```

**Common Queries:**

**Query 1: Find all sensitive accounts**

```kql
// All accounts tagged as sensitive
IdentityInfo
| where Tags has "Sensitive"
| project AccountUpn, AccountDisplayName, Department, AssignedRoles
| order by AccountDisplayName asc
```

**Query 2: Find admins without MFA**

```kql
// Admin accounts (should all have MFA)
IdentityInfo
| where AssignedRoles has_any ("Global Administrator", "Security Administrator", "Domain Administrator")
| where AccountName !endswith "$" // Exclude computer accounts
| project AccountUpn, AccountDisplayName, AssignedRoles, Department, Manager
// Note: MFA status requires joining with AADSignInEventsBeta or Azure AD data
```

**Query 3: Find enabled accounts in sensitive groups**

```kql
// Active accounts in privileged groups
IdentityInfo
| where IsAccountEnabled == true
| where GroupMembership has_any ("Domain Admins", "Enterprise Admins")
| project AccountUpn, AccountDisplayName, Department, Manager, LastSeenDate
```

### 11.6 Complex Cross-Table Queries

**Query 1: Find accounts with both failed and successful logins (potential brute force success)**

```kql
// Accounts with failed attempts followed by success
let FailedLogons = IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| distinct AccountUpn, IPAddress;

IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess"
| join kind=inner (FailedLogons) on AccountUpn, IPAddress
| summarize SuccessfulLogons = count(),
            FirstSuccess = min(Timestamp),
            Devices = make_set(DeviceName)
    by AccountUpn, IPAddress
| extend Suspicious = "Potential brute force SUCCESS"
| order by FirstSuccess desc
```

**Query 2: Correlate reconnaissance with credential attacks**

```kql
// LDAP reconnaissance followed by Kerberoasting
let Reconnaissance = IdentityQueryEvents
| where Timestamp > ago(1h)
| where QueryCount > 100 // Excessive queries
| summarize ReconTime = min(Timestamp) by AccountName;

AlertEvidence
| where Timestamp > ago(1h)
| where Title has "Kerberoasting"
| join kind=inner (Reconnaissance) on $left.AccountName == $right.AccountName
| where Timestamp > ReconTime // Attack after reconnaissance
| project ReconTime, AttackTime=Timestamp, AccountName, Title
| extend TimeDifference = Timestamp - ReconTime
```

**Query 3: Find lateral movement after identity compromise**

```kql
// Identity alert followed by lateral movement
let IdentityAlerts = AlertEvidence
| where Timestamp > ago(24h)
| where ServiceSource == "Microsoft Defender for Identity"
| where Severity in ("High", "Critical")
| project AlertTime=Timestamp, AccountName, DeviceName;

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (445, 135, 139) // SMB, RPC, NetBIOS
| where InitiatingProcessFileName in~ ("psexec.exe", "wmic.exe")
| join kind=inner (IdentityAlerts) on $left.AccountName == $right.AccountName
| where Timestamp > AlertTime // Lateral movement after compromise
| project AlertTime, LateralMovementTime=Timestamp, AccountName, 
          SourceDevice=DeviceName, TargetDevice=RemoteIP, Process=InitiatingProcessFileName
| extend TimeDifference = Timestamp - AlertTime
```

### 11.7 Threat Hunting with KQL

**Hunt 1: Detect Kerberos ticket reuse (Pass-the-Ticket)**

```kql
// Same ticket used from multiple devices
IdentityLogonEvents
| where Timestamp > ago(1h)
| where Protocol == "Kerberos"
| where ActionType == "LogonSuccess"
| extend TicketID = tostring(parse_json(AdditionalFields).["Ticket.Id"])
| where isnotempty(TicketID)
| summarize Devices = make_set(DeviceName), 
            IPs = make_set(IPAddress),
            LogonCount = count()
    by AccountUpn, TicketID
| where array_length(Devices) > 1 // Same ticket, multiple devices
| extend Suspicious = "Possible Pass-the-Ticket attack"
```

**Hunt 2: Detect Golden Ticket characteristics**

```kql
// Long-lived Kerberos tickets (Golden Ticket indicator)
IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Kerberos"
| extend TicketLifetime = tostring(parse_json(AdditionalFields).["Ticket.LifetimeHours"])
| where TicketLifetime > 10 // Normal is 10 hours, Golden Ticket is much longer
| project Timestamp, AccountUpn, DeviceName, TicketLifetime, IPAddress
| extend Suspicious = "Abnormally long ticket lifetime - possible Golden Ticket"
```

**Hunt 3: Detect DCSync prerequisites (replication permissions)**

```kql
// Find accounts granted DS-Replication permissions
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where AdditionalFields has "DS-Replication-Get-Changes"
| extend TargetAccount = tostring(parse_json(AdditionalFields).["TARGET_OBJECT.USER"])
| extend PermissionGranted = tostring(parse_json(AdditionalFields).["Replication Permission"])
| project Timestamp, TargetAccount, PermissionGranted, GrantedBy=AccountName
| extend Warning = "Account granted replication permissions - Monitor for DCSync attack"
```

**🎯 Exam Tip:** For SC-200, know the main MDI hunting tables (IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents) and understand how to detect common attacks (brute force, reconnaissance, pass-the-hash, Kerberoasting) using KQL.

---

## 12. ITDR (Identity Threat Detection and Response)

### 12.1 What is ITDR?

**Identity Threat Detection and Response (ITDR)** is an emerging security discipline focused specifically on protecting identity infrastructure.

**ITDR vs Traditional Security:**

```
Traditional Security          ITDR
│                            │
├─ Endpoints                 ├─ Identity Infrastructure
├─ Network                   ├─ Active Directory
├─ Applications              ├─ Azure AD / Entra ID
└─ Data                      ├─ Federation Services (AD FS)
                             ├─ Certificate Services (AD CS)
                             └─ Identity Providers (IDPs)
```

**Why ITDR Matters:**

```
Modern Attacks Target Identity:
│
├─ 80%+ breaches involve compromised credentials
├─ Attackers bypass endpoint security via valid credentials
├─ Cloud migration increases identity attack surface
├─ Traditional security tools don't protect identity infrastructure
└─ Need specialized solutions → ITDR
```

**MDI as ITDR Platform:**

Microsoft Defender for Identity is Microsoft's **ITDR solution** providing:

✅ **Detection** - Identify identity-based attacks
✅ **Investigation** - Understand attack scope
✅ **Response** - Contain and remediate threats
✅ **Posture Management** - Proactively fix weaknesses

### 12.2 ITDR Kill Chain

**Identity Attack Kill Chain:**

```
1. Reconnaissance
   ├─ LDAP enumeration
   ├─ SMB enumeration
   ├─ DNS queries
   └─ BloodHound/SharpHound
   
   MDI Detection:
   - Account enumeration reconnaissance
   - Network mapping reconnaissance
   - Active Directory attributes reconnaissance

2. Initial Access
   ├─ Phishing (credential theft)
   ├─ Brute force
   ├─ Password spray
   └─ Credential stuffing
   
   MDI Detection:
   - Suspected brute force attack
   - Suspected password spray attack

3. Credential Access
   ├─ AS-REP Roasting
   ├─ Kerberoasting
   ├─ NTLM relay
   └─ DCSync
   
   MDI Detection:
   - Suspected AS-REP Roasting attack
   - Suspected Kerberoasting attack
   - Suspected DCSync attack

4. Lateral Movement
   ├─ Pass-the-Hash
   ├─ Pass-the-Ticket
   ├─ Over-Pass-the-Hash
   └─ Remote execution (PsExec, WMI)
   
   MDI Detection:
   - Suspected identity theft (pass-the-hash)
   - Suspected identity theft (pass-the-ticket)
   - Suspected Over-Pass-the-Hash attack

5. Domain Dominance
   ├─ Golden Ticket
   ├─ Silver Ticket
   ├─ DCShadow
   └─ Skeleton Key
   
   MDI Detection:
   - Suspected Golden Ticket usage (multiple types)
   - Suspected DCShadow attack
   - Suspected skeleton key attack
```

### 12.3 ITDR Best Practices

**1. Deploy Comprehensive Coverage**

```
ITDR Deployment Checklist:
├─ ✅ MDI sensors on ALL domain controllers
├─ ✅ MDI sensors on all AD FS servers
├─ ✅ MDI sensors on all AD CS servers (🆕)
├─ ✅ MDI sensors on Entra Connect servers
├─ ✅ Event auditing configured (4776, 4768, 4769, 4662, etc.)
├─ ✅ Directory Services account with proper permissions
└─ ✅ Network connectivity to MDI cloud service
```

**2. Implement Zero Trust for Identity**

```
Zero Trust Identity Principles:
│
├─ Verify explicitly
│  ├─ MFA for all users
│  ├─ Risk-based conditional access
│  └─ Continuous authentication
│
├─ Use least privileged access
│  ├─ JIT (Just-In-Time) admin access
│  ├─ PIM (Privileged Identity Management)
│  └─ Time-bound permissions
│
└─ Assume breach
   ├─ Monitor all authentication
   ├─ Detect anomalies
   └─ Rapid response
```

**3. Harden Active Directory**

```
AD Security Hardening:
│
├─ Account Security
│  ├─ Protected Users group
│  ├─ Authentication Policies and Silos
│  ├─ Disable NTLM where possible
│  └─ Strong password policies
│
├─ Privileged Access
│  ├─ Admin tiering model (Tier 0/1/2)
│  ├─ PAWs (Privileged Access Workstations)
│  ├─ LAPS (Local Administrator Password Solution)
│  └─ No admin logon to workstations
│
├─ Infrastructure Security
│  ├─ Secure domain controllers physically
│  ├─ Restrict DC access (firewall rules)
│  ├─ Regular patching
│  └─ Disable insecure protocols
│
└─ Monitoring & Detection
   ├─ MDI sensors deployed
   ├─ Event log collection (SIEM)
   ├─ Honeytokens deployed
   └─ Security posture assessments reviewed
```

**4. Enable Advanced Protections**

```
Advanced Identity Protections:

Windows Features:
├─ Credential Guard (Windows 10/11, Server 2016+)
├─ Remote Credential Guard
├─ Windows Defender Firewall with Advanced Security
└─ AppLocker or Windows Defender Application Control

Azure AD/Entra ID:
├─ Conditional Access policies
├─ Identity Protection (risk-based policies)
├─ MFA for all users
├─ Passwordless authentication (Windows Hello, FIDO2)
└─ PIM (Privileged Identity Management)

Active Directory:
├─ Protected Users security group
├─ Authentication Policies (limit where admins can login)
├─ Fine-Grained Password Policies
└─ Read-Only Domain Controllers (RODCs) in DMZ
```

### 12.4 ITDR Metrics and KPIs

**Key Metrics for ITDR Program:**

```
Detection Metrics:
├─ Mean Time to Detect (MTTD) identity threats
│  Goal: < 5 minutes for critical attacks
│
├─ Alert volume and accuracy
│  Goal: < 10% false positive rate
│
└─ Coverage percentage
   Goal: 100% of DCs with MDI sensors

Response Metrics:
├─ Mean Time to Respond (MTTR)
│  Goal: < 15 minutes for critical alerts
│
├─ Mean Time to Remediate (MTTR)
│  Goal: < 1 hour for containment, < 24 hours for full remediation
│
└─ Incident escalation rate
   Goal: < 5% require escalation

Posture Metrics:
├─ Number of lateral movement paths
│  Goal: < 10 paths to sensitive accounts
│
├─ ISPM remediation rate
│  Goal: 90% of Critical/High ISPMs remediated within 30 days
│
└─ Microsoft Secure Score (Identity section)
   Goal: > 80% score
```

**Dashboard Example:**

```
ITDR Dashboard (Weekly View)

Detection:
├─ Alerts this week: 45
│  ├─ Critical: 2 ✓ (both investigated)
│  ├─ High: 8 ✓ (all investigated)
│  ├─ Medium: 20 (15 investigated)
│  └─ Low: 15 (backlog)
│
├─ MTTD: 4.2 minutes ✓ (Goal: < 5 min)
└─ False positive rate: 8% ✓ (Goal: < 10%)

Response:
├─ MTTR: 12 minutes ✓ (Goal: < 15 min)
├─ Open incidents: 3
└─ Escalated incidents: 1 (3%)

Posture:
├─ Lateral movement paths: 12 ⚠️ (Goal: < 10)
├─ Critical ISPMs: 2 open
├─ High ISPMs: 5 open
└─ Secure Score: 78% ⚠️ (Goal: > 80%)

Action Items:
1. Remediate 2 lateral movement paths this week
2. Close 2 critical ISPMs
3. Investigate backlog of medium alerts
```

### 12.5 ITDR Maturity Model

**Assess your ITDR maturity:**

**Level 0: Non-Existent**
- ❌ No identity threat detection
- ❌ No MDI deployment
- ❌ Reactive only (forensics after breach)

**Level 1: Initial**
- ⚠️ MDI deployed on some DCs
- ⚠️ Default settings
- ⚠️ Alerts reviewed sporadically
- ⚠️ No formal incident response

**Level 2: Developing**
- ✅ MDI deployed on all DCs
- ✅ Sensors on AD FS, AD CS
- ✅ Alerts reviewed daily
- ✅ Basic incident response process
- ⚠️ Limited proactive hunting

**Level 3: Defined**
- ✅ Comprehensive coverage (all infrastructure)
- ✅ Alert tuning and optimization
- ✅ Formal IR playbooks
- ✅ Weekly threat hunting
- ✅ ISPM tracking and remediation
- ⚠️ Manual response processes

**Level 4: Managed**
- ✅ Automated response for common scenarios
- ✅ Integration with SOAR platform
- ✅ Advanced hunting queries scheduled
- ✅ Honeytokens deployed
- ✅ Metrics tracked and reported
- ✅ Continuous improvement

**Level 5: Optimizing**
- ✅ AI/ML-enhanced detection
- ✅ Full automation for containment
- ✅ Proactive posture management
- ✅ Regular red team exercises
- ✅ Industry-leading practices
- ✅ Zero trust identity fully implemented

**🎯 Goal:** Reach Level 3 (Defined) minimum for production environments.

### 12.6 ITDR vs Other Security Disciplines

**How ITDR Fits in Security Architecture:**

```
Security Layers:

┌─────────────────────────────────────────────┐
│  SIEM/SOAR (Microsoft Sentinel)             │ ← Overall orchestration
│  Correlation, investigation, response       │
└─────────────────────────────────────────────┘
              ↑      ↑       ↑       ↑
              │      │       │       │
    ┌─────────┼──────┼───────┼───────┼─────────┐
    │         │      │       │       │         │
┌───┴───┐ ┌──┴───┐ ┌┴────┐ ┌┴─────┐ ┌┴────────┐
│  EDR  │ │ ITDR │ │ CDR │ │ CASB │ │  NDR    │
│ (MDE) │ │ (MDI)│ │(MDO)│ │(MDCA)│ │(Network)│
└───────┘ └──────┘ └─────┘ └──────┘ └─────────┘
   │         │        │       │         │
   │         │        │       │         │
Endpoints  Identity Email   Cloud    Network
                              Apps
```

**Complementary Disciplines:**

| Discipline | Focus | Tool | Overlap with ITDR |
|------------|-------|------|-------------------|
| **EDR** | Endpoint behavior | MDE | Credential theft on endpoints |
| **ITDR** | Identity infrastructure | MDI | Full identity lifecycle |
| **CDR** | Communication security | MDO | Phishing (initial access) |
| **CASB** | Cloud app security | MDCA | Cloud identity usage |
| **NDR** | Network traffic | Various | East-west traffic monitoring |
| **SIEM** | Log aggregation & correlation | Sentinel | Central visibility |

**When to Use Each:**

```
Scenario: Detect credential theft

EDR (MDE): Detect Mimikatz execution on endpoint
ITDR (MDI): Detect pass-the-hash authentication
Combined: Full attack chain visibility

Scenario: Detect lateral movement

EDR (MDE): Process execution (psexec.exe, wmic.exe)
ITDR (MDI): Abnormal authentication patterns
NDR: East-west network traffic spikes
Combined: Multi-layer detection

Scenario: Detect data exfiltration

EDR (MDE): Large file copy to USB
ITDR (MDI): Access to sensitive AD objects
CASB (MDCA): Mass upload to personal cloud
Combined: Data flow tracking end-to-end
```

**🎯 Exam Tip:** MDI is the **ITDR** solution in Microsoft's stack. It specifically protects **identity infrastructure** (AD, Kerberos, LDAP, AD FS, AD CS) and detects **identity-based attacks**. It complements MDE (endpoints), MDO (email), and MDCA (cloud apps).

---

## 13. Configuration and Best Practices

### 13.1 Production Deployment Checklist

**Pre-Deployment:**

```
☐ License Verification
  ├─ Confirm MDI licenses assigned
  ├─ Verify license covers all users
  └─ Check license expiration date

☐ Infrastructure Assessment
  ├─ Document all DCs (writable and RODC)
  ├─ Identify AD FS servers
  ├─ Identify AD CS servers (🆕)
  ├─ Identify Entra Connect servers
  └─ Map network topology and trusts

☐ Prerequisites
  ├─ .NET Framework 4.7+ on all servers (v2.x)
  ├─ MDE deployed on all DCs (v3.x)
  ├─ Outbound HTTPS 443 allowed
  ├─ Proxy configured (if needed)
  └─ DNS resolution functional

☐ Account Preparation
  ├─ Create DSA or gMSA account
  ├─ Grant permissions:
  │  ├─ Read all objects in domain
  │  └─ Read Deleted Objects container
  └─ Test account access

☐ Event Auditing
  ├─ Configure Advanced Audit Policies
  ├─ Enable event IDs: 4776, 4768, 4769, 4662, etc.
  ├─ Test event generation
  └─ Verify logs flowing to DCs
```

**Deployment Phase:**

```
☐ Create MDI Workspace
  ├─ Sign in to security.microsoft.com
  ├─ Create workspace
  ├─ Configure DSA/gMSA account
  └─ Note workspace access key

☐ Deploy Sensors
  ├─ Install v2.x sensors on:
  │  ├─ All writable DCs
  │  ├─ All RODCs
  │  ├─ AD FS servers
  │  ├─ AD CS servers
  │  └─ Entra Connect servers
  OR
  ├─ Activate v3.x sensors on:
  │  └─ All DCs (if all Server 2019+)
  
☐ Verify Sensor Health
  ├─ All sensors show "Running"
  ├─ No health alerts
  ├─ Data flowing to portal
  └─ Domain synchronizer elected
```

**Post-Deployment:**

```
☐ Initial Configuration
  ├─ Configure VPN integration (optional)
  ├─ Apply entity tags (Sensitive accounts)
  ├─ Configure alert notifications
  ├─ Set up delayed update ring (optional)
  └─ Review default settings

☐ Testing
  ├─ Generate test authentication events
  ├─ Verify events appear in timeline
  ├─ Trigger test alert (safe method)
  ├─ Verify alert appears in portal
  └─ Test incident response workflow

☐ Tuning (First 30 Days)
  ├─ Enable Recommended test mode (first 30 days)
  ├─ Review alerts daily
  ├─ Document false positives
  ├─ Create exclusions as needed
  └─ Adjust thresholds

☐ Operationalization
  ├─ Train SOC team
  ├─ Create runbooks/playbooks
  ├─ Define escalation paths
  ├─ Set up metrics dashboard
  └─ Schedule regular reviews
```

### 13.2 Optimal Configuration Settings

**Sensor Configuration:**

```
Recommended Settings:

Delayed Updates:
- Enable on 1-2 "canary" sensors
- Rest get updates immediately
- Allows testing new versions before wide rollout

Directory Service Account:
- Use gMSA (recommended)
- OR dedicated account with:
  * Password never expires
  * Cannot change password
  * Complex 25+ character password
  * No interactive logon rights

Sensor Placement:
- Physical DCs in main datacenter
- Virtual DCs (if no physical DCs)
- Branch office RODCs
- All AD FS servers
- All AD CS servers
- Entra Connect servers
```

**Alert Tuning:**

```
Recommended Exclusions (Examples):

1. Authorized Security Tools
   Alert: Account enumeration reconnaissance
   Exclude: VulnerabilityScanner service account
   Reason: Authorized vulnerability scanning

2. Legacy Applications
   Alert: NTLM authentication
   Exclude: Application: OldERPSystem
   Reason: Legacy app cannot use Kerberos

3. Service Accounts
   Alert: Logon from unusual location
   Exclude: ServiceAccount1
   Reason: Service runs in different datacenter

Document ALL exclusions with:
- Business justification
- Approval
- Review date (annually)
```

**Entity Tagging:**

```
Tagging Strategy:

Sensitive Accounts:
- Domain Admins members
- Enterprise Admins members
- Service accounts with elevated privileges
- VIP user accounts
- Break-glass emergency accounts

Honeytoken Accounts:
- 5-10 fake accounts across tiers
- Realistic names
- Credentials "exposed" strategically
- Monitored 24/7

Custom Tags:
- "Tier 0" - Domain admin level
- "Tier 1" - Server admin level
- "Tier 2" - Workstation admin level
- "VIP" - Executive accounts
- "External" - Vendor accounts
```

### 13.3 Performance Optimization

**Sensor Performance:**

MDI sensor is designed to have minimal impact:
- Reserves 15% of CPU and memory max
- Automatically throttles if exceeding
- No noticeable performance impact

**If Performance Issues:**

```
Troubleshooting:

1. Check sensor health
   Settings → Identities → Sensors
   Look for "Dropped port mirrored network traffic" alert

2. Verify hardware resources
   - CPU: 4+ cores recommended
   - RAM: 10+ GB recommended
   - Network: 1+ Gbps

3. Reduce sensor load (if needed)
   - Deploy sensor to more DCs (distribute load)
   - Exclude non-critical event IDs (not recommended)
   - Add more RAM to DC

4. Check for issues
   - Antivirus scanning sensor files (exclude)
   - Other monitoring tools conflicting
   - Network capture issues
```

**Network Traffic:**

```
MDI Network Usage:

Inbound (to sensor):
- Minimal (queries to AD)
- LDAP: < 1 Mbps
- Event logs: Local read (no network)

Outbound (to cloud):
- Parsed metadata only
- Typical: 1-5 Mbps per DC
- Peak: 10 Mbps during initial sync
- Compressed and encrypted

Bandwidth Recommendations:
- Small org (<1000 users): 5 Mbps
- Medium org (1000-10000 users): 10 Mbps
- Large org (>10000 users): 20+ Mbps
```

### 13.4 Multi-Forest Best Practices

**Architecture:**

```
Multi-Forest Deployment:

Forest A (corp.contoso.com)    Forest B (dev.contoso.com)
├─ DC01 (Sensor)               ├─ DC05 (Sensor)
├─ DC02 (Sensor)               └─ DC06 (Sensor)
│                              │
└───── Two-way Trust ──────────┘
              │
              ↓
       Single MDI Workspace
       (security.microsoft.com)
```

**Best Practices:**

```
1. Single Workspace for All Forests
   ✅ Easier management
   ✅ Unified view of threats
   ✅ Cross-forest attack detection

2. Sensor in Each Forest
   ✅ Deploy sensors to ALL DCs in ALL forests
   ✅ Use same workspace access key

3. Trust Relationships Required
   ✅ Two-way trust: Full visibility
   ⚠️ One-way trust: Limited visibility
   ❌ No trust: Cannot detect cross-forest attacks

4. DSA Account per Forest
   ✅ Create DSA/gMSA in each forest
   ✅ Grant permissions in each forest
   ✅ Configure in workspace settings

5. Test Cross-Forest Detection
   ✅ Authenticate from Forest A to Forest B
   ✅ Verify MDI sees cross-forest activity
   ✅ Test lateral movement detection
```

### 13.5 Compliance and Regulatory Considerations

**Data Residency:**

```
MDI Data Centers (2025):

Available Regions:
├─ United States
├─ Europe
├─ United Kingdom
├─ Australia
├─ Asia Pacific
├─ Canada
├─ India
└─ UAE (🆕 2025)

Data Storage:
- Workspace data stored in selected region
- Cannot change region after creation
- Choose region during workspace creation
```

**Compliance Standards:**

MDI helps meet requirements for:

```
Standards:
├─ ISO 27001 (Information Security)
├─ SOC 2 Type II
├─ GDPR (EU Data Protection)
├─ HIPAA (Healthcare)
├─ PCI-DSS (Payment Card Industry)
├─ NIST CSF (Cybersecurity Framework)
└─ FedRAMP (US Government)

How MDI Helps:
├─ Detect unauthorized access (AC-2)
├─ Monitor privileged account usage (AU-6)
├─ Alert on anomalous behavior (SI-4)
└─ Audit trail of investigations (AU-12)
```

**Data Retention:**

```
MDI Data Retention:

Alerts: 90 days in M365 Defender portal
Timeline: 6 months per entity
Advanced Hunting: 30 days

Long-term Retention:
→ Export to Sentinel (1-2+ years)
→ Export to SIEM (configurable)
→ Archive via API (permanent)
```

### 13.6 Regular Maintenance Tasks

**Daily:**
```
☐ Review new alerts
☐ Investigate high/critical alerts
☐ Check sensor health status
☐ Verify no health issues
```

**Weekly:**
```
☐ Review alert trends
☐ Update incident documentation
☐ Check for new ISPMs
☐ Review lateral movement paths
☐ Verify honeytoken accounts intact
```

**Monthly:**
```
☐ Review and tune false positives
☐ Update exclusions (if needed)
☐ Analyze metrics (MTTD, MTTR, etc.)
☐ Review entity tags (still accurate?)
☐ Check for sensor updates
☐ Backup workspace configuration
```

**Quarterly:**
```
☐ Full ISPM review and remediation
☐ Lateral movement path reduction
☐ Honeytoken rotation (optional)
☐ Review SOC training needs
☐ Update playbooks based on incidents
☐ Conduct tabletop exercise
```

**Annually:**
```
☐ Full security posture assessment
☐ Review all configuration settings
☐ Update entity tags comprehensively
☐ Review and update exclusions
☐ Conduct penetration test
☐ Review compliance requirements
☐ Reset krbtgt password (TWICE!)
☐ ITDR maturity assessment
```

**🎯 Exam Tip:** For SC-200, focus on **configuration** (how to set up sensors, entity tags, exclusions) and **operational tasks** (investigate alerts, review ISPMs, remediate threats). Day-to-day maintenance is less tested.

---

## 14. Troubleshooting Common Issues

### 14.1 Sensor Installation Issues

**Issue 1: Sensor Installation Fails**

**Symptoms:**
- Setup.exe crashes or hangs
- Error message during installation
- Sensor service won't start

**Common Causes:**

```
1. Missing Prerequisites
   ✓ .NET Framework 4.7+ not installed
   ✓ Insufficient disk space
   ✓ Antivirus blocking installer

2. Access Key Issues
   ✓ Invalid access key
   ✓ Access key expired
   ✓ Copy/paste error (extra spaces)

3. Permission Issues
   ✓ Not running as Administrator
   ✓ Group Policy blocking installation
   ✓ AppLocker/WDAC blocking
```

**Troubleshooting Steps:**

```powershell
# 1. Verify .NET version
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" | Select-Object Release

# Release should be >= 461808 (.NET 4.7.2)

# 2. Check available disk space
Get-PSDrive C | Select-Object Used, Free

# Should have at least 10 GB free

# 3. Verify service account can log on
Test-ADServiceAccount MDI_gMSA$

# 4. Check installation logs
Get-Content "C:\ProgramData\Microsoft\Azure ATP Sensor\Logs\Setup.log" -Tail 50

# 5. Verify network connectivity
Test-NetConnection -ComputerName "triprd1wcusso1sensorapi.atp.azure.com" -Port 443
```

**Resolution:**

```
1. Install prerequisites:
   - .NET Framework 4.8 (recommended)
   - Latest Windows updates

2. Temporarily disable antivirus during installation

3. Get fresh access key from portal

4. Run installer as Administrator:
   Azure ATP sensor Setup.exe /quiet AccessKey=<key>

5. Check Event Viewer:
   Applications and Services Logs → Azure Advanced Threat Protection
```

---

**Issue 2: Sensor Shows "Disconnected"**

**Symptoms:**
- Sensor status: Disconnected in portal
- No data flowing
- Last seen: Hours or days ago

**Common Causes:**

```
1. Network Connectivity
   ✓ Firewall blocking *.atp.azure.com
   ✓ Proxy not configured
   ✓ DNS resolution failing
   ✓ Internet connection down

2. Service Issues
   ✓ Sensor service stopped
   ✓ Service crashed
   ✓ Insufficient permissions

3. Certificate Issues
   ✓ Certificate expired
   ✓ Certificate revocation check failing
   ✓ TLS 1.2 not enabled
```

**Troubleshooting:**

```powershell
# 1. Check sensor service
Get-Service AATPSensor

# Should be Running
# If not:
Start-Service AATPSensor

# 2. Test connectivity
Test-NetConnection -ComputerName "triprd1wcusso1sensorapi.atp.azure.com" -Port 443

# 3. Check DNS resolution
Resolve-DnsName "*.atp.azure.com"

# 4. Review sensor logs
Get-Content "C:\Program Files\Azure Advanced Threat Protection Sensor\VERSION\Logs\*" -Tail 100 | Select-String -Pattern "Error", "Warning"

# 5. Verify proxy configuration
netsh winhttp show proxy

# 6. Test with MDI Client Analyzer
# Download from Microsoft
# https://aka.ms/MDIClientAnalyzer
.\MDIClientAnalyzer.cmd
```

**Resolution:**

```
1. Fix network issues:
   - Allow *.atp.azure.com:443 in firewall
   - Configure proxy if needed
   - Enable TLS 1.2

2. Restart sensor service:
   Restart-Service AATPSensor -Force

3. Check event logs for specific errors

4. If persistent, uninstall and reinstall sensor

5. Contact Microsoft Support if needed
```

---

### 14.2 Detection Issues

**Issue 3: No Alerts Generating**

**Symptoms:**
- Sensor installed and running
- No alerts in portal
- Expected attacks not detected

**Common Causes:**

```
1. Event Auditing Not Configured
   ✓ Required events not enabled
   ✓ Event ID 4662 not auditing
   ✓ Advanced Audit Policy not configured

2. Sensor Not Capturing Traffic
   ✓ Network interface not monitored
   ✓ Port mirroring issue
   ✓ "Dropped network traffic" health alert

3. Test Mode Enabled
   ✓ Recommended test mode reducing alerts
   ✓ Thresholds too high

4. Legitimate Traffic Only
   ✓ No actual attacks occurring
   ✓ Environment too quiet
```

**Troubleshooting:**

```powershell
# 1. Verify event auditing
auditpol /get /category:*

# Should show "Success and Failure" for:
# - Kerberos Authentication Service
# - Kerberos Service Ticket Operations
# - Directory Service Access

# 2. Generate test event
# Try Kerberos authentication from another machine

# 3. Check if test mode is enabled
# Portal: Settings → Detection tuning → Test mode

# 4. Verify sensor is processing events
# Portal: Settings → Sensors → Select sensor
# Check "Events per second" metric (should be > 0)

# 5. Check for health alerts
# Settings → Health issues
# Look for "Dropped port mirrored network traffic"
```

**Resolution:**

```
1. Configure event auditing:
   # Use MDI PowerShell module
   Set-MDIConfiguration -Mode Domain -Configuration All

2. Disable test mode (after initial 30 days)

3. Generate test alert (safely):
   # Perform reconnaissance activity
   # Tools like ADExplorer, PowerView (test environment only!)

4. Verify data flow:
   # Check entity timeline shows activity
   # Verify authentication events appear

5. If still no alerts:
   # Check that you're looking in correct workspace
   # Verify license is active
   # Contact Microsoft Support
```

---

**Issue 4: Too Many False Positives**

**Symptoms:**
- Alert volume overwhelming
- Many false positive alerts
- SOC team ignoring alerts

**Common Causes:**

```
1. Legitimate But Unusual Activity
   ✓ Security tools (vulnerability scanners)
   ✓ Admin tools (ADExplorer, PowerShell)
   ✓ Service accounts with legitimate unusual behavior

2. Environment-Specific Behavior
   ✓ Legacy applications using NTLM
   ✓ Scheduled tasks running queries
   ✓ Multi-forest trust authentication patterns

3. Tuning Not Applied
   ✓ No exclusions configured
   ✓ Default thresholds too sensitive
   ✓ Test mode not used initially
```

**Resolution:**

```
1. Use Recommended Test Mode (first 30 days)
   Settings → Detection tuning → Enable test mode
   Expiration: 30-60 days

2. Create Targeted Exclusions
   For each false positive:
   - Document why it's false positive
   - Get approval to exclude
   - Create specific exclusion (not broad)
   - Set expiration date
   - Review quarterly

3. Adjust Alert Thresholds (if available)
   Example: Brute force threshold from 10 to 20 attempts

4. Tag Authorized Tools
   - Service accounts for vulnerability scanners
   - Admin accounts used for legitimate queries

5. Improve Security Hygiene
   - Fix issues causing alerts (e.g., migrate from NTLM)
   - Rather than just excluding alerts
```

---

### 14.3 Performance Issues

**Issue 5: High CPU/Memory on Domain Controller**

**Symptoms:**
- DC CPU usage high (>80%)
- DC memory usage high (>80%)
- DC performance sluggish
- Health alert: "Sensor performance issue"

**Common Causes:**

```
1. Insufficient Resources
   ✓ DC undersized for workload
   ✓ Only 2 cores or 4 GB RAM

2. Other Services Competing
   ✓ Antivirus doing full scan
   ✓ Backup running
   ✓ Other monitoring tools

3. Sensor Issue
   ✓ Sensor bug (rare)
   ✓ Sensor not self-throttling
```

**Troubleshooting:**

```powershell
# 1. Check sensor resource usage
Get-Process | Where-Object {$_.ProcessName -like "*ATP*"} | Select-Object ProcessName, CPU, WorkingSet

# Sensor should use < 15% CPU and memory

# 2. Check for competing processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# 3. Verify DC specifications
Get-WmiObject Win32_ComputerSystem | Select-Object TotalPhysicalMemory, NumberOfLogicalProcessors

# Minimum: 4 cores, 8 GB RAM
# Recommended: 8+ cores, 16+ GB RAM

# 4. Check event log processing
Get-EventLog -LogName Security -Newest 1000 | Measure-Object
# High event volume can increase processing

# 5. Check network capture
# Portal: Settings → Sensors → Select sensor
# Look for "Dropped network traffic" (indicates overload)
```

**Resolution:**

```
1. Add Resources to DC
   - Add RAM (cheapest, most effective)
   - Add CPU cores
   - Add disk speed (SSD for logs)

2. Distribute Load
   - Deploy sensor to more DCs
   - Each sensor handles less traffic

3. Exclude Sensor from Antivirus Scans
   Exclude:
   - C:\Program Files\Azure Advanced Threat Protection Sensor
   - Sensor process: Microsoft.Tri.Sensor.exe

4. Schedule Resource-Intensive Tasks
   - Run backups during off-hours
   - Schedule AV scans at night
   - Stagger across DCs

5. Monitor and Tune
   - Watch CPU/memory trends
   - Set alerts if exceeds 80%
   - Plan capacity accordingly
```

---

### 14.4 Data and Visibility Issues

**Issue 6: Entity Not Showing in Portal**

**Symptoms:**
- User or computer exists in AD
- Not visible in MDI portal
- Cannot search for entity

**Common Causes:**

```
1. Synchronization Delay
   ✓ New entity, not yet synced
   ✓ Sync happens every 30 minutes

2. Sensor Not on All DCs
   ✓ Entity authenticated to DC without sensor
   ✓ Missing coverage

3. Deleted Entity
   ✓ Entity deleted from AD
   ✓ Still in MDI but marked deleted
```

**Resolution:**

```
1. Wait for sync (30 minutes)

2. Force entity sync:
   # No direct way to force
   # Trigger activity from entity (authenticate)

3. Verify sensor coverage:
   # Ensure sensors on ALL DCs
   # Entity must authenticate to DC with sensor

4. Check entity status in AD:
   Get-ADUser -Identity "john.doe"
   # Ensure Enabled = True
```

---

**Issue 7: Timeline Shows No Activity**

**Symptoms:**
- Entity exists in portal
- Timeline tab is empty
- No authentication events shown

**Common Causes:**

```
1. No Activity
   ✓ User hasn't logged in
   ✓ Computer hasn't authenticated

2. Activity Not Captured
   ✓ Sensor not on all DCs
   ✓ Event auditing not configured
   ✓ Sensor health issues

3. Time Range Issue
   ✓ Looking at wrong date range
   ✓ Activity older than retention (6 months)
```

**Resolution:**

```
1. Verify entity has been active:
   # Check AD last logon
   Get-ADUser -Identity "john.doe" -Properties LastLogonDate

2. Adjust timeline date range:
   # Expand from default (Last 30 days) to Last 6 months

3. Verify event auditing:
   auditpol /get /category:*

4. Check sensor health:
   # Settings → Sensors → Verify all healthy

5. Generate activity:
   # Have user log in
   # Wait 5-10 minutes
   # Check timeline again
```

---

### 14.5 Alert and Incident Issues

**Issue 8: Alerts Not Creating Incidents**

**Symptoms:**
- Alerts appear in queue
- No incident created
- Alerts not correlated

**Common Causes:**

```
1. Severity Too Low
   ✓ Only Medium/High/Critical create incidents
   ✓ Low/Informational alerts don't auto-create incidents

2. Incident Already Exists
   ✓ Alert added to existing incident
   ✓ Check existing incidents

3. Correlation Disabled
   ✓ Advanced feature toggle off
```

**Resolution:**

```
1. Check alert severity:
   # Only Medium/High/Critical auto-create incidents

2. Search existing incidents:
   # Incidents → Search by entity or time

3. Manually create incident (if needed):
   # Select alert(s) → Create incident

4. Verify incident creation settings:
   # Settings → Incidents → Auto-creation enabled
```

---

**Issue 9: Cannot Take Response Actions**

**Symptoms:**
- "Disable account" button greyed out
- Actions fail with permission error
- Cannot execute remediation

**Common Causes:**

```
1. Insufficient Permissions
   ✓ User lacks Security Administrator role
   ✓ URBAC not configured properly

2. Account Type Restriction
   ✓ Cannot disable cloud-only accounts from MDI
   ✓ Cannot disable break-glass accounts

3. Technical Issue
   ✓ No writable DC available
   ✓ Network connectivity issue
```

**Resolution:**

```
1. Verify permissions:
   # Azure AD → Roles and administrators
   # Verify user has "Security Administrator" role

2. Check account type:
   # On-prem AD accounts: Can disable
   # Azure AD-only accounts: Cannot disable via MDI

3. Alternative method (PowerShell):
   Disable-ADAccount -Identity "compromised-user"

4. Check URBAC configuration (if new tenant):
   # Settings → Permissions → URBAC
```

---

### 14.6 Getting Help

**Self-Service Resources:**

```
1. Microsoft Learn Documentation
   https://learn.microsoft.com/defender-for-identity/

2. Microsoft Community
   https://techcommunity.microsoft.com/

3. Microsoft Q&A
   https://learn.microsoft.com/answers/

4. MDI Release Notes
   https://learn.microsoft.com/defender-for-identity/whats-new

5. Status Page
   https://status.microsoft.com/
```

**Contact Support:**

```
When to Contact Microsoft Support:
├─ Sensor consistently disconnecting
├─ Persistent health issues
├─ Data loss or corruption
├─ Bug suspected
├─ License or billing issues
└─ Advanced configuration help

How to Open Support Ticket:
1. Microsoft 365 Admin Center
2. Support → New service request
3. Select: Security → Defender for Identity
4. Describe issue with details:
   - Error messages
   - Screenshots
   - Logs (sensor logs, event logs)
   - Troubleshooting already done
5. Submit
```

**🎯 Exam Tip:** For SC-200, focus on **common issues** (sensor disconnected, false positives, missing events) and **basic troubleshooting** (check service, verify auditing, test connectivity). Advanced troubleshooting is less tested.

---

## 15. Exam Tips and Practice Questions

### 15.1 Key Exam Topics for MDI

**Must-Know Concepts:**

✅ **Sensor Deployment**
- v2.x (Classic) vs v3.x (Unified)
- Cannot mix v2 and v3
- v3 requires Server 2019+, MDE deployed, DC only
- v2 supports all (DC, AD FS, AD CS, Entra Connect)

✅ **Alert Types by Kill Chain**
- Reconnaissance: Account enumeration, Network mapping
- Credential Access: Brute force, Kerberoasting, AS-REP Roasting
- Lateral Movement: Pass-the-hash, Pass-the-ticket
- Domain Dominance: Golden Ticket, DCSync, DCShadow

✅ **ISPMs (Security Posture)**
- Proactive recommendations
- Fix before attack
- Integrated with Secure Score

✅ **Lateral Movement Paths**
- Show potential attack paths
- Remediate by reducing admin sessions on workstations
- Use admin tiering, PAWs, LAPS

✅ **Honeytokens**
- Fake accounts tagged in MDI
- Zero false positives
- Any usage = High severity alert

✅ **Integration**
- M365 Defender: Unified incidents
- Sentinel: Data connector
- Advanced Hunting: IdentityLogonEvents, IdentityQueryEvents, etc.

### 15.2 Common Exam Question Types

**Type 1: Scenario-Based (Which alert will trigger?)**

Example:
```
Scenario: An attacker uses Mimikatz to extract password hashes from a
domain controller and then uses the krbtgt hash to create a forged
Kerberos ticket with a 10-year lifetime.

Which MDI alert will be triggered?

A. Suspected Kerberoasting attack
B. Suspected Golden Ticket usage (ticket anomaly)
C. Suspected DCSync attack
D. Suspected AS-REP Roasting attack

✅ Correct Answer: B
Explanation: Forged ticket with abnormal lifetime = Golden Ticket
```

**Type 2: Configuration (How to set up?)**

Example:
```
You need to configure accounts for attackers to exploit.
From Entity tags, what should you add?

A. Sensitive account
B. Honeytoken account
C. External account
D. Service account

✅ Correct Answer: B
Explanation: Honeytoken = Decoy account for attacker detection
```

**Type 3: Troubleshooting**

Example:
```
Sensor status shows "Disconnected" in the portal.
What should you check first?

A. Event auditing configuration
B. Network connectivity to *.atp.azure.com
C. Entity tags configuration
D. Alert tuning settings

✅ Correct Answer: B
Explanation: Disconnected = Network connectivity issue most likely
```

**Type 4: KQL Hunting**

Example:
```
You need to find users who authenticated from multiple countries
within the same hour. Which table should you query?

A. IdentityQueryEvents
B. IdentityDirectoryEvents
C. IdentityLogonEvents
D. DeviceLogonEvents

✅ Correct Answer: C
Explanation: IdentityLogonEvents contains authentication events with location data
```

**Type 5: Integration**

Example:
```
How does MDI integrate with Microsoft 365 Defender?

A. Via API connector
B. Native integration (built-in)
C. Via SIEM connector
D. Requires third-party tool

✅ Correct Answer: B
Explanation: MDI is natively integrated in M365 Defender portal
```

### 15.3 Practice Questions

#### **Question 1: Sensor Deployment**

You need to deploy Microsoft Defender for Identity sensors in your environment:
- 4 Domain Controllers running Windows Server 2022
- 2 AD FS servers running Windows Server 2019
- 1 AD CS server running Windows Server 2016

All servers have Microsoft Defender for Endpoint deployed.

Which sensor version should you use?

A. Sensor v3.x (Unified) on all servers
B. Sensor v2.x (Classic) on all servers
C. Sensor v3.x on DCs, v2.x on AD FS and AD CS
D. Sensor v2.x on DCs, v3.x on AD FS and AD CS

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Sensor v2.x (Classic) on all servers**

**Explanation:**
- v3.x only supports Domain Controllers (not AD FS or AD CS)
- Cannot mix v2.x and v3.x in same environment
- Must use v2.x for ALL servers when AD FS or AD CS present
- v2.x works on all server types

**Key Rule:** If you need to protect AD FS or AD CS, use v2.x everywhere.
</details>

---

#### **Question 2: Alert Investigation**

You receive the following alert:

```
Alert: Suspected DCSync attack
Severity: Critical
Account: CONTOSO\compromised-admin
Activity: Directory replication from DC01.contoso.com
Objects replicated: krbtgt, Administrator, 500+ accounts
```

What should be your FIRST response action?

A. Reset passwords for all replicated accounts
B. Disable the compromised-admin account immediately
C. Reset krbtgt password twice
D. Run antivirus scan on DC01

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Disable the compromised-admin account immediately**

**Explanation:**
Order of operations for DCSync:
1. **FIRST: Disable compromised account** (stop ongoing attack)
2. Then: Reset krbtgt password (twice, 24 hours apart)
3. Then: Reset passwords for all admin accounts
4. Then: Hunt for Golden Ticket usage
5. Finally: Investigate how account was compromised

**Why B is correct:**
- Immediate containment stops attacker access
- Must stop active replication before remediation
- Disabling account takes seconds
- Resetting krbtgt is critical but takes longer to plan
</details>

---

#### **Question 3: Lateral Movement Paths**

You review lateral movement paths and find the following path:

```
[StandardUser on WKS-001] → [Has local admin on SRV-001] →
[ITAdmin has session on SRV-001] → [ITAdmin can access DC-001]
```

Which action will MOST effectively break this attack path?

A. Remove StandardUser's local admin rights on SRV-001
B. Force ITAdmin to log off from SRV-001
C. Deploy LAPS to randomize local admin passwords
D. Implement policy: ITAdmin cannot log in to member servers

<details>
<summary>Click to see answer</summary>

**✅ Answer: D - Implement policy: ITAdmin cannot log in to member servers**

**Explanation:**
- **A** breaks one path, but StandardUser could regain access
- **B** is temporary; ITAdmin will log in again
- **C** is good (LAPS) but doesn't address ITAdmin session exposure
- **D** prevents root cause: Admin shouldn't have sessions on member servers

**Best Practice:** Admin Tiering
- Tier 0 (Domain admins) → Only login to DCs
- Tier 1 (Server admins) → Only login to servers  
- Tier 2 (Workstation admins) → Only login to workstations

This prevents credential exposure on lower-tier systems.
</details>

---

#### **Question 4: Honeytokens**

You create a user account named "backup_admin" for honeytoken purposes.

What must you do to make this work as a honeytoken in MDI?

A. Disable the account in Active Directory
B. Tag the account as "Honeytoken account" in MDI portal
C. Add the account to a honeypot group
D. Configure DNS entry for the account

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Tag the account as "Honeytoken account" in MDI portal**

**Explanation:**
- MDI must KNOW the account is a honeytoken
- Without the tag, MDI treats it as a normal account
- Tagging tells MDI: "ANY activity from this account = Alert"

**Steps:**
1. Create account in AD (enabled, with password)
2. MDI portal → Search account → Entity profile
3. Manage tags → Select "Honeytoken account"
4. "Expose" credentials (saved credentials, scripts, etc.)

**Why not A?**
- Disabled accounts can't authenticate (honeytoken won't work)
- Account should be ENABLED but never used legitimately
</details>

---

#### **Question 5: Advanced Hunting**

You need to create a KQL query to find all authentication failures in the last 24 hours for accounts in the "Domain Admins" group.

Which query should you use?

A.
```kql
IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| where AccountName contains "Admin"
```

B.
```kql
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| where AccountUpn in (
    IdentityInfo
    | where GroupMembership has "Domain Admins"
    | distinct AccountUpn
)
```

C.
```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonStatus == "Failed"
| where AccountName has "Domain Admins"
```

D.
```kql
IdentityQueryEvents
| where Timestamp > ago(1d)
| where Query has "Domain Admins"
```

<details>
<summary>Click to see answer</summary>

**✅ Answer: B**

**Explanation:**
- **A:** Wrong - "contains Admin" is too broad (matches any admin-like name)
- **B:** Correct - Joins IdentityLogonEvents with IdentityInfo to get actual Domain Admins group members
- **C:** Wrong - DeviceLogonEvents is MDE (endpoint logons), not MDI (AD authentication)
- **D:** Wrong - IdentityQueryEvents is for LDAP queries, not authentication failures

**Key Points:**
- Use `IdentityLogonEvents` for authentication events (MDI)
- Use `IdentityInfo` to get group membership
- `ago(1d)` and `ago(24h)` are equivalent
- Join tables to correlate data
</details>

---

#### **Question 6: ISPMs**

You see the following Identity Security Posture Assessment:

```
Recommendation: Unsecure Kerberos delegation
Severity: High
Affected: 5 service accounts
Risk: Allows lateral movement attacks
```

What should you do to remediate?

A. Disable Kerberos delegation entirely for all accounts
B. Configure constrained delegation with protocol transition only
C. Enable Kerberos encryption for all accounts
D. Add accounts to Protected Users group

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Configure constrained delegation with protocol transition only**

**Explanation:**

**Kerberos Delegation Types:**
1. **Unconstrained** (Insecure) ⚠️
   - Service can delegate to ANY service
   - Attacker can impersonate users to any system
   
2. **Constrained** (Better) ✓
   - Service can only delegate to specific services
   - Limits attack surface
   
3. **Constrained with Protocol Transition** (Best) ✅
   - Most secure
   - Allows delegation from non-Kerberos protocols
   - Limits delegation scope

**Why not A?**
- Many applications legitimately need delegation
- Disabling entirely may break functionality

**Why not D?**
- Protected Users blocks delegation entirely
- May break service accounts that need it
- Use constrained delegation instead
</details>

---

#### **Question 7: Integration**

You need to investigate a multi-stage attack involving phishing, endpoint compromise, and lateral movement using stolen credentials.

Which Microsoft 365 Defender portal features should you use? (Select TWO)

A. Unified incident queue showing correlated alerts
B. Advanced hunting across all products
C. Device isolation from MDE
D. LDAP query logs from MDI only

<details>
<summary>Click to see answer</summary>

**✅ Answers: A and B**

**Explanation:**

**A. Unified incident queue** ✓
- Correlates alerts from MDO (phishing), MDE (endpoint), MDI (lateral movement)
- Shows complete attack story
- Single investigation workflow

**B. Advanced hunting** ✓
- Query data from all products in one place
- Correlate email events, endpoint activity, identity authentication
- Find full attack chain

**Why not C?**
- Device isolation is a response action, not investigation feature
- Useful AFTER investigation

**Why not D?**
- LDAP query logs alone won't show full attack
- Need cross-product visibility

**Cross-Product Investigation:**
```kql
// Example query correlating all products
let PhishingEmail = EmailEvents
| where ThreatTypes has "Phish"
| project EmailTime=Timestamp, RecipientEmailAddress;

let EndpointCompromise = DeviceProcessEvents
| where FileName == "mimikatz.exe"
| project EndpointTime=Timestamp, AccountName;

let LateralMovement = IdentityLogonEvents
| where ActionType == "LogonSuccess"
| where Protocol == "NTLM"
| project IdentityTime=Timestamp, AccountName;

// Join all together
PhishingEmail
| join (EndpointCompromise) on $left.RecipientEmailAddress == $right.AccountName
| join (LateralMovement) on AccountName
```
</details>

---

#### **Question 8: MITRE ATT&CK**

An alert shows:

```
Alert: Suspected Golden Ticket usage (encryption downgrade)
Technique: T1558.001
```

What does T1558.001 represent in MITRE ATT&CK?

A. Kerberoasting
B. Steal or Forge Kerberos Tickets: Golden Ticket
C. Pass-the-Hash
D. DCSync

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Steal or Forge Kerberos Tickets: Golden Ticket**

**Explanation:**

**MITRE ATT&CK Identity Techniques (Exam Focus):**

| Technique ID | Name | Alert in MDI |
|--------------|------|--------------|
| **T1558.001** | Golden Ticket | Suspected Golden Ticket usage |
| **T1558.003** | Kerberoasting | Suspected Kerberoasting attack |
| **T1558.004** | AS-REP Roasting | Suspected AS-REP Roasting attack |
| **T1003.006** | DCSync | Suspected DCSync attack |
| **T1550.002** | Pass the Hash | Suspected identity theft (pass-the-hash) |
| **T1550.003** | Pass the Ticket | Suspected identity theft (pass-the-ticket) |
| **T1110.001** | Password Guessing | Suspected brute force attack |
| **T1110.003** | Password Spraying | Suspected password spray attack |

**Golden Ticket Indicators:**
- Forged TGT using stolen krbtgt hash
- Abnormal encryption (RC4 when user has AES)
- Excessive lifetime (10 years vs 10 hours)
- Ticket for deleted/non-existent user
</details>

---

#### **Question 9: Troubleshooting**

After deploying MDI sensors, you notice no alerts are being generated.

In what order should you troubleshoot?

1. Check for test mode enabled
2. Verify sensor service is running
3. Confirm event auditing is configured
4. Generate test authentication event

A. 2, 3, 1, 4
B. 1, 2, 3, 4
C. 2, 3, 4, 1
D. 3, 2, 1, 4

<details>
<summary>Click to see answer</summary>

**✅ Answer: A - 2, 3, 1, 4**

**Explanation:**

**Troubleshooting Order (Most to Least Likely):**

**1. Verify sensor service running (2)**
- Most basic check
- If service stopped, nothing works
- Quick to verify: `Get-Service AATPSensor`

**2. Confirm event auditing configured (3)**
- Second most common issue
- MDI requires specific event IDs (4776, 4768, 4769, 4662)
- Check: `auditpol /get /category:*`

**3. Check test mode (1)**
- Test mode reduces alerts (by design)
- Common after initial deployment
- Portal: Settings → Detection tuning

**4. Generate test event (4)**
- Only after confirming everything is configured
- Validates entire pipeline
- Safest test: Simple authentication from another machine

**Why This Order?**
- Start with simplest, most likely issues
- Work from infrastructure → configuration → validation
- Don't generate test events until infrastructure is verified
</details>

---

#### **Question 10: Response Actions**

You detect a pass-the-hash attack involving the account "CONTOSO\admin-user".

Which response actions should you take? (Select ALL that apply)

A. Disable admin-user account
B. Force password reset for admin-user
C. Isolate the source device
D. Reset krbtgt password
E. Review where admin-user credentials were exposed

<details>
<summary>Click to see answer</summary>

**✅ Correct Answers: A, B, C, E**

**Explanation:**

**A. Disable account** ✓
- Immediately stops attacker access
- Prevents further pass-the-hash usage
- First containment step

**B. Force password reset** ✓
- Changes NTLM hash (invalidates stolen hash)
- After disabling account (to ensure user gets new password)
- Required for full remediation

**C. Isolate source device** ✓
- Contains the compromised endpoint
- Prevents lateral movement
- Allows forensic investigation

**D. Reset krbtgt** ✗
- Only needed for Golden Ticket (not pass-the-hash)
- Pass-the-hash uses NTLM hash, not krbtgt
- Overkill for this scenario (major impact on domain)

**E. Review credential exposure** ✓
- Find WHERE credentials were stolen (which device?)
- Identify HOW they were stolen (Mimikatz? Dump? Cached?)
- Prevent recurrence (fix credential hygiene)

**Response Workflow:**
```
1. Contain (A, C)
   ├─ Disable account (stops attacker)
   └─ Isolate device (preserves forensics)

2. Investigate (E)
   ├─ How were credentials stolen?
   ├─ What else did attacker access?
   └─ Are other accounts compromised?

3. Remediate (B)
   ├─ Reset password (invalidates hash)
   ├─ Remove persistence mechanisms
   └─ Fix vulnerability

4. Recover
   ├─ Re-enable account (with new password)
   ├─ Release device from isolation (after cleanup)
   └─ Monitor for recurrence
```
</details>

---

### 15.4 Final Exam Tips

**Last-Minute Review:**

✅ **Sensor Deployment**
- v2 vs v3 differences
- v3 limitations (DC only, Server 2019+, preview)
- Cannot mix v2 and v3

✅ **Alert Types (Memorize Top 10)**
1. DCSync (Critical)
2. Golden Ticket (Critical)
3. Pass-the-Hash (High)
4. Kerberoasting (High)
5. AS-REP Roasting (High)
6. Brute Force (Medium)
7. Password Spray (Medium)
8. Account Enumeration (Low)
9. Honeytoken Usage (High)
10. DCShadow (Critical)

✅ **ISPMs**
- Proactive (prevent attacks)
- Integrated with Secure Score
- Remediate Critical/High within 30 days

✅ **Lateral Movement Paths**
- Show potential attack paths
- Remediate by breaking paths:
  - Remove admin sessions from workstations
  - Implement admin tiering
  - Deploy LAPS
  - Use PAWs

✅ **Honeytokens**
- Must be tagged in MDI portal
- Zero false positives
- Account should be enabled (not disabled)

✅ **Advanced Hunting Tables**
- IdentityLogonEvents - Authentication
- IdentityQueryEvents - LDAP queries
- IdentityDirectoryEvents - AD changes
- IdentityInfo - Entity information

✅ **Integration**
- M365 Defender: Native integration
- Sentinel: Data connector
- Security Copilot: AI assistance
- Automatic attack disruption: Cross-product

**Exam Day Strategy:**

1. **Read questions carefully**
   - Look for keywords: "FIRST", "BEST", "MOST", "LEAST"
   - Note: "Which TWO..." or "Select ALL that apply"

2. **Eliminate wrong answers**
   - Cross out obviously wrong choices
   - Narrow to 2 options
   - Choose best answer

3. **Watch for traps**
   - v2 vs v3 confusion
   - DCSync vs Golden Ticket
   - ISPMs vs Alerts (proactive vs reactive)
   - MDE tables vs MDI tables

4. **Time management**
   - ~40-60 questions in 100 minutes
   - ~1.5-2 minutes per question
   - Flag difficult questions
   - Return to flagged questions at end

5. **Trust your preparation**
   - First instinct usually correct
   - Don't overthink
   - If studied properly, you know this!

---

**🎉 Congratulations! You've completed Module 2: Microsoft Defender for Identity!**

**Next Steps:**
1. Review any sections you found challenging
2. Practice the KQL queries
3. Try hands-on labs (if available)
4. Take practice exams
5. Schedule your SC-200 exam with confidence!

**Good luck! 🚀🎓**

---

**End of Module 2 - Part 2**

*Continue to Module 3: Microsoft Defender for Office 365 for email and collaboration threat protection.*
