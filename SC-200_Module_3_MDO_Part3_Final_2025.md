# SC-200 Study Notes - Module 3: Microsoft Defender for Office 365 (MDO)
## 📧 Part 3 (FINAL): Advanced Features and Exam Mastery

**Continuation from Part 2** - Sections 9-15
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest MDO Updates

---

## 9. Priority Account Protection

### 9.1 Overview

**What is Priority Account Protection?**

Priority Account Protection provides **differentiated security** for high-value targets:
- VIPs (CEO, CFO, Board members)
- High-risk users (Finance, HR, Legal)
- Executive assistants
- Key decision makers

**Why It's Critical:**

```
Statistics:
- 78% of targeted attacks focus on executives
- BEC (Business Email Compromise) targets VIPs
- CEO fraud costs average $130,000 per incident
- Priority accounts = High-impact if compromised

Priority Protection Goals:
├─ Enhanced detection sensitivity
├─ Faster alert escalation
├─ Dedicated monitoring
├─ Specialized reporting
└─ Proactive threat hunting
```

### 9.2 How Priority Account Protection Works

**Architecture:**

```
Priority Account Tagging
│
├─ Tag users as "Priority" (up to 250 accounts)
│
├─ Enhanced Protection Applied:
│  ├─ More aggressive anti-phishing thresholds
│  ├─ Stricter Safe Links/Attachments policies
│  ├─ Lower tolerance for suspicious behavior
│  ├─ Mailbox intelligence focused on VIPs
│  └─ Faster automated investigation (AIR)
│
├─ Visibility Improvements:
│  ├─ Priority tag shown in Threat Explorer
│  ├─ Dedicated priority account reports
│  ├─ Alert priority escalation
│  └─ Incident queue filtering
│
└─ Threat Hunting:
   ├─ Filter by priority accounts
   ├─ Track threats targeting VIPs
   └─ Proactive monitoring
```

### 9.3 Configuring Priority Accounts

**Method 1: Microsoft 365 Admin Center**

```
1. Navigate to: admin.microsoft.com
2. Users → Active users
3. Select user (e.g., CEO)
4. Click on user's profile
5. Account → Priority account
6. Toggle: ON
7. Save changes

Result:
- User tagged as priority
- Enhanced protection automatically applied
- Visible across all security tools
```

**Method 2: Exchange Online PowerShell**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Tag single user as priority
Set-User -Identity "ceo@contoso.com" -IsPriorityAccount $true

# Tag multiple users (bulk)
$priorityUsers = @(
    "ceo@contoso.com",
    "cfo@contoso.com",
    "coo@contoso.com",
    "board-member1@contoso.com"
)

foreach ($user in $priorityUsers) {
    Set-User -Identity $user -IsPriorityAccount $true
    Write-Host "Tagged $user as priority account"
}

# Verify priority accounts
Get-User | Where-Object {$_.IsPriorityAccount -eq $true} | 
    Select-Object DisplayName, UserPrincipalName, IsPriorityAccount
```

**Method 3: CSV Import (Bulk)**

```powershell
# CSV format: Email
# ceo@contoso.com
# cfo@contoso.com

# Import and tag
Import-Csv "C:\priority-accounts.csv" | ForEach-Object {
    Set-User -Identity $_.Email -IsPriorityAccount $true
}
```

### 9.4 Priority Account Policies

**Stricter Policy Configuration:**

```
Recommended Settings for Priority Accounts:

Anti-Phishing Policy:
├─ Name: "Priority Account Protection"
├─ Applied to: CEO, CFO, Board members
├─ Phishing threshold: 3 - More Aggressive
├─ User impersonation: Quarantine message
├─ Domain impersonation: Quarantine message
├─ Mailbox intelligence: Enabled
└─ Safety tips: All enabled

Safe Links Policy:
├─ Name: "Priority Account Links"
├─ Applied to: Priority accounts
├─ Track clicks: Enabled
├─ Allow click-through: DISABLED (no bypass)
├─ Scan URLs in real-time: Enabled
└─ Apply to Teams/Office apps: Enabled

Safe Attachments Policy:
├─ Name: "Priority Account Attachments"
├─ Applied to: Priority accounts
├─ Response: Block (most secure, not Dynamic Delivery)
├─ Redirect on detection: security@contoso.com
└─ Apply if scanning error: Enabled

Anti-Spam Policy:
├─ Name: "Priority Account Spam"
├─ Applied to: Priority accounts
├─ Bulk threshold: 4 (stricter than default 7)
├─ Spam action: Quarantine (not Junk folder)
└─ High confidence spam: Quarantine
```

### 9.5 Priority Account Visibility

**Threat Explorer with Priority Accounts:**

```
Filtering by Priority Accounts:

1. Threat Explorer → Filters
2. Recipient: Filter by priority account
3. OR use Advanced filters:
   - Tags: Priority account

View:
- All threats targeting priority accounts
- Easier identification of VIP-targeted attacks
- Priority badge displayed next to user name

Example Query:
"Show all phishing emails targeting priority accounts in last 30 days"

Result:
┌──────────────────────────────────────────────┐
│ From          | To (Priority) | Subject      │
├──────────────────────────────────────────────┤
│ attacker@evil | CEO 🌟        | Wire transfer│
│ phish@bad     | CFO 🌟        | Password exp │
│ spam@junk     | COO 🌟        | Urgent action│
└──────────────────────────────────────────────┘
🌟 = Priority account indicator
```

**Dedicated Priority Account Report:**

```
Location: 
Defender Portal → Reports → Email & collaboration → 
"Priority account protection" report

Shows:
├─ Threats targeting priority accounts
├─ Top targeted priority users
├─ Attack types (phishing, malware, spam)
├─ Blocked vs. delivered ratio
├─ Trend over time
└─ Comparison to non-priority accounts

Example Metrics:
┌─────────────────────────────────────────────┐
│ Priority Accounts: 25                       │
│ Threats blocked: 156 (last 30 days)        │
│ Avg threats per priority account: 6.2      │
│ Threats delivered: 2 (investigated)        │
│ Most targeted: CFO (23 threats)            │
│ Attack type: 89% Phishing, 11% Malware     │
└─────────────────────────────────────────────┘
```

**Incident Queue:**

```
Priority Account Indicators in Incidents:

1. Incident list shows priority badge
   Incident #12345: Phishing campaign
   Impacted: CEO 🌟, CFO 🌟 (Priority accounts)
   Severity: High → Critical (escalated due to priority accounts)

2. Automated priority escalation
   - Incident severity increased if priority accounts involved
   - Faster SOC response time
   - Enhanced investigation depth

3. Filtering:
   - Filter incidents by priority account involvement
   - Focus on high-impact threats first
```

### 9.6 Monitoring Priority Accounts

**Advanced Hunting for Priority Accounts:**

```kql
// All email to priority accounts (last 7 days)
let PriorityAccounts = 
    IdentityInfo
    | where Tags has "Priority account"
    | distinct AccountUpn;

EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress in (PriorityAccounts)
| project Timestamp, RecipientEmailAddress, SenderFromAddress, 
          Subject, ThreatTypes, DeliveryAction
| order by Timestamp desc

// Phishing attempts against priority accounts
EmailEvents
| where Timestamp > ago(30d)
| where RecipientEmailAddress in (PriorityAccounts)
| where ThreatTypes has_any ("Phish", "Malware")
| summarize Attempts = count(), 
            Blocked = countif(DeliveryAction == "Blocked"),
            Delivered = countif(DeliveryAction == "Delivered")
    by RecipientEmailAddress
| order by Attempts desc

// URL clicks by priority accounts
UrlClickEvents
| where Timestamp > ago(7d)
| where AccountUpn in (PriorityAccounts)
| where ActionType == "ClickBlocked"
| project Timestamp, AccountUpn, Url, ThreatTypes
| order by Timestamp desc
```

**Scheduled Hunting:**

```
Create scheduled query:
1. Advanced hunting → New query
2. Paste query above
3. "Create detection rule"
4. Name: "Priority Account Phishing Attempts"
5. Frequency: Every 1 hour
6. Threshold: 3+ attempts
7. Alert: Create incident
8. Severity: High
9. Save

Result:
- Automatic detection of threats to priority accounts
- Immediate alerting
- Proactive protection
```

### 9.7 Best Practices

**Priority Account Management:**

```
1. Identification (Who should be priority?)
   ✅ Include:
   - C-level executives (CEO, CFO, COO, CTO)
   - Board members
   - Finance team (wire transfer authority)
   - HR leadership (access to PII)
   - Legal counsel
   - Executive assistants (access to exec accounts)
   
   ⚠️ Consider:
   - High-visibility employees (PR, media relations)
   - M&A team (sensitive deals)
   - Product development leadership (IP)
   
   ❌ Don't overuse:
   - Limit to ~250 accounts (system limit)
   - Focus on truly high-value targets
   - Too many "priority" dilutes effectiveness

2. Policy Configuration
   ✅ Stricter than default policies
   ✅ Block (not Dynamic Delivery) for attachments
   ✅ No user click-through on Safe Links
   ✅ Aggressive phishing threshold (Level 3)
   ✅ Lower bulk email tolerance (BCL 4-5)

3. Monitoring and Review
   ✅ Daily review of priority account threats
   ✅ Weekly report to CISO
   ✅ Monthly review of priority account list
   ✅ Quarterly policy effectiveness assessment
   
4. User Education
   ✅ Enhanced security awareness for priority accounts
   ✅ Monthly phishing simulations (mandatory)
   ✅ Incident reporting expectations
   ✅ Secure communication practices (no text for sensitive topics)

5. Additional Protections
   ✅ MFA required (no exceptions)
   ✅ Privileged Access Workstations (PAWs) for sensitive work
   ✅ Email encryption for financial discussions
   ✅ Phone verification for wire transfers (out-of-band)
   ✅ Regular security briefings
```

### 9.8 Priority Account Scenarios

**Scenario 1: CEO Targeted by BEC**

```
Attack Timeline:

Day 1, 09:00 - Reconnaissance email sent to CEO assistant
    From: hr-benefits@outlook.com (not company domain)
    Subject: "Updated W-2 information needed"
    Verdict: Not blocked (seemed legitimate at time)
    
Day 1, 09:15 - CEO assistant replies with W-2 data
    Result: Attacker now has CEO personal info
    
Day 2, 14:00 - BEC attack email sent to CFO
    From: CEO <ceo.urgent@gmail.com>
    Display name: Exactly matches CEO
    Subject: "Urgent wire transfer - confidential"
    Content: "Need $250,000 wired to vendor for acquisition. 
              Don't discuss with anyone. Time-sensitive."
    
MDO Detection:
✅ Anti-phishing: User impersonation detected
✅ Priority account: CFO is tagged, higher scrutiny
✅ Mailbox intelligence: CEO never emails from Gmail
✅ Verdict: HIGH CONFIDENCE PHISHING
✅ Action: QUARANTINED before delivery

Outcome: Attack blocked, no financial loss

Follow-up:
1. CFO notified of attempted CEO fraud
2. Real CEO informed
3. Security team investigates Day 1 email (missed)
4. Enhanced policies for executive assistants
5. User education on BEC tactics
6. Phone verification policy reinforced for wire transfers
```

**Scenario 2: Priority Account Clicking Malicious Link**

```
Attack Timeline:

14:00 - CFO receives "DocuSign" phishing email
    From: noreply@docusign-secure.com (typosquatting)
    Subject: "Document requires your signature"
    Link: https://docusign-secure.com/sign?id=...
    
14:01 - CFO clicks link (legitimate-looking)
    
Safe Links Action:
✅ URL rewritten to Safe Links proxy
✅ Real-time verification at click-time
✅ Reputation check: docusign-secure.com = MALICIOUS
✅ Verdict: PHISHING SITE
✅ Action: CLICK BLOCKED
✅ Warning page displayed to CFO

User Experience:
┌────────────────────────────────────────┐
│  ⚠️ THIS SITE HAS BEEN BLOCKED         │
│                                        │
│  This site is known to be malicious    │
│  and may attempt to steal your         │
│  credentials or infect your device.    │
│                                        │
│  [Go Back]   [Report False Positive]   │
└────────────────────────────────────────┘

Alert Generated:
- Incident: Priority account clicked malicious link
- Severity: HIGH (due to CFO priority tag)
- Assigned to: SOC team immediately
- Actions taken:
  1. CFO contacted for follow-up
  2. Endpoint scan (MDE) initiated
  3. Recent authentication reviewed
  4. Password reset required (precaution)
  5. User education scheduled

Outcome: No compromise, user protected
```

### 9.9 GCC/GCC-H/DoD Availability

**🆕 2024-2025 Update:**

Priority Account Protection now available in:
- **GCC (Government Community Cloud)** ✅
- **GCC-H (Government Community Cloud High)** ✅
- **DoD (Department of Defense)** ✅

**Deployment Timeline:**
- Commercial: GA since 2023
- GCC: GA Q2 2024
- GCC-H: GA Q3 2024
- DoD: GA Q4 2024

**Government-Specific Use Cases:**
- Political officials (targeted by nation-states)
- Military leadership
- Intelligence community
- Diplomatic corps
- Critical infrastructure executives

### 9.10 Limitations and Considerations

**Current Limitations:**

```
❌ Maximum 250 priority accounts per tenant
   - Choose wisely
   - Focus on truly high-value targets

❌ No granular policy differences by priority level
   - All priority accounts treated equally
   - Cannot have "super priority" tier

⚠️ Not a replacement for proper security hygiene
   - Still need MFA, conditional access, etc.
   - Priority tagging enhances, doesn't replace

⚠️ False positives may increase
   - More aggressive detection = more FPs
   - Balance security with usability
   - Monitor and tune regularly
```

**Cost Considerations:**

```
Licensing:
- Priority account tagging: Included in MDO Plan 1 & 2
- No additional cost per priority account
- No limit charges

Operational Cost:
- Increased alert volume (more investigation time)
- Stricter policies (more user friction)
- Enhanced monitoring (SOC resource allocation)

ROI:
- Prevents high-impact compromises
- Reduces BEC/CEO fraud risk
- Protects crown jewels
- Worth the operational investment
```

**🎯 Exam Tip:**
- Priority accounts = **VIP tagging** for enhanced protection
- Available in **MDO Plan 1 and Plan 2**
- Maximum **250 accounts** per tenant
- 🆕 Now available in **GCC/GCC-H/DoD** (2024-2025)
- Provides **stricter policies**, **dedicated reports**, and **faster escalation**
- Tag via: Admin Center, PowerShell (`Set-User -IsPriorityAccount $true`)
- Visible in: **Threat Explorer**, **Incident queue**, **Reports**

---

## 10. Email Authentication (SPF, DKIM, DMARC)

### 10.1 Overview

**Why Email Authentication Matters:**

Email authentication prevents **spoofing** and **impersonation** by verifying:
- **Who** sent the email (sender identity)
- **Where** it came from (authorized servers)
- **What to do** if verification fails (policy enforcement)

**The Three Pillars:**

```
Email Authentication Framework:

1. SPF (Sender Policy Framework)
   └─ "Which IP addresses can send email for my domain?"
      Example: Only mail.contoso.com can send @contoso.com email

2. DKIM (DomainKeys Identified Mail)
   └─ "Is this email signed by my domain's private key?"
      Example: Email has cryptographic signature proving authenticity

3. DMARC (Domain-based Message Authentication, Reporting & Conformance)
   └─ "What should receivers do if SPF/DKIM fails?"
      Example: If auth fails, quarantine email and send me a report

Together:
SPF + DKIM + DMARC = Strong defense against spoofing and phishing
```

### 10.2 SPF (Sender Policy Framework)

**What is SPF?**

SPF is a DNS record that lists **authorized mail servers** for a domain.

**How SPF Works:**

```
Email Sent:
From: user@contoso.com
Via: mail.external-server.com

Receiving Server Checks:
1. Look up SPF record for contoso.com
   DNS query: TXT record for contoso.com
   
2. SPF record found:
   v=spf1 ip4:203.0.113.0/24 include:spf.protection.outlook.com ~all
   
3. Check if sending IP matches:
   - Sending IP: 203.0.113.10 ✅ (in authorized range)
   - OR: Sending IP via outlook.com ✅ (included)
   - OR: Sending IP: 192.0.2.50 ❌ (not authorized)

4. SPF Verdict:
   ✅ Pass: IP is authorized
   ⚠️ SoftFail: Not authorized but don't reject (~all)
   ❌ Fail: Not authorized, reject (-all)
   ❓ None: No SPF record found
   ⚠️ Neutral: Can't determine (?all)
   ⚠️ TempError: DNS lookup failed (transient)
   ❌ PermError: SPF record invalid (syntax error)
```

**SPF Record Syntax:**

```
Example SPF Record:
v=spf1 ip4:203.0.113.0/24 include:spf.protection.outlook.com ~all

Breakdown:
├─ v=spf1: Version (always "spf1")
│
├─ ip4:203.0.113.0/24: Allow IPv4 range
│  └─ Can also use: ip6: (IPv6), a: (domain A record), mx: (MX servers)
│
├─ include:spf.protection.outlook.com: Include another domain's SPF
│  └─ Used for: Email services like Microsoft 365, SendGrid, Mailchimp
│
└─ ~all: Default policy (SoftFail)
   ├─ -all: Hard fail (strict, reject unauthorized)
   ├─ ~all: Soft fail (suspicious but don't reject) [RECOMMENDED]
   ├─ ?all: Neutral (don't care)
   └─ +all: Allow all (NEVER USE - defeats purpose)
```

**Creating SPF Record for Microsoft 365:**

```
For Exchange Online (Microsoft 365):

TXT Record:
Name: @ (or blank, represents root domain)
Value: v=spf1 include:spf.protection.outlook.com ~all

If you have additional mail servers:
v=spf1 ip4:203.0.113.5 include:spf.protection.outlook.com ~all

If you use third-party email service (e.g., Mailchimp):
v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ~all

⚠️ SPF Limit:
- Maximum 10 DNS lookups (includes nested lookups)
- Too many includes = PermError
- Solution: Flatten SPF record (convert includes to IPs)
```

**Verifying SPF:**

```powershell
# Windows DNS lookup
nslookup -type=txt contoso.com

# PowerShell
Resolve-DnsName -Name contoso.com -Type TXT | Where-Object {$_.Strings -like "*spf1*"}

# Online tools:
# https://mxtoolbox.com/spf.aspx
# Check SPF record validity and DNS lookups
```

**Common SPF Issues:**

```
Issue 1: Multiple SPF records
❌ WRONG:
   TXT: v=spf1 include:spf.protection.outlook.com ~all
   TXT: v=spf1 ip4:203.0.113.0/24 ~all

✅ CORRECT:
   TXT: v=spf1 include:spf.protection.outlook.com ip4:203.0.113.0/24 ~all

Issue 2: Exceeding 10 DNS lookups
❌ WRONG:
   v=spf1 include:service1.com include:service2.com include:service3.com ... (12 includes)
   Result: PermError

✅ CORRECT:
   Flatten includes to IP ranges where possible
   OR: Remove unnecessary includes

Issue 3: Using +all
❌ NEVER DO THIS:
   v=spf1 +all
   Meaning: Anyone can send email as your domain!

✅ USE THIS:
   v=spf1 include:spf.protection.outlook.com ~all
```

### 10.3 DKIM (DomainKeys Identified Mail)

**What is DKIM?**

DKIM adds a **cryptographic signature** to outgoing emails, proving they came from your domain and weren't modified in transit.

**How DKIM Works:**

```
Sending Process:

1. Email composed:
   From: user@contoso.com
   Subject: Q3 Financial Report
   Body: [content]

2. Mail server signs email:
   - Uses private key (stored on mail server)
   - Creates hash of email headers and body
   - Encrypts hash with private key
   - Adds DKIM-Signature header to email

3. Email sent with DKIM signature:
   DKIM-Signature: v=1; a=rsa-sha256; d=contoso.com; s=selector1;
                   h=from:subject:date; bh=[body hash]; b=[signature]

Receiving Process:

1. Email arrives at recipient's server

2. Server extracts DKIM signature

3. Server looks up public key:
   DNS query: TXT selector1._domainkey.contoso.com
   Returns: Public key

4. Server verifies signature:
   - Decrypts signature with public key
   - Compares with hash of received email
   - If match: DKIM PASS ✅
   - If mismatch: DKIM FAIL ❌

5. Verdict used in spam filtering
```

**DKIM Signature Components:**

```
DKIM-Signature: v=1; a=rsa-sha256; d=contoso.com; s=selector1;
                c=relaxed/relaxed; h=from:to:subject:date;
                bh=abcd1234...; b=xyz789...;

Breakdown:
├─ v=1: Version
├─ a=rsa-sha256: Algorithm (RSA with SHA-256)
├─ d=contoso.com: Signing domain
├─ s=selector1: Selector (identifies which key pair)
├─ c=relaxed/relaxed: Canonicalization (how to normalize email)
├─ h=from:to:subject:date: Headers signed
├─ bh=...: Body hash
└─ b=...: Signature of headers + body hash
```

**Enabling DKIM for Microsoft 365:**

```
Method 1: Microsoft 365 Admin Center

1. Navigate to: admin.microsoft.com
2. Settings → Domains
3. Select domain (e.g., contoso.com)
4. Email authentication → DKIM
5. Click "Enable DKIM signing"
6. Follow instructions:
   a. Microsoft provides 2 CNAME records
   b. Add CNAMEs to your DNS:
      
      CNAME: selector1._domainkey.contoso.com
      Points to: selector1-contoso-com._domainkey.contoso.onmicrosoft.com
      
      CNAME: selector2._domainkey.contoso.com
      Points to: selector2-contoso-com._domainkey.contoso.onmicrosoft.com
   
   c. Wait for DNS propagation (15 min - 72 hours)
   d. Return to admin center
   e. Click "Enable" (turns on DKIM signing)

7. Status: Enabled ✅

Method 2: PowerShell

# Connect
Connect-ExchangeOnline

# Enable DKIM for domain
New-DkimSigningConfig -DomainName "contoso.com" -Enabled $true

# Verify DKIM status
Get-DkimSigningConfig -Identity "contoso.com"
```

**Verifying DKIM:**

```
1. Send test email from your domain to external account

2. View email headers in recipient mailbox

3. Look for DKIM-Signature header:
   DKIM-Signature: v=1; a=rsa-sha256; d=contoso.com; ...
   
4. Check authentication results:
   Authentication-Results: dkim=pass header.d=contoso.com

5. Online tools:
   - https://dkimvalidator.com
   - Send email to provided address
   - Tool validates DKIM signature
```

**DKIM Best Practices:**

```
✅ DO:
- Enable DKIM for all sending domains
- Use 2048-bit keys (stronger than 1024-bit)
- Rotate keys annually (security best practice)
- Monitor for DKIM failures (indicates issues)

❌ DON'T:
- Disable DKIM once enabled (weakens reputation)
- Use same selector for multiple domains
- Forget to update DNS if migrating mail servers
```

### 10.4 DMARC (Domain-based Message Authentication)

**What is DMARC?**

DMARC builds on SPF and DKIM, telling receiving servers:
- **Policy:** What to do if authentication fails
- **Reporting:** Send me reports of authentication results

**How DMARC Works:**

```
Receiving Server Checks:

1. Email arrives from: user@contoso.com

2. Check SPF:
   └─ Does sending IP match SPF record?
      Result: Pass/Fail

3. Check DKIM:
   └─ Is DKIM signature valid?
      Result: Pass/Fail

4. Check DMARC:
   a. Look up DMARC record: _dmarc.contoso.com
   b. DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@contoso.com
   c. Check alignment:
      - SPF: Does envelope-from match header-from domain?
      - DKIM: Does d= domain match header-from domain?
   d. Apply policy:
      - If SPF OR DKIM passes AND aligns: Deliver ✅
      - If both fail: Apply policy (none/quarantine/reject)

5. Send aggregate report:
   └─ Daily report to rua=dmarc@contoso.com
      Contains: All email claiming to be from contoso.com
                SPF/DKIM/DMARC results
                Volume, IP addresses, etc.
```

**DMARC Record Syntax:**

```
Example DMARC Record:
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@contoso.com; ruf=mailto:forensic@contoso.com; fo=1; adkim=r; aspf=r;

Breakdown:
├─ v=DMARC1: Version
│
├─ p=quarantine: Policy for main domain
│  ├─ none: Monitor only (no action)
│  ├─ quarantine: Send to Junk folder
│  └─ reject: Reject email
│
├─ sp=reject: Subdomain policy (optional, defaults to p=)
│
├─ pct=100: Percentage of emails to apply policy to
│  └─ Start with pct=10 for testing, gradually increase to 100
│
├─ rua=mailto:dmarc@contoso.com: Aggregate reports
│  └─ Daily summary of all authentication attempts
│
├─ ruf=mailto:forensic@contoso.com: Forensic reports
│  └─ Real-time failure reports (not widely supported)
│
├─ fo=1: Forensic options (when to send forensic reports)
│  ├─ 0: All checks fail
│  ├─ 1: Any check fails (recommended)
│  └─ d/s: DKIM or SPF fails
│
├─ adkim=r: DKIM alignment mode
│  ├─ r: Relaxed (subdomain.contoso.com aligns with contoso.com)
│  └─ s: Strict (exact match only)
│
├─ aspf=r: SPF alignment mode
│  └─ Same as adkim (r=relaxed, s=strict)
│
└─ rf=afrf: Report format (default)
   └─ ri=86400: Report interval (seconds, default 86400 = 24 hours)
```

**DMARC Deployment Stages:**

```
Stage 1: Monitor (p=none)
TXT: _dmarc.contoso.com
Value: v=DMARC1; p=none; rua=mailto:dmarc@contoso.com;

Purpose:
- Collect data on email authentication
- Identify legitimate mail sources
- Find authentication issues
- Duration: 2-4 weeks

Stage 2: Gradual Enforcement (p=quarantine; pct=10)
TXT: _dmarc.contoso.com
Value: v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc@contoso.com;

Purpose:
- Start enforcing on 10% of emails
- Test impact on legitimate mail
- Gradually increase: 10% → 25% → 50% → 100%
- Duration: 2-3 weeks per increment

Stage 3: Full Quarantine (p=quarantine; pct=100)
TXT: _dmarc.contoso.com
Value: v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@contoso.com;

Purpose:
- Quarantine all failing emails
- Monitor for false positives
- Duration: 4-8 weeks

Stage 4: Reject (p=reject) [ULTIMATE GOAL]
TXT: _dmarc.contoso.com
Value: v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com;

Purpose:
- Reject all failing emails at SMTP level
- Maximum protection against spoofing
- Duration: Ongoing
```

**DMARC Reports:**

```
Aggregate Reports (rua):
- Sent daily by receiving mail servers
- XML format (parse with tools)
- Contains:
  * Source IPs sending email as your domain
  * Volume of emails
  * SPF/DKIM/DMARC pass/fail counts
  * Disposition (none/quarantine/reject)

Example Report Summary:
┌───────────────────────────────────────────┐
│ DMARC Report for contoso.com              │
│ Date: 2025-10-22                          │
├───────────────────────────────────────────┤
│ Source IP     | Volume | SPF | DKIM | Disp│
├───────────────────────────────────────────┤
│ 203.0.113.10  | 5,234  | ✅  | ✅   | None│ ← Your mail server
│ 198.51.100.5  | 12     | ❌  | ❌   | Quar│ ← Spoofer!
│ 192.0.2.20    | 1,008  | ✅  | ✅   | None│ ← MailChimp
└───────────────────────────────────────────┘

Forensic Reports (ruf):
- Real-time failure notifications
- Contains full email headers and body
- Privacy concern (contains content)
- Not widely supported by receivers
- Use with caution
```

**Analyzing DMARC Reports:**

```
Tools:
1. Microsoft-provided reports (if using M365)
   - Defender Portal → Email & collaboration → DMARC
   - Shows pass/fail rates, sources

2. Third-party DMARC services:
   - Dmarcian
   - Valimail
   - Postmark DMARC
   - PowerDMARC
   
3. Manual parsing:
   - Python scripts
   - Parse XML reports
   - Aggregate in dashboard

What to Look For:
✅ High DMARC pass rate (>95%)
⚠️ Failing sources (investigate if legitimate)
❌ Spoof attempts (unauthorized sources)
📊 Volume trends (spikes may indicate attacks)
```

**Creating DMARC Record:**

```
1. Determine current authentication status:
   - Is SPF configured? ✅
   - Is DKIM enabled? ✅
   - Ready for DMARC!

2. Create DMARC record:
   TXT record:
   Name: _dmarc.contoso.com
   Value: v=DMARC1; p=none; rua=mailto:dmarc-reports@contoso.com;

3. Create mailbox for reports:
   - dmarc-reports@contoso.com
   - Or use third-party aggregation service

4. Wait 24-48 hours for first reports

5. Analyze reports for 2-4 weeks

6. Gradually increase enforcement:
   p=none → p=quarantine; pct=10 → ... → p=reject

7. Monitor continuously
```

**DMARC for Subdomains:**

```
Subdomain Policy:

Main domain: contoso.com
- DMARC: v=DMARC1; p=reject; ...

Subdomain: newsletter.contoso.com
- If no DMARC record: Inherits main domain policy (p=reject)
- If separate DMARC record: Uses own policy

Explicit Subdomain Policy:
TXT: _dmarc.contoso.com
Value: v=DMARC1; p=reject; sp=quarantine; ...

Meaning:
- Main domain (contoso.com): Reject
- Subdomains (*.contoso.com): Quarantine
```

### 10.5 Authentication in Microsoft Defender for Office 365

**Composite Authentication:**

MDO uses **composite authentication** (compauth) combining SPF, DKIM, and DMARC:

```
Composite Auth Algorithm:

1. Check SPF:
   - Pass: +10 points
   - Fail: -20 points
   - SoftFail: -5 points

2. Check DKIM:
   - Pass: +15 points
   - Fail: -15 points
   - None: 0 points

3. Check DMARC:
   - Pass: +20 points
   - Fail: -25 points
   - None: 0 points

4. Apply sender reputation:
   - Good reputation: +5 points
   - Bad reputation: -30 points

5. Other signals:
   - User interactions (opens/replies): +10 points
   - Similar domain (typosquatting): -50 points
   - Etc.

6. Final score → Verdict:
   - Score > 40: Likely legitimate
   - Score 0-40: Suspicious
   - Score < 0: Likely malicious

7. Action:
   - High score: Deliver to Inbox
   - Low score: Quarantine or Junk
   - Very low score: Block
```

**Authentication Headers:**

```
Example Email Headers:

Authentication-Results: spf=pass (sender IP is 203.0.113.10)
 smtp.mailfrom=contoso.com; dkim=pass (signature was verified)
 header.d=contoso.com; dmarc=pass action=none
 header.from=contoso.com;compauth=pass reason=100

Breakdown:
├─ spf=pass: SPF check passed
├─ dkim=pass: DKIM signature valid
├─ dmarc=pass: DMARC aligned and passed
└─ compauth=pass reason=100: Composite auth passed (100 = all checks passed)

compauth values:
- pass: Authentication passed
- softpass: Passed with warnings
- neutral: Indeterminate
- fail: Authentication failed
- reason=100: All checks passed
- reason=130: SPF passed, DKIM/DMARC not configured
- reason=001: All checks failed
```

**Monitoring Authentication:**

```
Reports:
1. Defender Portal → Reports → Email authentication
2. Shows:
   - SPF pass/fail rates
   - DKIM pass/fail rates
   - DMARC pass/fail rates
   - Trends over time
   - Top failing senders

Advanced Hunting:
// Check authentication status for emails
EmailEvents
| where Timestamp > ago(7d)
| extend AuthResults = parse_json(AuthenticationDetails)
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          SPF = AuthResults.SPF,
          DKIM = AuthResults.DKIM,
          DMARC = AuthResults.DMARC,
          CompAuth = AuthResults.CompAuth
| where DMARC == "fail"
| summarize FailedEmails = count() by SenderFromAddress
| order by FailedEmails desc
```

### 10.6 Troubleshooting Authentication

**Common Issues:**

**Issue 1: SPF Fails After Migrating to Microsoft 365**

```
Symptom: SPF failures after migration

Cause: Old SPF record still points to old mail server

Solution:
1. Update SPF record:
   OLD: v=spf1 ip4:198.51.100.5 ~all
   NEW: v=spf1 include:spf.protection.outlook.com ~all

2. Wait for DNS propagation (up to 72 hours)

3. Verify:
   nslookup -type=txt contoso.com
```

**Issue 2: DKIM Not Signing**

```
Symptom: Authentication-Results shows dkim=none

Cause: DKIM not enabled or DNS records missing

Solution:
1. Verify DKIM enabled:
   Get-DkimSigningConfig -Identity contoso.com
   
2. Check DNS records:
   nslookup -type=cname selector1._domainkey.contoso.com
   
3. If missing, add CNAME records from admin center

4. Wait for DNS propagation

5. Test by sending email
```

**Issue 3: DMARC Policy Too Strict**

```
Symptom: Legitimate emails blocked/quarantined

Cause: DMARC p=reject but authentication fails

Solution:
1. Temporarily relax policy:
   Change: p=reject → p=quarantine
   
2. Analyze DMARC reports to find failing sources

3. Fix authentication issues:
   - Add legitimate sources to SPF
   - Enable DKIM for all sending services
   - Fix alignment issues

4. Gradually re-tighten policy
```

**🎯 Exam Tip:**
- **SPF** = Authorized sending **IPs** (v=spf1 include:spf.protection.outlook.com ~all)
- **DKIM** = **Cryptographic signature** (proves email from domain, not modified)
- **DMARC** = **Policy** (what to do if SPF/DKIM fail) + **Reporting**
- DMARC stages: **p=none** (monitor) → **p=quarantine** → **p=reject** (ultimate goal)
- Microsoft 365: Use **include:spf.protection.outlook.com** for SPF
- DKIM: Enable via Admin Center, add **2 CNAME records** to DNS
- DMARC: **_dmarc.contoso.com** TXT record, start with **p=none**
- **Composite authentication** = MDO's combined SPF+DKIM+DMARC+other signals

---

## 11. Investigation and Response

### 11.1 Investigation Workflow

**Email Threat Investigation Process:**

```
1. Alert Triage (5-10 minutes)
   ├─ Review alert details
   ├─ Determine severity
   ├─ Check if true positive
   └─ Assign to analyst

2. Initial Investigation (15-30 minutes)
   ├─ Open email entity page
   ├─ Review threat indicators
   ├─ Check authentication results
   ├─ Analyze URLs and attachments
   └─ Identify affected users

3. Scope Determination (30-60 minutes)
   ├─ Use Threat Explorer to find similar emails
   ├─ Check for campaign indicators
   ├─ Identify all recipients
   ├─ Determine delivery locations
   └─ Assess risk level

4. Containment (Immediate)
   ├─ Quarantine/delete malicious emails
   ├─ Block sender/domain
   ├─ Disable compromised accounts
   └─ Reset passwords if needed

5. Remediation (Variable)
   ├─ Remove emails from all mailboxes
   ├─ Update policies to prevent recurrence
   ├─ Submit to Microsoft (false negatives)
   └─ Document findings

6. User Communication (30 minutes)
   ├─ Notify affected users
   ├─ Provide guidance
   └─ Security awareness reminder

7. Post-Incident Review (1-2 hours)
   ├─ Document lessons learned
   ├─ Update playbooks
   ├─ Improve detection rules
   └─ Train team
```

### 11.2 Investigating Phishing Emails

**Scenario: User Reports Phishing Email**

**Step 1: Locate Email in Threat Explorer**

```
1. Threat Explorer → View: Submissions
2. Filter:
   - Submission type: User reported
   - Recipient: user@contoso.com
   - Date: Last 7 days

3. Find reported email:
   From: payrol@contoso-hr.com (typosquatting!)
   Subject: "Urgent: Update your payroll information"
   Submission verdict: Should have been blocked
```

**Step 2: Analyze Email Entity**

```
Click email → Email entity page opens

Analysis Tab:
├─ Threat detection:
│  ├─ Threat types: Phish, Spoofing
│  ├─ Detection: Domain impersonation
│  └─ Confidence: High
│
├─ Authentication:
│  ├─ SPF: Fail (IP not authorized)
│  ├─ DKIM: None (not signed)
│  ├─ DMARC: Fail (no alignment)
│  └─ CompAuth: Fail
│
├─ URLs:
│  └─ https://payroll-update-contoso.com/login.php
│     ├─ Verdict: Phishing site
│     ├─ Safe Links: Blocked
│     └─ Clicks: 3 users clicked!
│
└─ Attachments: None

Red Flags:
⚠️ Domain typosquatting (contoso-hr.com vs contoso.com)
⚠️ Authentication failed (SPF/DKIM/DMARC)
⚠️ Phishing URL detected
⚠️ 3 users clicked link (potential compromise!)
```

**Step 3: Find Similar Emails (Campaign Hunt)**

```
Threat Explorer → Similar emails tab shows:
- 25 emails with same sender domain
- 18 emails with same URL
- Sent to 150 users total
- Delivered to: 45 inboxes, 105 quarantined

Timeline:
├─ 09:00-09:15: First wave (50 emails) → 30 quarantined
├─ 10:00-10:15: Second wave (50 emails) → 35 quarantined  
├─ 11:00-11:15: Third wave (50 emails) → 40 quarantined
└─ Total: 150 emails, 105 quarantined, 45 delivered

Verdict: Coordinated phishing campaign targeting organization
```

**Step 4: Identify Compromised Users**

```
URLClickEvents table:
| where Timestamp > ago(24h)
| where Url contains "payroll-update-contoso.com"
| project Timestamp, AccountUpn, ActionType

Results:
├─ user1@contoso.com: ClickAllowed (before Safe Links block)
├─ user2@contoso.com: ClickBlocked
└─ user3@contoso.com: ClickAllowed (before Safe Links block)

High Risk: user1 and user3 (may have entered credentials)

Action Required:
1. Check if credentials submitted (MDE telemetry)
2. Force password reset for user1 and user3
3. Review recent authentication attempts
4. Check for suspicious account activity
5. Isolate devices if compromise confirmed
```

**Step 5: Containment**

```
Immediate Actions:

1. Remove emails from all mailboxes:
   - Threat Explorer → Select all 45 delivered emails
   - Take action → Hard delete
   - Scope: All recipients
   - ✓ Remove from Sent Items

2. Block sender domain:
   - Add contoso-hr.com to tenant block list
   - Block at connection filter level

3. Block phishing URL:
   - Add payroll-update-contoso.com to URL block list
   - Safe Links will block future clicks

4. Reset compromised user passwords:
   - user1@contoso.com: Force password reset
   - user3@contoso.com: Force password reset
   - Revoke all active sessions

5. Monitor for follow-on activity:
   - Check for unusual logins
   - Monitor for lateral movement
   - Watch for data exfiltration
```

**Step 6: Remediation**

```
1. Submit false negative to Microsoft:
   - Admin submission → Email
   - Upload original email
   - Reason: Should have been blocked as phishing
   - Microsoft improves filters globally

2. Update anti-phishing policy:
   - Add "contoso" to protected domains (if not already)
   - Lower phishing threshold for finance/HR users
   - Enable all safety tips

3. User education:
   - Send organization-wide awareness email
   - Highlight red flags (typosquatting, urgency, links)
   - Remind: Never enter credentials via email link
   - Promote use of password manager (detects fake sites)

4. Create detection rule (Advanced hunting):
   // Alert on future similar campaigns
   EmailEvents
   | where SenderFromAddress contains "contoso-"
   | where ThreatTypes has "Phish"
   | summarize Count = count() by SenderFromAddress
   | where Count > 5
```

### 11.3 Automated Investigation & Response (AIR)

**What is AIR?**

**Automated Investigation & Response** (MDO Plan 2 only) automatically investigates and remediates email threats.

**How AIR Works:**

```
Trigger:
- Alert generated (phishing, malware, etc.)
- Campaign detected
- Suspicious pattern identified

AIR Process:

1. Investigation Launched (Automatic)
   ├─ Gather evidence:
   │  ├─ Email details
   │  ├─ Recipient actions (opened, clicked, replied)
   │  ├─ Similar emails
   │  ├─ Related alerts
   │  └─ Threat intelligence
   │
   ├─ Analyze threat:
   │  ├─ URL reputation check
   │  ├─ Attachment analysis
   │  ├─ Sender reputation
   │  └─ Campaign correlation
   │
   └─ Determine verdict:
      ├─ Malicious: High confidence
      ├─ Suspicious: Medium confidence
      └─ Clean: False positive

2. Recommendations Generated
   ├─ Soft delete emails
   ├─ Block sender
   ├─ Reset user passwords
   └─ Isolate devices (if MDE integrated)

3. Actions Taken (based on automation level)
   ├─ Manual: Analyst approves each action
   ├─ Semi-automated: Some actions automatic
   └─ Fully automated: All actions automatic

4. Action Center
   ├─ Shows pending actions
   ├─ Shows completed actions
   └─ Allows manual approval/rejection
```

**AIR Investigation Example:**

```
Alert: Phishing email delivered to 50 users

AIR Investigation #12345:
├─ Status: Completed
├─ Started: 2025-10-22 14:30:00
├─ Completed: 2025-10-22 14:45:00
├─ Duration: 15 minutes

Investigation Summary:
├─ Emails analyzed: 50
├─ Verdict: Malicious (High confidence)
├─ Evidence:
│  ├─ URLs: 1 malicious URL detected
│  ├─ Domain: Typosquatting (contoso-secure.com)
│  ├─ Authentication: All checks failed (SPF/DKIM/DMARC)
│  └─ Threat intelligence: Known phishing campaign

Recommended Actions:
1. Soft delete 50 emails (all instances)
2. Block sender domain: contoso-secure.com
3. Block URL: https://contoso-secure.com/login
4. Reset passwords: 3 users (clicked link)

Automation Level: Semi-automated
Actions Taken Automatically:
✅ Soft deleted 50 emails
✅ Blocked sender domain
✅ Blocked URL

Pending Approval:
⏳ Reset passwords for 3 users (requires admin approval)

Analyst Action:
- Review investigation
- Approve password resets
- Or: Reject if false positive
```

**AIR Automation Levels:**

```
Configure: Settings → Email & collaboration → AIR

Levels:

1. No automated response (Manual)
   - AIR investigates only
   - Generates recommendations
   - Admin must approve ALL actions
   - Use: High-security environments, limited trust in automation

2. Semi-automated
   - AIR automatically remediates SOME threats
   - Requires approval for sensitive actions (e.g., password reset)
   - Use: Most organizations (balanced approach) [RECOMMENDED]

3. Fully automated (🔥 Use with caution)
   - AIR automatically remediates ALL threats
   - No approval required
   - Use: High-confidence environments with strong tuning

Recommendation: Start with Manual, move to Semi-automated after 30 days
```

**Monitoring AIR:**

```
1. Action Center:
   Defender Portal → Actions & submissions → Action center

2. Shows:
   - Pending actions (require approval)
   - History (completed actions)
   - Investigation details

3. Tabs:
   - Pending: Actions awaiting approval
   - History: Last 30 days of actions
   - Unified action center: Cross-product actions (MDO + MDE + MDI)

4. Actions you can take:
   - Approve: Execute pending action
   - Reject: Dismiss action
   - View details: See full investigation
   - Undo: Revert completed action (if possible)
```

**AIR Playbooks:**

```
MDO includes pre-built playbooks:

1. Phishing Email Playbook:
   ├─ Trigger: Phishing alert
   ├─ Actions:
   │  ├─ Find similar emails
   │  ├─ Check if users clicked links
   │  ├─ Soft delete emails
   │  ├─ Block sender
   │  └─ Recommend password reset for click victims

2. Malware Email Playbook:
   ├─ Trigger: Malware alert
   ├─ Actions:
   │  ├─ Find similar emails
   │  ├─ Hard delete emails (malware = high risk)
   │  ├─ Block sender
   │  ├─ Quarantine attached files
   │  └─ Trigger MDE investigation (if integrated)

3. Compromised User Playbook:
   ├─ Trigger: Account compromise indicator
   ├─ Actions:
   │  ├─ Disable account
   │  ├─ Revoke active sessions
   │  ├─ Find emails sent from compromised account
   │  ├─ Soft delete sent emails
   │  └─ Force password reset

Custom Playbooks:
- Not available in MDO (only pre-built playbooks)
- Custom automation via: Microsoft Sentinel playbooks (Logic Apps)
```

### 11.4 Manual Remediation Actions

**Available Actions:**

```
1. Soft Delete
   - Moves email to Deleted Items
   - User can recover (Ctrl+Z in Outlook)
   - Use: Medium-risk threats

2. Hard Delete (🆕)
   - Permanently removes email
   - User CANNOT recover
   - Admin can recover (litigation hold)
   - 🆕 Extends to malicious calendar invites
   - Use: High-risk threats (malware, confirmed phishing)

3. Move to Junk
   - Moves to Junk Email folder
   - User sees warning
   - Use: Low-risk spam

4. Move to Inbox
   - Restore false positive
   - Use: Legitimate email mistakenly blocked

Scope Options:
- Single mailbox
- Multiple specific mailboxes
- All recipients organization-wide
```

**🆕 September 2025: Enhanced Manual Remediation**

Microsoft brought **manual email purge actions** to the unified **Action Center**:

```
Before (2024):
- Manual actions scattered across tools
- No unified tracking
- Hard to see what was done

After (Sept 2025):
- All manual actions visible in Action center
- Unified tracking with AIR
- Action-focused investigation view
- Single pane of glass

Benefits:
✅ Better visibility
✅ Easier audit trail
✅ Consistent workflow
✅ Integration with automated actions
```

**Manual Action Workflow:**

```
Scenario: Admin manually removes phishing email

1. Threat Explorer → Find email
2. Select email(s) → Take action
3. Choose: Hard delete
4. Scope: All recipients (25 users)
5. ✓ Submit to Microsoft as phishing
6. ✓ Remove from Sent Items (🆕)
7. Submit

Action Recorded:
└─ Action Center → History
   ├─ Action: Hard delete
   ├─ Entity: Email (subject: "Urgent wire transfer")
   ├─ Scope: 25 mailboxes
   ├─ Status: Completed
   ├─ Timestamp: 2025-10-22 15:30:00
   ├─ Initiated by: admin@contoso.com
   └─ Investigation ID: Manual-12345

Audit Trail:
- Compliance center → Audit log
- Shows: Who, What, When, Where
- Retention: 90 days (or longer with retention policy)
```

### 11.5 Cross-Product Investigation

**Unified Incident Investigation:**

```
Scenario: Phishing to Endpoint Compromise

Timeline:

09:00 - Phishing email delivered (MDO)
   From: hr@c0ntoso.com
   Attachment: payroll.xlsm (malicious macro)

09:15 - User opens attachment (MDE)
   Process: EXCEL.EXE → PowerShell.exe (suspicious)
   MDE alert: "Suspicious macro execution"

09:20 - Credential theft (MDI)
   Mimikatz execution detected
   MDI alert: "Credential dumping detected"

09:25 - Lateral movement (MDE + MDI)
   Pass-the-hash attack
   Access to file server
   MDE + MDI alerts

09:30 - Unified Incident Created
   Incident #12345: "Multi-stage attack"
   Alerts: 4 (MDO + MDE + MDI)
   Attack story: Phishing → Execution → Credential Theft → Lateral Movement

Investigation:
1. Defender Portal → Incidents
2. Incident #12345 → Shows complete attack chain
3. Evidence:
   - Email (MDO)
   - Malicious file (MDO + MDE)
   - Process execution (MDE)
   - Credential theft (MDI)
   - Lateral movement (MDE + MDI)

Response:
- Isolate compromised device (MDE)
- Disable user account (MDI)
- Reset password (MDI)
- Remove email from all mailboxes (MDO)
- Block sender domain (MDO)
- Hunt for similar emails (MDO)
- Check for data exfiltration (MDE + MDCA)
```

**Advanced Hunting Across Products:**

```kql
// Correlate phishing email with endpoint activity

// 1. Find phishing email
let PhishEmail = EmailEvents
| where Timestamp > ago(24h)
| where ThreatTypes has "Phish"
| where Subject contains "payroll"
| project EmailTime=Timestamp, RecipientEmailAddress, NetworkMessageId, SenderFromAddress;

// 2. Find attachment download
let AttachmentDownload = EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileName endswith ".xlsm"
| project NetworkMessageId, FileName, SHA256;

// 3. Find file execution on endpoint
let FileExecution = DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName endswith ".xlsm"
| project DeviceTime=Timestamp, DeviceName, FileName, SHA256, InitiatingProcessAccountName;

// 4. Find process creation (macro execution)
let ProcessCreation = DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "EXCEL.EXE"
| where ProcessCommandLine has "powershell"
| project ProcessTime=Timestamp, DeviceName, ProcessCommandLine, AccountName;

// 5. Correlate all events
PhishEmail
| join kind=inner (AttachmentDownload) on NetworkMessageId
| join kind=inner (FileExecution) on SHA256
| join kind=inner (ProcessCreation) on DeviceName
| where ProcessTime > EmailTime  // Process happened after email
| project EmailTime, RecipientEmailAddress, SenderFromAddress, FileName, 
          DeviceName, ProcessTime, ProcessCommandLine
```

### 11.6 User Education and Awareness

**Phishing Simulation Results:**

```
After Incident, Use Attack Simulation Training:

1. Create simulation matching real attack:
   - Phishing technique: Credential theft
   - Theme: Payroll/HR
   - Target: Same users who received real phish

2. Launch simulation:
   - 100 users targeted
   - 15 clicked link (15% click rate)
   - 8 entered credentials (8% compromise rate)

3. Immediate training:
   - Users who clicked/compromised get instant training
   - 10-minute video on identifying phishing
   - Quiz to test understanding

4. Follow-up:
   - Weekly security tips via email
   - Monthly lunch-and-learn sessions
   - Quarterly red team exercises

5. Metrics:
   Track improvement over time:
   - Month 1: 15% click rate
   - Month 3: 10% click rate
   - Month 6: 5% click rate
   - Goal: <3% click rate
```

**Security Awareness Campaign:**

```
Post-Incident Communication:

Subject: Security Alert: Recent Phishing Attempt

Dear Team,

We recently detected and blocked a phishing campaign targeting our organization. 
Here's what you need to know:

What Happened:
- Attackers sent emails appearing to be from HR
- Subject: "Urgent: Update your payroll information"
- Email contained link to fake payroll site
- Goal: Steal your credentials

How We Responded:
- Blocked 105 emails automatically
- Removed 45 emails that were delivered
- Blocked the malicious domain
- No accounts were compromised ✅

Red Flags to Watch For:
⚠️ Urgent requests via email
⚠️ Misspelled domains (c0ntoso.com vs contoso.com)
⚠️ Requests for credentials or sensitive info
⚠️ Suspicious sender (personal email for work topics)

What You Should Do:
✅ Always verify requests via phone/Teams (not email reply)
✅ Hover over links before clicking (check URL)
✅ Report suspicious emails (click "Report Phishing" button)
✅ Use password manager (detects fake sites)
✅ Enable MFA on all accounts

Questions?
Contact IT Security: security@contoso.com

Stay vigilant!
- IT Security Team
```

**🎯 Exam Tip:**
- **AIR** (Automated Investigation & Response) = **MDO Plan 2 only**
- AIR automation levels: **Manual**, **Semi-automated** (recommended), **Fully automated**
- Manual actions: **Soft delete**, **Hard delete** (🆕), Move to Junk, Move to Inbox
- 🆕 **Sept 2025**: Manual actions now in **unified Action Center**
- 🆕 **Sept 2025**: **Sender's copy cleanup** (removes from Sent Items)
- 🆕 **Hard delete** now works on **malicious calendar invites** (2025)
- **Cross-product investigation**: Unified incidents correlate MDO + MDE + MDI + MDCA
- Post-incident: **User education**, **policy tuning**, **attack simulation training**

---

## 12. Advanced Hunting for Email Threats

### 12.1 Email-Related Tables

**Primary Tables:**

| Table | Contains | Retention | Use Cases |
|-------|----------|-----------|-----------|
| **EmailEvents** | All email metadata | 30 days | Email flow, threat detection, campaigns |
| **EmailAttachmentInfo** | Attachment details | 30 days | Malware hunting, file tracking |
| **EmailUrlInfo** | URLs in emails | 30 days | Phishing URL tracking |
| **EmailPostDeliveryEvents** | Post-delivery actions (ZAP, user, admin) | 30 days | ZAP tracking, remediation audit |
| **UrlClickEvents** 🆕 | Safe Links click data | 30 days | User behavior, blocked clicks |

**Supporting Tables:**

| Table | Contains | Integration |
|-------|----------|-------------|
| **IdentityInfo** | User details, priority accounts | Cross-reference with EmailEvents |
| **IdentityLogonEvents** | Authentication attempts | Correlate email access with auth |
| **DeviceFileEvents** | File operations | Track email attachment execution |
| **DeviceProcessEvents** | Process execution | Macro execution, malware behavior |
| **AlertEvidence** | Alert data | Incident correlation |

### 12.2 EmailEvents Table

**Schema:**

```kql
// View schema
EmailEvents
| getschema

// Key columns:
Timestamp                  - When email processed
NetworkMessageId           - Unique email identifier
InternetMessageId          - SMTP message ID
SenderFromAddress          - Sender (From header)
SenderMailFromAddress      - Envelope sender (MAIL FROM)
SenderFromDomain           - Sender domain
SenderIPv4                 - Sending server IP
RecipientEmailAddress      - Recipient
RecipientObjectId          - Azure AD ObjectId
Subject                    - Email subject
ThreatTypes                - Detected threats (Phish, Malware, Spam)
DetectionMethods           - How detected (File detonation, URL reputation, etc.)
DeliveryAction             - What happened (Delivered, Blocked, etc.)
DeliveryLocation           - Where delivered (Inbox, Junk, Quarantine, etc.)
ThreatNames                - Specific threat names
AuthenticationDetails      - SPF/DKIM/DMARC results (JSON)
AttachmentCount            - Number of attachments
UrlCount                   - Number of URLs
EmailDirection             - Inbound, Outbound, Intra-org
Connectors                 - Mail flow connectors used
```

### 12.3 Common Email Hunting Queries

**Query 1: Find All Phishing Emails (Last 7 Days)**

```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, 
          ThreatTypes, DetectionMethods, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

**Query 2: Emails from External Domains to Priority Accounts**

```kql
// Get priority accounts
let PriorityAccounts = IdentityInfo
| where Tags has "Priority account"
| distinct AccountUpn;

// Find external emails to priority accounts
EmailEvents
| where Timestamp > ago(30d)
| where RecipientEmailAddress in (PriorityAccounts)
| where SenderFromDomain !endswith "contoso.com" // External only
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, 
          ThreatTypes, DeliveryAction
| order by Timestamp desc
```

**Query 3: Phishing Campaign Detection (Similar Subjects)**

```kql
// Find emails with similar subjects (potential campaign)
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| summarize Recipients = make_set(RecipientEmailAddress), 
            Count = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
    by Subject, SenderFromAddress
| where Count > 5 // 5+ emails with same subject = campaign
| order by Count desc
```

**Query 4: Emails with Malicious Attachments**

```kql
EmailEvents
| where Timestamp > ago(7d)
| where AttachmentCount > 0
| where ThreatTypes has "Malware"
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp > ago(7d)
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject,
          FileName, FileType, ThreatNames, DeliveryAction
| order by Timestamp desc
```

**Query 5: Zero-Hour Auto Purge (ZAP) Activity**

```kql
// Emails removed by ZAP after delivery
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where Action == "ZAP"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, 
          ThreatTypes, DeliveryLocation
| join kind=inner (
    EmailEvents
    | project NetworkMessageId, SenderFromAddress, Subject
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes
| order by Timestamp desc
```

**Query 6: Authentication Failures (Potential Spoofing)**

```kql
EmailEvents
| where Timestamp > ago(7d)
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend SPF = tostring(AuthDetails.SPF)
| extend DKIM = tostring(AuthDetails.DKIM)
| extend DMARC = tostring(AuthDetails.DMARC)
| where SPF == "fail" or DKIM == "fail" or DMARC == "fail"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject,
          SPF, DKIM, DMARC, DeliveryAction
| order by Timestamp desc
```

**Query 7: Top Senders of Spam**

```kql
EmailEvents
| where Timestamp > ago(30d)
| where ThreatTypes has "Spam"
| summarize SpamCount = count(), 
            Recipients = dcount(RecipientEmailAddress)
    by SenderFromDomain
| order by SpamCount desc
| take 20
```

**Query 8: Users Receiving Most Threats**

```kql
EmailEvents
| where Timestamp > ago(30d)
| where isnotempty(ThreatTypes)
| summarize ThreatCount = count(),
            ThreatTypes = make_set(ThreatTypes),
            Senders = make_set(SenderFromAddress)
    by RecipientEmailAddress
| order by ThreatCount desc
| take 20
```

### 12.4 UrlClickEvents Table (🆕 2025)

**Schema:**

```kql
UrlClickEvents
| getschema

// Key columns:
Timestamp                  - When click occurred
NetworkMessageId           - Email containing URL
Url                        - Full URL clicked
UrlDomain                  - Domain of URL
ThreatTypes                - URL threats (Phish, Malware)
ActionType                 - ClickAllowed, ClickBlocked, ClickWarning
AccountUpn                 - User who clicked
AccountObjectId            - Azure AD ObjectId
IPAddress                  - User's IP address
ClickSource                - Email, Teams, Office app
```

**Common UrlClickEvents Queries:**

**Query 1: All Blocked Clicks (Last 7 Days)**

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| project Timestamp, AccountUpn, Url, ThreatTypes, ClickSource
| order by Timestamp desc
```

**Query 2: Users Who Clicked Phishing Links**

```kql
UrlClickEvents
| where Timestamp > ago(30d)
| where ThreatTypes has "Phish"
| where ActionType in ("ClickAllowed", "ClickWarning")  // Clicked despite warning
| summarize ClickCount = count(),
            PhishingUrls = make_set(Url)
    by AccountUpn
| order by ClickCount desc
```

**Query 3: Most Clicked Malicious URLs**

```kql
UrlClickEvents
| where Timestamp > ago(30d)
| where ActionType in ("ClickBlocked", "ClickWarning")
| summarize Clicks = count(),
            UniqueUsers = dcount(AccountUpn)
    by Url, ThreatTypes
| order by Clicks desc
| take 20
```

**Query 4: Click-Through Rate (Users Bypassing Warnings)**

```kql
// Users who clicked "Continue anyway" on warnings
UrlClickEvents
| where Timestamp > ago(30d)
| summarize TotalClicks = count(),
            Warned = countif(ActionType == "ClickWarning"),
            Blocked = countif(ActionType == "ClickBlocked"),
            Allowed = countif(ActionType == "ClickAllowed")
    by AccountUpn
| extend ClickThroughRate = round(100.0 * Allowed / TotalClicks, 2)
| where ClickThroughRate > 0
| order by ClickThroughRate desc
```

**Query 5: Correlate Phishing Email with Clicks**

```kql
// Find phishing emails and whether recipients clicked links
let PhishingEmails = EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress;

PhishingEmails
| join kind=leftouter (
    UrlClickEvents
    | where Timestamp > ago(7d)
) on NetworkMessageId
| project RecipientEmailAddress, Subject, SenderFromAddress, 
          Clicked = isnotnull(Url), Url, ActionType
| summarize ClickedCount = countif(Clicked == true), 
            TotalRecipients = dcount(RecipientEmailAddress)
    by Subject, SenderFromAddress
| extend ClickRate = round(100.0 * ClickedCount / TotalRecipients, 2)
| order by ClickedCount desc
```

### 12.5 Advanced Cross-Table Queries

**Query: Complete Email-to-Endpoint Attack Chain**

```kql
// 1. Phishing email delivered
let PhishEmail = EmailEvents
| where Timestamp > ago(24h)
| where ThreatTypes has "Phish"
| where AttachmentCount > 0
| project EmailTime=Timestamp, RecipientEmailAddress, NetworkMessageId;

// 2. Attachment info
let Attachments = EmailAttachmentInfo
| where Timestamp > ago(24h)
| project NetworkMessageId, FileName, SHA256;

// 3. File saved to disk (MDE)
let FileSaved = DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath has "Downloads"
| project FileTime=Timestamp, DeviceName, FileName, SHA256, InitiatingProcessAccountName;

// 4. File executed (MDE)
let FileExecuted = DeviceProcessEvents
| where Timestamp > ago(24h)
| where FolderPath has "Downloads"
| project ExecTime=Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName;

// Correlate all events
PhishEmail
| join kind=inner (Attachments) on NetworkMessageId
| join kind=inner (FileSaved) on SHA256
| join kind=inner (FileExecuted) on FileName, DeviceName
| where FileTime > EmailTime and ExecTime > FileTime
| project EmailTime, RecipientEmailAddress, FileName, 
          FileTime, ExecTime, DeviceName, ProcessCommandLine
| order by EmailTime asc
```

**Query: Find Lateral Movement After Email Compromise**

```kql
// 1. Phishing email clicked
let PhishClicks = UrlClickEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where ActionType in ("ClickAllowed", "ClickWarning")
| project ClickTime=Timestamp, AccountUpn;

// 2. Suspicious authentication after click
let SuspiciousAuth = IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where IPAddress !startswith "192.168." // External IP
| project AuthTime=Timestamp, AccountUpn, DeviceName, IPAddress;

// Correlate: Auth within 1 hour of phishing click
PhishClicks
| join kind=inner (SuspiciousAuth) on AccountUpn
| where AuthTime between (ClickTime .. (ClickTime + 1h))
| project ClickTime, AuthTime, AccountUpn, DeviceName, IPAddress
| extend TimeDifference = AuthTime - ClickTime
| order by ClickTime asc
```

### 12.6 Creating Custom Detection Rules

**Convert Query to Detection Rule:**

```
Scenario: Alert when priority accounts receive 3+ phishing emails in 1 hour

Step 1: Write query
let PriorityAccounts = IdentityInfo
| where Tags has "Priority account"
| distinct AccountUpn;

EmailEvents
| where Timestamp > ago(1h)
| where RecipientEmailAddress in (PriorityAccounts)
| where ThreatTypes has "Phish"
| summarize PhishCount = count(), 
            Senders = make_set(SenderFromAddress)
    by RecipientEmailAddress
| where PhishCount >= 3

Step 2: Create detection rule
1. Advanced hunting → Run query
2. "Create detection rule" button
3. Configure:
   - Name: "Priority account targeted by phishing campaign"
   - Frequency: Every 1 hour
   - Alert threshold: 1 or more results
   - Severity: High
   - Impacted entities: RecipientEmailAddress
   - Alert description: "Priority account {{RecipientEmailAddress}} received {{PhishCount}} phishing emails from {{Senders}}"
   - Recommended actions: "1. Review emails in Threat Explorer. 2. Contact user to verify no click/compromise. 3. Block sender domains."

Step 3: Save

Result:
- Query runs every hour
- If conditions met → Incident created
- SOC team alerted
- Automated response can be configured
```

### 12.7 Hunting for Specific Threats

**Hunt 1: Business Email Compromise (BEC)**

```kql
// Indicators: Internal sender impersonation, urgent financial request
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" // External source
| where SenderFromDomain !in ("contoso.com", "contoso-partners.com") // Not real internal
| where Subject has_any ("urgent", "wire transfer", "payment", "invoice", "funds")
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend DMARC = tostring(AuthDetails.DMARC)
| where DMARC == "fail" or SenderFromAddress has "ceo" or SenderFromAddress has "cfo"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, 
          DMARC, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

**Hunt 2: Credential Phishing Targeting O365**

```kql
// Look for URLs mimicking Microsoft login pages
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| join kind=inner (
    EmailUrlInfo
    | where Url has_any ("office365", "microsoft", "login", "outlook")
    | where UrlDomain !endswith "microsoft.com"
    | where UrlDomain !endswith "office.com"
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, 
          Url, UrlDomain, DeliveryAction
| order by Timestamp desc
```

**Hunt 3: QR Code Phishing (🆕 Trend 2024-2025)**

```kql
// QR codes embedded in images (common phishing tactic)
EmailEvents
| where Timestamp > ago(7d)
| where Subject has_any ("qr", "scan", "code", "verify", "authentication")
| where AttachmentCount > 0
| join kind=inner (
    EmailAttachmentInfo
    | where FileType in ("png", "jpg", "jpeg", "pdf")
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, 
          FileName, FileType, ThreatTypes, DeliveryAction
| order by Timestamp desc
```

**🎯 Exam Tip:**
- Primary email tables: **EmailEvents**, **EmailAttachmentInfo**, **EmailUrlInfo**, **EmailPostDeliveryEvents**
- 🆕 **UrlClickEvents** table (2025) = Safe Links click data
- **Retention**: 30 days for all email tables
- Common fields: **NetworkMessageId** (unique email ID), **ThreatTypes**, **DeliveryAction**, **DeliveryLocation**
- **Cross-table joins**: Use NetworkMessageId, SHA256, AccountUpn, DeviceName to correlate
- **Custom detection rules**: Create from Advanced Hunting queries, run on schedule
- **Priority accounts**: Filter by `Tags has "Priority account"` in IdentityInfo table

---

## 13. Attack Simulation Training

### 13.1 Overview

**What is Attack Simulation Training?**

**Attack Simulation Training** (MDO Plan 2 only) allows you to run **realistic phishing simulations** on your users to:
- Test user awareness
- Identify vulnerable users
- Provide immediate training
- Measure improvement over time

**Benefits:**

```
1. Safe Environment
   - No real risk (emails from Microsoft, not actual attackers)
   - Controlled testing
   - Educational purpose

2. Immediate Training
   - Users who fall for sim get instant training
   - 10-15 minute micro-learning
   - Reinforces safe behaviors

3. Metrics and Reporting
   - Track compromise rate over time
   - Identify departments needing more training
   - Prove ROI of security awareness program

4. Realistic Attacks
   - Mimics real-world phishing tactics
   - Based on current threat landscape
   - Covers various techniques (credential harvesting, malware, link, attachment)
```

### 13.2 Simulation Techniques

**Available Techniques:**

```
1. Credential Harvest
   - Fake login page (O365, banking, etc.)
   - Captures username/password (simulated)
   - User gets training immediately
   - Most common technique (70% of real phishing)

2. Malware Attachment
   - Simulated malicious attachment
   - User opens attachment → Training delivered
   - No actual malware (safe)
   - Common file types: .docx, .xlsx, .pdf

3. Link in Attachment
   - Attachment contains link to fake login page
   - Two-stage attack (open attachment, then click link)
   - More sophisticated than simple link

4. Link to Malware
   - Email link leads to fake malware download
   - User clicks → Training delivered
   - No actual malware downloaded

5. Drive-by URL
   - Link to compromised-looking website
   - Mimics legitimate sites with malware
   - Tests user's URL awareness

6. OAuth Consent Grant
   - Simulates app permission request scam
   - "App wants to access your data"
   - User grants permission → Training delivered
```

### 13.3 Creating Simulations

**Method 1: Built-in Simulation Wizard**

```
1. Defender Portal → Email & collaboration → Attack simulation training
2. "+ Simulate phishing attack"
3. Configure:

Step 1: Technique
- Choose: Credential Harvest (recommended for first simulation)

Step 2: Payload
- Select from library:
  * "Microsoft Office 365 Password Expiration"
  * "IT Department Security Update"
  * "HR Benefits Enrollment"
  * "Package Delivery Notification"
  * "Payroll Update Required"

- OR: Create custom payload
  * Subject: [Custom]
  * Body: [Custom HTML/text]
  * Login page: [Custom branding]

Step 3: Target Users
- All users
- OR: Specific groups/users
- Exclude: C-level executives (first simulation)
- Preview: Shows how email looks

Step 4: Training Assignment
- Assign training to:
  * Users who click link
  * Users who enter credentials
  * All users (awareness)

- Training content:
  * Microsoft-provided: 10-min video
  * Custom: Upload own content
  * None: Simulation only

Step 5: End User Notifications
- Notify users it was simulation? (Recommended: Yes, after training)
- Notification timing:
  * Immediate (after falling for sim)
  * Delayed (1 day later)
  * No notification

Step 6: Launch Settings
- Launch now
- OR: Schedule for later (date/time)
- Frequency: One-time or recurring (weekly, monthly)

Step 7: Review and Launch
```

**Built-in Payloads (Examples):**

```
Credential Harvest Payloads:
├─ "Your password will expire in 24 hours"
├─ "Unusual sign-in activity detected"
├─ "Complete your security training (urgent)"
├─ "Verify your account information"
└─ "Your mailbox is almost full"

Malware Attachment Payloads:
├─ "Invoice from vendor [see attachment]"
├─ "Package delivery slip [open PDF]"
├─ "Performance review [see document]"
└─ "Updated employee handbook [download]"

Link-based Payloads:
├─ "Congratulations! You've won a prize"
├─ "COVID-19 benefits update [click here]"
├─ "Your shipment is delayed [track package]"
└─ "HR policy change [read more]"
```

### 13.4 Custom Payloads

**Creating Custom Payload:**

```
Purpose: Tailor simulation to your organization's threats

Example: Finance Department Wire Transfer Phishing

1. Attack sim → Payloads → + Create payload
2. Configure:

Payload Settings:
├─ Name: "CEO Wire Transfer Request"
├─ Description: "BEC simulation targeting finance team"
├─ Technique: Credential Harvest
│
├─ Email:
│  ├─ From: CEO [Spoofed display name]
│  ├─ Subject: "Urgent: Wire Transfer Needed"
│  ├─ Body:
│  │   Hi [FirstName],
│  │   
│  │   I'm in a meeting and need you to wire $50,000
│  │   to our acquisition partner immediately. Time-sensitive!
│  │   
│  │   Please confirm your credentials to authorize:
│  │   [Fake finance portal link]
│  │   
│  │   Thanks,
│  │   CEO Name
│
├─ Landing Page:
│  ├─ Fake finance portal login
│  ├─ Organization branding (logo, colors)
│  ├─ Username/password fields
│  └─ "Submit" button (captures input)
│
└─ Training:
   ├─ Immediate: "You just fell for a BEC simulation!"
   ├─ Explanation: Wire transfer fraud techniques
   ├─ Video: 5-minute BEC awareness training
   └─ Quiz: 3 questions to test understanding

3. Preview and Save
```

### 13.5 Simulation Workflow

**User Experience:**

```
Simulation: "Password Expiration" Credential Harvest

User Flow:

1. User receives email:
   ┌────────────────────────────────────────┐
   │ From: Microsoft 365 <noreply@...>     │
   │ Subject: Your password expires in 24h │
   │                                        │
   │ Your password will expire tomorrow.   │
   │ Click here to reset: [Reset Password] │
   └────────────────────────────────────────┘

2a. User IGNORES email:
    Result: Passed simulation ✅
    Action: No training needed (user vigilant)

2b. User CLICKS link:
    → Redirected to fake Microsoft login page

3a. User ENTERS credentials:
    → Immediately shown training splash:
    ┌─────────────────────────────────────┐
    │  ⚠️ THIS WAS A SIMULATION          │
    │                                     │
    │  You just provided your password   │
    │  to a fake site. In a real attack, │
    │  your account would be compromised.│
    │                                     │
    │  [Start Training →]                 │
    └─────────────────────────────────────┘

3b. User CLOSES page without entering credentials:
    → Shown warning:
    ┌─────────────────────────────────────┐
    │  ⚠️ THIS WAS A SIMULATION          │
    │                                     │
    │  You clicked a link in a suspicious│
    │  email. Always verify before       │
    │  clicking!                         │
    │                                     │
    │  [Learn More →]                     │
    └─────────────────────────────────────┘

4. Training delivered:
   - 10-minute video: "Identifying Phishing Emails"
   - Interactive quiz: 5 questions
   - Certificate of completion
   - Added to training records

5. Post-simulation email (optional):
   ┌─────────────────────────────────────┐
   │ Subject: Security Training Update  │
   │                                     │
   │ You recently completed a phishing  │
   │ simulation. [Pass/Fail]            │
   │                                     │
   │ Remember: Always verify requests!  │
   └─────────────────────────────────────┘
```

### 13.6 Reporting and Metrics

**Simulation Report:**

```
Simulation: "Password Expiration" (Credential Harvest)
Date: October 1-15, 2025
Target: 500 users

Results:
┌─────────────────────────────────────────┐
│ Sent: 500 emails                       │
│ Clicked link: 75 users (15%)          │
│ Entered credentials: 30 users (6%)    │
│ Reported phishing: 120 users (24%)    │
│                                         │
│ Compromise Rate: 6% ⚠️                  │
│ Click Rate: 15% ⚠️                      │
│ Report Rate: 24% ✅ (Improving!)        │
└─────────────────────────────────────────┘

Breakdown by Department:
┌────────────────────────────────────────┐
│ Dept        | Click% | Compromise%   │
├────────────────────────────────────────┤
│ Finance     |   8%   |     2%        │ ✅ Best
│ Sales       |  22%   |    12%        │ ⚠️ Needs training
│ HR          |  12%   |     5%        │
│ IT          |   5%   |     1%        │ ✅ Excellent
│ Marketing   |  18%   |     8%        │ ⚠️
└────────────────────────────────────────┘

Users Who Fell for Simulation:
├─ user1@contoso.com: Clicked + Entered credentials
├─ user2@contoso.com: Clicked + Entered credentials
├─ user3@contoso.com: Clicked only
└─ [27 more users...]

Action: All 30 users assigned mandatory training

Training Completion:
├─ Completed: 25 users (83%)
├─ In progress: 3 users
├─ Not started: 2 users (follow-up required)
```

**Trend Analysis:**

```
Quarterly Simulation Results:

Q1 2025:
- Compromise rate: 12%
- Click rate: 25%
- Report rate: 15%

Q2 2025:
- Compromise rate: 9% (⬇️ -3%)
- Click rate: 20% (⬇️ -5%)
- Report rate: 18% (⬆️ +3%)

Q3 2025:
- Compromise rate: 6% (⬇️ -3%)
- Click rate: 15% (⬇️ -5%)
- Report rate: 24% (⬆️ +6%)

Trend: Improving! ✅
Goal: <5% compromise rate by end of year
```

**User Resilience Score:**

```
Individual User Report:

John Doe (john.doe@contoso.com)

Simulation History:
├─ Oct 2024: Failed (entered credentials)
├─ Jan 2025: Passed (reported phishing)
├─ Apr 2025: Passed (ignored email)
├─ Jul 2025: Passed (reported phishing)
└─ Oct 2025: Passed (reported phishing)

Resilience Score: 85/100 ✅ (Excellent)

Training Completed:
├─ Phishing Fundamentals: ✅ 100%
├─ BEC Awareness: ✅ 100%
├─ Malware Recognition: ✅ 100%
└─ Social Engineering Tactics: ✅ 100%

Status: Security Champion 🏆
Eligible for advanced security awareness program
```

### 13.7 Best Practices

**Simulation Strategy:**

```
1. Start Simple, Increase Difficulty
   Month 1: Obvious phishing (poor grammar, generic)
   Month 3: Moderate (better quality, targeted)
   Month 6: Advanced (perfect grammar, personalized)
   Month 12: Sophisticated (APT-style, multi-stage)

2. Vary Techniques
   - Don't always use same tactic
   - Rotate: Credential harvest → Malware → Link → Attachment
   - Surprise users (avoid patterns)

3. Target All Departments
   - IT may be savvy, but test everyone
   - Don't exclude C-level (they're prime targets!)
   - Rotate which departments tested each month

4. Timing Matters
   - Avoid Monday mornings (users busy, may miss training)
   - Avoid major holidays (low participation)
   - Spread throughout month (not all on same day)
   - Random times (9am-5pm, any day)

5. Make Training Relevant
   - Customize to actual threats facing organization
   - Use real-world examples
   - Keep training short (10-15 min max)
   - Make it engaging (videos, quizzes, not just text)

6. Positive Reinforcement
   - Celebrate users who report phishing
   - Recognize "Security Champions"
   - Reward departments with low compromise rates
   - Don't shame users who fail (learning opportunity)

7. Continuous Improvement
   - Monthly or quarterly simulations
   - Track trends (not just pass/fail)
   - Adjust difficulty based on results
   - Focus on high-risk departments

8. Leadership Buy-In
   - Include executives in simulations
   - Report metrics to CISO/leadership
   - Show ROI (prevented incidents, reduced risk)
   - Make security awareness part of culture
```

**Simulation Frequency:**

```
Recommended Schedule:

Small Organization (<500 users):
- Quarterly simulations (4x per year)
- All users included each time

Medium Organization (500-5000 users):
- Monthly simulations
- Rotate departments/teams
- Each user tested 2-4x per year

Large Organization (>5000 users):
- Bi-weekly or weekly simulations
- Automated campaigns
- Each user tested 4-6x per year

High-Risk Organizations (Finance, Healthcare):
- Weekly simulations
- Continuous testing
- Each user tested 6-12x per year
```

### 13.8 Integration with Real Threats

**Post-Incident Simulation:**

```
Scenario: Real phishing attack detected

Timeline:
Day 1: Real phishing campaign detected and blocked
Day 2: Security team sends awareness email to all users
Day 3: Launch simulation mimicking the real attack

Purpose:
✅ Test if users learned from incident
✅ Identify users who still vulnerable
✅ Reinforce security awareness in context
✅ Measure effectiveness of incident communication

Example:
- Real attack: Fake Docusign email with malicious link
- Simulation: Similar Docusign email (but safe) 1 week later
- Result: Compromise rate drops from 8% (real attack) to 3% (simulation)
```

**Simulation Based on Threat Intelligence:**

```
Q4 2025 Threat Landscape:
- QR code phishing increasing 300%
- Attackers using QR codes in emails to bypass URL filters

Response:
1. Create QR code phishing simulation
   - Email: "Verify your account (scan QR code)"
   - QR code leads to fake login page
   - Tests user awareness of QR code risks

2. Launch simulation
3. Measure click rate
4. Provide QR code-specific training
5. Retest in 30 days to measure improvement
```

**🎯 Exam Tip:**
- **Attack Simulation Training** = **MDO Plan 2 only**
- **Techniques**: Credential Harvest, Malware Attachment, Link in Attachment, Link to Malware, Drive-by URL, OAuth Consent Grant
- **Most common**: **Credential Harvest** (~70% of real phishing)
- **User flow**: Email → Click → (Optional) Enter credentials → Training delivered immediately
- **Metrics**: Compromise rate, Click rate, Report rate (track improvement)
- **Best practice**: Start simple, increase difficulty, vary techniques, quarterly+ frequency
- **Training**: Immediate (when user fails simulation), micro-learning (10-15 min)
- **Integration**: Simulate real threats, post-incident testing, threat intel-driven

---

## 14. Configuration Best Practices

### 14.1 Recommended Configuration

**Preset Security Policies:**

```
Microsoft provides 3 preset security levels:

1. Standard Protection (Recommended for most orgs)
2. Strict Protection (High-security environments)
3. Custom (Build your own)

Standard vs Strict Comparison:

| Setting | Standard | Strict |
|---------|----------|--------|
| Phishing threshold | 2 - Aggressive | 3 - More Aggressive |
| Bulk threshold | 7 | 5 |
| Spam action | Move to Junk | Quarantine |
| Safe Links click-through | Allow with warning | Block (no bypass) |
| Safe Attachments action | Dynamic Delivery | Block |

Recommendation:
- Start with Standard (30 days)
- Move high-risk users to Strict (executives, finance, HR)
- Gradually tighten for all users based on metrics
```

**Best Practice Configuration:**

```
Protection Layer          | Configuration
─────────────────────────────────────────────────────
Anti-Phishing:
├─ Phishing threshold     | 2 (Aggressive) for standard users
│                         | 3 (More Aggressive) for priority accounts
├─ User impersonation     | Enabled (protect CEO, CFO, top 10-20 users)
├─ Domain impersonation   | Enabled (protect primary domain + key subdomains)
├─ Mailbox intelligence   | Enabled
├─ Safety tips            | All enabled
└─ Spoof intelligence     | Enabled

Safe Attachments:
├─ Action                 | Dynamic Delivery (user experience)
│                         | OR Block (maximum security for sensitive users)
├─ Redirect               | Enabled → security@contoso.com
├─ SharePoint/OneDrive    | Enabled
└─ Apply on scan error    | Enabled

Safe Links:
├─ URL rewriting          | Enabled
├─ Real-time scanning     | Enabled
├─ Teams protection       | Enabled
├─ Office apps protection | Enabled
├─ Track clicks           | Enabled (threat hunting)
└─ Click-through          | Disabled (no user bypass)

Anti-Spam:
├─ Bulk threshold         | 7 (standard users), 5 (sensitive users)
├─ Spam action            | Move to Junk (standard), Quarantine (priority)
├─ High confidence spam   | Quarantine
├─ Phishing               | Quarantine
├─ High confidence phish  | Quarantine
└─ ZAP                    | Enabled (spam + phishing)

Anti-Malware:
├─ Malware action         | Quarantine (not delete)
├─ Common attachment filter | Enabled (block .exe, .bat, .vbs, etc.)
├─ Notify internal sender | Enabled
└─ Notify external sender | Disabled (don't reveal detection)
```

### 14.2 Policy Structure

**Best Practice Policy Hierarchy:**

```
Policy Priority (Highest to Lowest):

1. VIP Protection (Priority 0)
   ├─ Applied to: CEO, CFO, Board members (Priority accounts)
   ├─ Settings: Most aggressive (Strict preset)
   └─ Policies: Anti-phishing, Safe Links, Safe Attachments, Anti-spam

2. Finance/HR Protection (Priority 1)
   ├─ Applied to: Finance team, HR team
   ├─ Settings: Aggressive (between Standard and Strict)
   └─ Reason: High-value targets for BEC, data theft

3. IT/Security Team (Priority 2)
   ├─ Applied to: IT admins, security team
   ├─ Settings: Moderate (Standard preset)
   └─ Reason: More sophisticated users, but still test

4. Standard Users (Priority 999 - Lowest)
   ├─ Applied to: Everyone else
   ├─ Settings: Standard preset
   └─ Reason: Baseline protection

Built-in Protection (Default - Always applies)
   └─ Catch-all for any users not covered above

Recommendation:
- Use priority to ensure VIPs get strictest protection
- Standard users get balanced protection
- No one falls through cracks (built-in protection as safety net)
```

### 14.3 Testing and Validation

**Pre-Production Testing:**

```
Before deploying to production:

1. Pilot Group Testing (2-4 weeks)
   ├─ Select: 50-100 diverse users
   │  ├─ Mix of departments
   │  ├─ Mix of roles (end users, power users, admins)
   │  └─ Include security team
   │
   ├─ Deploy: Proposed policies to pilot group only
   │
   ├─ Monitor:
   │  ├─ False positive rate (legitimate emails blocked)
   │  ├─ User complaints
   │  ├─ Threat detection effectiveness
   │  └─ Performance impact
   │
   └─ Collect Feedback:
      ├─ User surveys
      ├─ Helpdesk tickets
      └─ Threat metrics

2. Gradual Rollout (4-8 weeks)
   ├─ Week 1-2: 10% of users (pilot + early adopters)
   ├─ Week 3-4: 25% of users
   ├─ Week 5-6: 50% of users
   ├─ Week 7-8: 100% of users
   │
   └─ At each stage:
      ├─ Monitor metrics
      ├─ Adjust policies if needed
      └─ Communicate with users

3. Final Tuning (Ongoing)
   ├─ Review false positives weekly
   ├─ Create exclusions where justified
   ├─ Adjust thresholds based on data
   └─ Continuous improvement
```

**Test Email Flow:**

```
Validation Tests:

1. External to Internal (Inbound)
   ├─ Send test email from external account
   ├─ Verify: SPF/DKIM/DMARC checks
   ├─ Verify: Anti-spam filtering
   ├─ Verify: Safe Attachments scanning
   └─ Verify: Safe Links rewriting

2. Internal to External (Outbound)
   ├─ Send test email to external account
   ├─ Verify: DKIM signing enabled
   ├─ Verify: Email delivered
   └─ Verify: Headers show proper authentication

3. Internal to Internal (Intra-org)
   ├─ Send test email between users
   ├─ Verify: Internal scanning (if enabled)
   └─ Verify: Policies apply (if configured)

4. Known Malicious (Test file)
   ├─ Use EICAR test file (safe malware test)
   ├─ Attach to email and send
   ├─ Verify: Safe Attachments blocks it
   └─ Verify: Alert generated

5. Phishing Simulation
   ├─ Use Attack Simulation Training
   ├─ Send simulated phish to test group
   ├─ Verify: Anti-phishing detection
   └─ Verify: User training delivered if clicked
```

### 14.4 Monitoring and Maintenance

**Daily Tasks:**

```
☐ Review new alerts (Defender Portal → Incidents)
☐ Check for critical incidents (High/Critical severity)
☐ Monitor quarantine (any legitimate emails blocked?)
☐ Review user-reported submissions
☐ Check Action Center for pending AIR actions
```

**Weekly Tasks:**

```
☐ Review Threat Explorer for campaigns
☐ Analyze top targeted users
☐ Check for new threat trends
☐ Review false positive submissions
☐ Update allow/block lists if needed
☐ Check sensor health (if applicable)
☐ Review phishing simulation results
```

**Monthly Tasks:**

```
☐ Full policy review (any changes needed?)
☐ Analyze email security reports
☐ Review priority account protection effectiveness
☐ Check DMARC reports for authentication issues
☐ Update protected users/domains in anti-phishing
☐ Rotate honeytoken credentials (if applicable)
☐ Security awareness training review
☐ Update documentation
```

**Quarterly Tasks:**

```
☐ Full security posture assessment
☐ Review all exclusions (still needed?)
☐ Update email authentication (SPF/DKIM/DMARC)
☐ Test disaster recovery procedures
☐ Review Secure Score recommendations
☐ Conduct tabletop exercise
☐ Update security policies based on threat landscape
☐ Executive report to CISO/leadership
```

### 14.5 Common Mistakes to Avoid

**❌ Mistake 1: Over-Exclusions**

```
Problem:
- Adding too many exclusions (allow lists)
- "This vendor gets blocked a lot, just allow them"
- Exclusions reduce protection

Solution:
- Investigate WHY vendor is blocked
- Fix authentication (SPF/DKIM/DMARC) instead of excluding
- Only exclude as last resort with approval
- Review exclusions quarterly
- Document business justification
```

**❌ Mistake 2: Not Enabling ZAP**

```
Problem:
- ZAP disabled to "reduce false positives"
- Malicious emails stay in user mailboxes

Solution:
- Always enable ZAP (for spam, phishing, malware)
- Accept that some FPs may occur
- Users can recover from Deleted Items if needed
- Risk of NOT using ZAP > risk of FPs
```

**❌ Mistake 3: Allowing User Click-Through on Safe Links**

```
Problem:
- "Let users click through to original URL" enabled
- Users bypass warnings, get compromised

Solution:
- DISABLE click-through (no "Continue anyway" button)
- Users should never need to bypass security warnings
- If legitimate site blocked, admin can add to allow list
```

**❌ Mistake 4: Not Testing Changes**

```
Problem:
- Making policy changes directly in production
- Breaking email flow
- Causing user disruption

Solution:
- Always test with pilot group first
- Start with "Monitor" or lower thresholds
- Gradually increase restrictions
- Have rollback plan
```

**❌ Mistake 5: Ignoring Authentication (SPF/DKIM/DMARC)**

```
Problem:
- Not configuring email authentication
- Allows spoofing
- Legitimate email gets blocked

Solution:
- Configure SPF (day 1)
- Enable DKIM (week 1)
- Implement DMARC (month 1, p=none → p=quarantine → p=reject)
- Monitor DMARC reports continuously
```

**❌ Mistake 6: Set-and-Forget Mentality**

```
Problem:
- Deploying MDO once and never reviewing
- Threat landscape evolves
- Policies become outdated

Solution:
- Continuous monitoring (daily/weekly tasks)
- Regular policy reviews (monthly/quarterly)
- Stay updated on new threats
- Adapt policies to emerging threats
```

**🎯 Exam Tip:**
- **Standard Protection** vs **Strict Protection** = Preset security policies
- **Standard**: Balanced (most orgs), **Strict**: High security (VIPs, finance, HR)
- **Policy priority**: 0 = Highest (VIPs), 999 = Lowest (default)
- **Testing**: Always pilot first (50-100 users, 2-4 weeks)
- **Gradual rollout**: 10% → 25% → 50% → 100%
- **ZAP**: Always enable (don't disable to reduce FPs)
- **Safe Links click-through**: Always DISABLE (no user bypass)
- **Email authentication**: SPF (day 1) → DKIM (week 1) → DMARC (month 1, p=none → p=reject)

---

## 15. Exam Tips and Practice Questions

### 15.1 Key Exam Topics for MDO

**Must-Know Concepts:**

✅ **Plan 1 vs Plan 2**
- Plan 1: Safe Attachments, Safe Links, Real-time detections, Advanced anti-phishing
- Plan 2: All Plan 1 + Threat Explorer, AIR, Attack simulation training, Campaign views

✅ **Safe Attachments**
- **Dynamic Delivery** = Email delivered immediately, attachment scanned, replaced if malicious (recommended)
- **Block** = Most secure, delays email until scan complete
- **Monitor** = REMOVED June 2025 (no longer available)
- SharePoint/OneDrive/Teams protection: Separate toggle

✅ **Safe Links**
- URL rewriting (proxy through Microsoft)
- Time-of-click verification (not just delivery-time)
- Protects in: Email, Teams, Office apps
- **Do not allow click-through** = Best practice (no user bypass)

✅ **Anti-Phishing**
- **User impersonation** = Protect specific individuals (CEO, CFO)
- **Domain impersonation** = Protect your domains from typosquatting
- **Mailbox intelligence** = ML-based anomaly detection
- **Spoof intelligence** = Detect unauthenticated senders
- **Phishing threshold**: 1 (Standard) to 4 (Most Aggressive)

✅ **Anti-Spam & Anti-Malware**
- **SCL** (Spam Confidence Level): 0-9, higher = more spam
- **BCL** (Bulk Complaint Level): 0-9, higher = more bulk
- **ZAP** (Zero-Hour Auto Purge): Retroactive email removal
  - ZAP for malware: ALWAYS ON (cannot disable)
  - ZAP for spam/phishing: Can be enabled/disabled per policy
- **Common Attachment Filter**: Block risky file types (.exe, .bat, .vbs, etc.)

✅ **Email Authentication**
- **SPF**: Authorized sending IPs (v=spf1 include:spf.protection.outlook.com ~all)
- **DKIM**: Cryptographic signature (selector1._domainkey.domain.com CNAME)
- **DMARC**: Policy + Reporting (_dmarc.domain.com TXT record)
  - Stages: p=none (monitor) → p=quarantine → p=reject (goal)

✅ **Threat Explorer**
- **Plan 2 ONLY** (Plan 1 has Real-time detections - limited to 7 days)
- 30 days retention
- Views: All email, Malware, Phish, Submissions, Content malware, URL clicks
- **Email entity page**: Deep dive into individual email
- **Campaign views**: Coordinated attacks (Plan 2 only)
- **Take action**: Soft delete, Hard delete (🆕), Move to Junk, Move to Inbox

✅ **AIR (Automated Investigation & Response)**
- **Plan 2 ONLY**
- Automation levels: Manual, Semi-automated (recommended), Fully automated
- Playbooks: Phishing, Malware, Compromised user
- **Action Center**: Pending actions, History, Unified view

✅ **Advanced Hunting**
- Tables: **EmailEvents**, EmailAttachmentInfo, EmailUrlInfo, EmailPostDeliveryEvents, **UrlClickEvents** (🆕 2025)
- **NetworkMessageId** = Unique email identifier (join key)
- 30 days retention
- Cross-product correlation: Email + Endpoint + Identity

✅ **Attack Simulation Training**
- **Plan 2 ONLY**
- Techniques: **Credential Harvest** (most common), Malware Attachment, Link in Attachment, etc.
- Training: Immediate (when user fails), micro-learning (10-15 min)
- Metrics: Compromise rate, Click rate, Report rate

✅ **Priority Account Protection**
- Tag up to 250 accounts
- Enhanced protection (stricter policies)
- Dedicated reports
- Visible in Threat Explorer, Incident queue
- 🆕 Available in GCC/GCC-H/DoD (2024-2025)

### 15.2 Common Exam Question Types

**Type 1: Feature Identification (Which plan has feature X?)**

Example:
```
Q: Your organization needs to automatically investigate and remediate
   phishing attacks without manual intervention. Which license do you need?

A. Microsoft 365 E3
B. Microsoft Defender for Office 365 Plan 1
C. Microsoft Defender for Office 365 Plan 2
D. Exchange Online Protection

✅ Correct Answer: C - MDO Plan 2
Explanation: AIR (Automated Investigation & Response) is Plan 2 only
```

**Type 2: Configuration (How to set up feature?)**

Example:
```
Q: You need to configure Safe Attachments to deliver emails immediately
   while scanning attachments. What should you configure?

A. Block
B. Replace
C. Dynamic Delivery
D. Monitor

✅ Correct Answer: C - Dynamic Delivery
Explanation: Dynamic Delivery delivers email body immediately,
            attachment scanned in background, best user experience
```

**Type 3: Troubleshooting (Why is this happening?)**

Example:
```
Q: Users report legitimate emails from a vendor are being quarantined.
   You verify the vendor's SPF and DKIM are configured correctly.
   What should you check next?

A. Anti-spam policy bulk threshold
B. Anti-phishing policy domain impersonation
C. Safe Attachments policy
D. Connection filter IP block list

✅ Correct Answer: B - Anti-phishing policy domain impersonation
Explanation: If domain is similar to yours, may trigger domain impersonation.
            Check if vendor domain in protected domains list.
```

**Type 4: Best Practice (What is the recommended approach?)**

Example:
```
Q: You are deploying Safe Links. What is the BEST configuration
   to prevent users from accessing malicious URLs?

A. Enable URL rewriting and real-time scanning
B. Enable URL rewriting and allow users to click through
C. Enable URL rewriting, real-time scanning, and disable click-through
D. Disable URL rewriting and use Safe Links API only

✅ Correct Answer: C
Explanation: Full protection = URL rewriting + real-time scanning + no bypass
            Users should NOT be able to click through warnings
```

**Type 5: Scenario-Based (Multi-step problem solving)**

Example:
```
Q: You detect a phishing campaign targeting 50 users. The emails
   were delivered to inboxes. What should you do first?

A. Create an allow list entry for the sender
B. Submit the email to Microsoft as a false negative
C. Use Threat Explorer to find and delete the emails
D. Reset passwords for all 50 users

✅ Correct Answer: C - Use Threat Explorer to find and delete emails
Explanation: First priority is CONTAINMENT (remove threat).
            Then investigate (who clicked), then remediate (password resets if needed).
            Submit to Microsoft for future prevention.
```

### 15.3 Practice Questions

#### **Question 1: Safe Attachments Configuration**

You are configuring Microsoft Defender for Office 365.
You need to ensure that:
- Emails are delivered to users immediately
- Attachments are scanned for malware
- Malicious attachments are removed if detected
- If scanning fails, the attachment is still blocked

Which Safe Attachments policy action should you use?

A. Block
B. Replace  
C. Dynamic Delivery
D. Monitor

<details>
<summary>Click to see answer</summary>

**✅ Answer: C - Dynamic Delivery**

**Explanation:**

Dynamic Delivery meets all requirements:
- ✅ Emails delivered immediately (no delay)
- ✅ Attachments scanned in background
- ✅ Malicious attachments replaced with warning
- ✅ "Apply if scanning error" setting blocks attachment if scan fails

**Why not others:**
- **A (Block)**: Delays email delivery until scan completes (not immediate)
- **B (Replace)**: Removes attachment completely, doesn't deliver at all
- **D (Monitor)**: REMOVED in June 2025, no longer available

**Key Point:** Dynamic Delivery is the RECOMMENDED action for most organizations.
</details>

---

#### **Question 2: Threat Explorer vs Real-time Detections**

Your organization has Microsoft Defender for Office 365 Plan 1.

Users report suspicious emails. You need to investigate emails received in the last 14 days.

What should you use?

A. Threat Explorer
B. Real-time detections
C. Advanced hunting
D. Message trace

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Real-time detections**

**Explanation:**

With **MDO Plan 1**, you have:
- **Real-time detections**: Limited threat hunting tool
- Retention: **7 days**
- Basic filtering and investigation

Problem: User needs 14 days data, but Real-time detections only has 7 days!

**Why not others:**
- **A (Threat Explorer)**: MDO **Plan 2 only** (30 days retention)
- **C (Advanced hunting)**: Requires MDO Plan 2 for email data (EmailEvents table)
- **D (Message trace)**: Tracks email flow, but doesn't provide threat hunting features

**Reality Check:** Since Plan 1 only has 7 days, best solution is:
1. Use Real-time detections for last 7 days
2. Use Message trace for older emails (up to 10 days)
3. OR: Upgrade to Plan 2 for 30-day retention in Threat Explorer

**Exam Answer:** B is correct based on available tools in Plan 1, but question is slightly tricky!
</details>

---

#### **Question 3: Email Authentication**

You need to configure email authentication for your domain (contoso.com) in Microsoft 365.

You need to:
- Allow Microsoft 365 to send email on behalf of your domain
- Digitally sign outgoing emails
- Specify a policy for receivers to quarantine unauthenticated emails

Which three actions should you perform? (Choose THREE)

A. Create SPF record: v=spf1 include:spf.protection.outlook.com ~all
B. Enable DKIM signing in Microsoft 365 admin center
C. Create CNAME records for DKIM selectors
D. Create DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com
E. Create DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@contoso.com
F. Configure SPF to allow all senders: v=spf1 +all

<details>
<summary>Click to see answer</summary>

**✅ Answers: A, C, E**

**Explanation:**

**A. Create SPF record** ✅
- Allows Microsoft 365 (spf.protection.outlook.com) to send email for your domain
- ~all = SoftFail (recommended, not too strict)

**C. Create CNAME records for DKIM selectors** ✅
- Enables DKIM signing
- Microsoft provides 2 CNAME records:
  - selector1._domainkey.contoso.com
  - selector2._domainkey.contoso.com
- Required step BEFORE enabling DKIM

**E. Create DMARC record with p=quarantine** ✅
- Specifies policy: Quarantine unauthenticated emails
- rua = aggregate reports
- Start with p=quarantine before moving to p=reject

**Why not others:**
- **B**: Enable DKIM is correct, but you must do C first (CNAME records)
- **D (p=reject)**: Too strict for initial deployment, should start with p=quarantine
- **F (+all)**: NEVER use this! Allows anyone to send email as your domain

**Key Point:** SPF → DKIM (CNAME first, then enable) → DMARC (p=quarantine → p=reject)
</details>

---

#### **Question 4: Priority Account Protection**

You have Microsoft Defender for Office 365 Plan 2.

You need to provide enhanced protection for your CEO and CFO.

What should you do?

A. Create a custom anti-phishing policy with aggressive settings and apply to CEO and CFO
B. Tag CEO and CFO as priority accounts in Microsoft 365 admin center
C. Add CEO and CFO to a security group and enable MFA
D. Configure Safe Links to block all URLs for CEO and CFO

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Tag as priority accounts**

**Explanation:**

Priority Account Protection provides:
- Enhanced phishing detection
- Stricter policies automatically
- Dedicated reporting
- Visible across all security tools
- Faster alert escalation

**How to configure:**
1. Microsoft 365 admin center → Users → Active users
2. Select CEO → Account → Priority account → Toggle ON
3. Repeat for CFO

**Why not others:**
- **A**: This is good, but Priority Account tagging does this PLUS more visibility
- **C**: MFA is good but doesn't enhance email protection specifically
- **D**: Blocking all URLs is too restrictive, breaks functionality

**Key Point:** Priority accounts get automatic enhanced protection + visibility.
</details>

---

#### **Question 5: Attack Simulation Training**

You have Microsoft Defender for Office 365 Plan 2.

You want to test your users' ability to identify phishing emails.

Which simulation technique is used in 70% of real-world phishing attacks?

A. Malware Attachment
B. Link in Attachment
C. Credential Harvest
D. Drive-by URL

<details>
<summary>Click to see answer</summary>

**✅ Answer: C - Credential Harvest**

**Explanation:**

**Credential Harvest** is the most common phishing technique:
- Fake login page (Office 365, banking, etc.)
- User enters username/password
- Attacker steals credentials
- Used in ~70% of real phishing attacks

**Why it's effective:**
- Easy for attackers (no malware needed)
- High success rate (users trust login pages)
- Immediate access to accounts
- Can be automated at scale

**Other techniques:**
- **Malware Attachment**: ~15-20% of attacks
- **Link in Attachment**: ~5-10% (more sophisticated)
- **Drive-by URL**: ~5% (requires compromised legitimate sites)

**Exam Tip:** For Attack Simulation Training, start with Credential Harvest simulations.
</details>

---

#### **Question 6: Automated Investigation & Response**

You have Microsoft Defender for Office 365 Plan 2.

You enable Automated Investigation & Response (AIR).

You want AIR to automatically remove malicious emails but require approval for user password resets.

Which automation level should you configure?

A. No automated response
B. Semi-automated
C. Fully automated
D. Custom automation

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - Semi-automated**

**Explanation:**

**Semi-automated** (Recommended):
- AIR automatically remediates SOME threats
- Low-risk actions: Automatic (soft delete email, block sender)
- High-risk actions: Require approval (password reset, isolate device)
- Best balance of automation and control

**Automation Levels:**
1. **No automated response (Manual)**:
   - AIR investigates only
   - All actions require approval
   - Use: High-security, low-trust environments

2. **Semi-automated** ← ANSWER:
   - Auto-remediates low-risk
   - Approval for high-risk
   - Use: Most organizations (balanced)

3. **Fully automated**:
   - Auto-remediates ALL threats
   - No approval needed
   - Use: High-confidence, mature environments (use with caution)

**Scenario fit:** Wants auto email removal (low-risk) ✅ but approval for password resets (high-risk) ✅ = Semi-automated
</details>

---

#### **Question 7: ZAP (Zero-Hour Auto Purge)**

You receive a report that a malicious email was delivered to 100 users yesterday.

The email contained a link that was clean at delivery time but is now hosting malware.

You verify ZAP is enabled for phishing.

What will happen?

A. ZAP will move the email to users' Junk Email folders
B. ZAP will quarantine the email
C. ZAP will delete the email permanently
D. ZAP will do nothing (email was already delivered)

<details>
<summary>Click to see answer</summary>

**✅ Answer: A - ZAP will move the email to users' Junk Email folders**

**Explanation:**

**ZAP for Phishing:**
- Default action: Move to **Junk Email folder** (not Quarantine)
- Allows user to recover if false positive
- But removes from Inbox (protects user)

**ZAP Actions by Type:**
- **ZAP for Spam**: Move to Junk folder
- **ZAP for Phishing**: Move to Junk folder
- **ZAP for Malware**: Quarantine (higher risk)

**How ZAP Works:**
1. Email delivered (URL was clean)
2. URL later identified as malicious (threat intel updated)
3. ZAP searches all mailboxes for emails with that URL
4. ZAP moves emails to Junk folder
5. Users protected retroactively

**Why not others:**
- **B (Quarantine)**: ZAP for malware quarantines, phishing moves to Junk
- **C (Delete)**: ZAP doesn't permanently delete (allows recovery)
- **D (Nothing)**: ZAP specifically handles post-delivery threats

**Key Point:** ZAP = Retroactive protection, even after email delivered!
</details>

---

#### **Question 8: Email Investigation**

You are investigating a phishing email using Threat Explorer (MDO Plan 2).

You need to find all emails from the same campaign.

Which filter should you use?

A. Sender domain
B. Subject
C. Campaign ID
D. All of the above

<details>
<summary>Click to see answer</summary>

**✅ Answer: D - All of the above**

**Explanation:**

**Campaign Detection** uses multiple signals:

1. **Sender domain**: Same attacker infrastructure
2. **Subject**: Similar or identical subjects
3. **Campaign ID**: Microsoft's ML-assigned campaign identifier
4. **URLs**: Same malicious URLs
5. **Attachments**: Same malware hashes
6. **Time window**: Sent within hours/days

**Best Approach:**
- Start with **Campaign ID** (if available) - most accurate
- Or use **Similar emails** tab in Email entity page
- Or filter by **Sender domain + Subject** combination
- Or use **Campaign views** (Plan 2 only) - dedicated campaign tracking

**Threat Explorer Workflow:**
1. Find initial phishing email
2. Open email entity page
3. Click "Similar emails" tab
4. See all emails from same campaign (auto-correlated)
5. Take action on all (bulk remediation)

**Exam Tip:** Campaigns are auto-detected in Plan 2. Use Campaign views or Similar emails for investigation.
</details>

---

#### **Question 9: Safe Links Configuration**

You configure a Safe Links policy with the following settings:
- On: URLs will be rewritten
- Apply real-time URL scanning
- Do not let users click through to original URL

A user receives an email with a URL and clicks it.

The URL is determined to be malicious.

What happens?

A. User is redirected to original URL with a warning banner
B. User sees a "This site has been blocked" page
C. User sees a warning and can click "Continue anyway"
D. Email is quarantined before delivery

<details>
<summary>Click to see answer</summary>

**✅ Answer: B - User sees a "This site has been blocked" page**

**Explanation:**

**Safe Links Flow:**
1. User clicks link
2. Request goes to Safe Links service (URL rewritten)
3. Real-time reputation check
4. Verdict: Malicious
5. "Do not let users click through" setting active
6. User sees: **Blocked page** (no bypass option)

**Blocked Page:**
```
┌──────────────────────────────────┐
│  ⚠️ THIS SITE HAS BEEN BLOCKED   │
│                                  │
│  This site is known to be        │
│  malicious and could harm your   │
│  device or steal your data.      │
│                                  │
│  [Go Back]  [Report Issue]       │
└──────────────────────────────────┘
```

**Why not others:**
- **A**: No warning banner, full block page shown
- **C**: No "Continue anyway" because click-through is DISABLED
- **D**: Safe Links is time-of-click, not delivery-time (email already delivered)

**Key Point:** "Do not let users click through" = No bypass, full protection
</details>

---

#### **Question 10: Anti-Phishing Policy**

You need to configure anti-phishing protection for your executives.

You want to:
- Protect the CEO's display name from being impersonated
- Quarantine emails that impersonate the CEO
- Show safety tips to users

Which anti-phishing policy settings should you configure? (Choose THREE)

A. Enable user impersonation protection and add CEO email address
B. Enable domain impersonation protection and add company domain
C. Set user impersonation action to "Quarantine message"
D. Enable mailbox intelligence
E. Enable all safety tips
F. Set phishing threshold to 1 - Standard

<details>
<summary>Click to see answer</summary>

**✅ Answers: A, C, E**

**Explanation:**

**A. Enable user impersonation protection** ✅
- Add CEO's email address to protected users list
- MDO watches for display names matching CEO
- Detects: "CEO John Smith" <attacker@evil.com>

**C. Set user impersonation action to Quarantine** ✅
- If CEO impersonation detected → Quarantine email
- Prevents delivery to user's inbox
- Admin can review and release if false positive

**E. Enable all safety tips** ✅
- Show warning if impersonation detected
- Show "First contact" tip for new senders
- Show "via" tag for unauthenticated senders
- User awareness enhancement

**Why not others:**
- **B (Domain impersonation)**: Protects DOMAIN (contoso.com), not USER (CEO). This is good but not required for CEO protection specifically.
- **D (Mailbox intelligence)**: Good feature but not required for CEO impersonation scenario
- **F (Threshold)**: Threshold is for overall phishing sensitivity, not impersonation specifically

**Key Configuration:**
```
User Impersonation:
├─ Users to protect: ceo@contoso.com
├─ Action: Quarantine message
└─ Safety tips: All enabled
```
</details>

---

### 15.4 Final Exam Tips

**Day Before Exam:**

```
✅ Review this study guide (all 3 parts)
✅ Focus on differences:
   - Plan 1 vs Plan 2
   - Standard vs Strict protection
   - Safe Attachments actions (Dynamic Delivery vs Block)
   - ZAP for spam/phishing (can disable) vs ZAP for malware (always on)
✅ Memorize key tables:
   - EmailEvents (most important)
   - UrlClickEvents (🆕 2025)
   - NetworkMessageId (join key)
✅ Review configurations:
   - SPF: include:spf.protection.outlook.com
   - DKIM: 2 CNAME records (selector1, selector2)
   - DMARC: _dmarc.domain.com, p=none → p=quarantine → p=reject
✅ Know best practices:
   - Dynamic Delivery (recommended)
   - No click-through on Safe Links
   - Priority accounts for VIPs
   - Semi-automated AIR (recommended)
✅ Understand workflows:
   - Email investigation (Threat Explorer → Email entity page → Similar emails → Take action)
   - Attack simulation (Email → Click → Training → Metrics)
   - AIR (Investigation → Recommendations → Actions → Action Center)
```

**During Exam:**

```
📖 Read questions carefully
- Look for keywords: "FIRST", "BEST", "MOST", "LEAST"
- Note: "Choose TWO" or "Choose THREE"

⏱️ Time management
- ~40-60 questions in 100 minutes
- ~1.5-2 minutes per question
- Flag difficult questions, return later

🎯 Elimination strategy
- Cross out obviously wrong answers
- Narrow to 2 options
- Choose best answer

⚠️ Watch for traps
- Plan 1 vs Plan 2 confusion
- Dynamic Delivery vs Block (know differences)
- Monitor mode REMOVED (June 2025) - may still appear as distractor
- ZAP for malware (always on) vs ZAP for spam (can disable)

✅ Trust your preparation
- First instinct usually correct
- Don't overthink
- You've studied well, you've got this!
```

**🎉 Final Words:**

You've completed all 3 parts of **Module 3: Microsoft Defender for Office 365**!

**What You've Mastered:**
- ✅ All MDO core features (Safe Attachments, Safe Links, Anti-Phishing, Anti-Spam)
- ✅ Email authentication (SPF, DKIM, DMARC)
- ✅ Threat hunting (Threat Explorer, Advanced Hunting)
- ✅ Automated investigation (AIR)
- ✅ User training (Attack Simulation Training)
- ✅ Priority account protection
- ✅ Configuration best practices
- ✅ 10 comprehensive practice questions

**Next Steps:**
1. Review any sections you found challenging
2. Practice the KQL queries
3. Take full-length practice exams
4. Continue to **Module 4: Microsoft Defender for Cloud Apps**
5. Or **Module 5: Microsoft Sentinel** for SIEM coverage

**You're ready for the MDO portion of SC-200! 🚀🎓**

Good luck on your exam! 💪

---

**End of Module 3 - Part 3 (FINAL)**

*Module 3 Complete! ✅*
*Continue to Module 4: Microsoft Defender for Cloud Apps for cloud application security.*
