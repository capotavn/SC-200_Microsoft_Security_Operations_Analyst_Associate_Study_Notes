# SC-200 Study Notes - Module 3: Microsoft Defender for Office 365 (MDO)
## 📧 Part 2: Advanced Features and Exam Preparation

**Continuation from Part 1** - Sections 6-15
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest MDO Updates

---

## 6. Anti-Spam and Anti-Malware

### 6.1 Anti-Spam Overview

**Exchange Online Protection (EOP) Anti-Spam:**

All Exchange Online subscriptions include built-in anti-spam (part of EOP, not MDO-specific).

**Spam Filtering Pipeline:**

```
Incoming Email
│
├─ 1. Connection Filtering
│   ├─ IP Allow List → Deliver
│   ├─ IP Block List → Reject
│   └─ IP reputation check → Continue
│
├─ 2. Spam Filtering
│   ├─ Content analysis
│   ├─ Machine learning models
│   ├─ Sender reputation
│   └─ Spam confidence level (SCL) assigned: 0-9
│
├─ 3. SCL-Based Action
│   ├─ SCL -1: Trusted sender → Inbox
│   ├─ SCL 0-1: Not spam → Inbox
│   ├─ SCL 2-4: Low spam → Inbox (usually)
│   ├─ SCL 5-6: Medium spam → Junk folder
│   ├─ SCL 7-9: High spam → Quarantine or Delete
│   └─ SCL 9: High confidence spam → Quarantine
│
└─ 4. Bulk Complaint Level (BCL)
    ├─ Measures bulk email (newsletters, marketing)
    ├─ BCL 0-3: Likely legit → Deliver
    ├─ BCL 4-7: Bulk, moderate complaints → Junk
    └─ BCL 8-9: High complaints → Block

Final Delivery:
├─ Inbox: Clean or low risk
├─ Junk Email folder: Suspected spam
├─ Quarantine: High confidence spam or admin-defined
└─ Delete: Highest risk (not recommended)
```

### 6.2 Spam Confidence Level (SCL)

**SCL Values:**

| SCL | Classification | Default Action | Description |
|-----|----------------|----------------|-------------|
| **-1** | Trusted sender | Inbox | From safe sender/domain list |
| **0, 1** | Not spam | Inbox | Very unlikely spam |
| **2, 3, 4** | Low spam | Inbox | Possible spam, low confidence |
| **5, 6** | Medium spam | Junk folder | Likely spam |
| **7, 8, 9** | High spam | Quarantine | High confidence spam |

**How SCL is Determined:**

```
Microsoft's spam filtering uses:
1. Content analysis
   - Subject line keywords
   - Body content patterns
   - HTML structure
   - Images and links

2. Sender reputation
   - IP reputation (history of spam from this IP)
   - Domain reputation
   - Previous recipient interactions

3. Machine learning
   - Trained on billions of emails
   - Identifies spam patterns
   - Continuously updated

4. Authentication results
   - SPF, DKIM, DMARC pass/fail
   - Affects trustworthiness score
```

### 6.3 Bulk Complaint Level (BCL)

**What is Bulk Email?**

Bulk email is legitimate marketing/newsletter email, but:
- Users may not want it
- Can be considered spam-like
- Not malicious, but unwanted

**BCL Scale:**

| BCL | Meaning | Action |
|-----|---------|--------|
| **0** | Not bulk | Deliver normally |
| **1-3** | Low complaints | Deliver (unlikely to be unwanted) |
| **4-7** | Medium complaints | May move to Junk based on threshold |
| **8-9** | High complaints | Usually move to Junk or block |

**BCL Threshold Configuration:**

```
Anti-spam policy setting:
- Bulk email threshold: 7 (default)
- If BCL ≥ threshold → Mark as spam

Recommendations:
- Sensitive users (executives): BCL threshold = 5 (stricter)
- Standard users: BCL threshold = 7 (balanced)
- Marketing dept: BCL threshold = 9 (lenient)
```

### 6.4 Anti-Spam Policies

**Policy Structure:**

```
Anti-Spam Policy: "Corporate Users"
│
├─ Bulk email threshold: 7
│
├─ Spam actions (by SCL):
│  ├─ Spam (SCL 5-6):
│  │  └─ Move to Junk Email folder
│  │
│  ├─ High confidence spam (SCL 7-9):
│  │  └─ Quarantine message
│  │
│  ├─ Phishing email:
│  │  └─ Quarantine message
│  │
│  ├─ High confidence phishing:
│  │  └─ Quarantine message
│  │
│  └─ Bulk email (BCL ≥ threshold):
│     └─ Move to Junk Email folder
│
├─ Retain spam in quarantine: 30 days
│
├─ Safety tips:
│  └─ Enable safety tips
│
├─ Zero-hour auto purge (ZAP):
│  ├─ Enable ZAP for spam: ✓
│  ├─ Enable ZAP for phishing: ✓
│  └─ Move to Junk allowed: ✓
│
├─ Allow & Block Lists:
│  ├─ Allowed senders: partner@vendor.com
│  ├─ Allowed domains: trustedpartner.com
│  ├─ Blocked senders: spam@evil.com
│  └─ Blocked domains: knownspam.com
│
└─ Applied to: All users
```

**Action Options:**

| Action | Description | Use Case |
|--------|-------------|----------|
| **Move to Junk Email folder** | Deliver to user's Junk folder | Medium confidence spam, user can review |
| **Add X-header** | Tag message, don't move | Custom mail flow rules, logging |
| **Prepend subject line** | Add "[SPAM]" to subject | User awareness, manual filtering |
| **Redirect to email address** | Send to security team | Investigation, analysis |
| **Delete message** | Permanently delete | Not recommended (no recovery) |
| **Quarantine message** | Admin-managed quarantine | High confidence spam, admin review |
| **No action** | Deliver normally | Low risk items |

### 6.5 Zero-Hour Auto Purge (ZAP)

**What is ZAP?**

Zero-hour auto purge **retroactively removes** malicious emails that were **already delivered** to user mailboxes.

**How ZAP Works:**

```
Timeline:

09:00 - Email arrives, passes all filters
        └─ Contains URL to clean website
        └─ Delivered to user's Inbox

09:15 - Attacker weaponizes URL
        └─ Website now hosts malware
        └─ URL now malicious

09:20 - Microsoft updates threat intelligence
        └─ URL marked as malicious globally

09:21 - ZAP triggered for emails with that URL
        └─ Searches all mailboxes
        └─ Finds email delivered at 09:00
        └─ Moves email to Junk folder or Quarantine
        └─ Protects user retroactively

Result: Email removed before user clicks link!
```

**ZAP for Spam:**

```
Scope: Emails in Inbox or other folders
Action: Move to Junk Email folder
Conditions:
- Email retroactively identified as spam
- ZAP for spam enabled in policy

Example:
1. Email delivered to Inbox (SCL 4)
2. Later, sender reputation drops (mass spam campaign)
3. Email re-evaluated → SCL 8 (high confidence spam)
4. ZAP moves email to Junk folder
```

**ZAP for Phishing:**

```
Scope: Emails in Inbox or other folders
Action: Move to Junk folder or Quarantine
Conditions:
- Email retroactively identified as phishing
- ZAP for phishing enabled in policy

Example:
1. Email delivered with clean URL
2. URL later identified as phishing site
3. ZAP quarantines email
4. User protected from clicking malicious link
```

**ZAP for Malware:**

```
Scope: Emails in any folder (Inbox, Junk, etc.)
Action: Quarantine (always)
Conditions:
- Attachment identified as malware post-delivery
- Applies to all users (can't be disabled)

Example:
1. Email with attachment delivered
2. Safe Attachments later detonates attachment
3. Malware detected
4. ZAP quarantines email automatically
```

**ZAP Configuration:**

```
Settings in Anti-Spam Policy:

Zero-hour auto purge (ZAP):
├─ ✓ Enable ZAP for spam messages
├─ ✓ Enable ZAP for phishing messages
└─ ✓ Move messages to Junk Email folder (ZAP spam)

Notes:
- ZAP for malware: Always on (can't disable)
- ZAP for spam/phishing: Can be disabled (not recommended)
- ZAP respects user's allow list
- ZAP doesn't apply to emails in Deleted Items
```

**When ZAP Doesn't Work:**

```
ZAP is blocked by:
❌ Email in Deleted Items folder
❌ User has email open (being read)
❌ Email already moved by user to specific folder
❌ Mailbox is on litigation hold (compliance)
❌ Email is in archive mailbox (ZAP doesn't scan archive)

Best Practice:
- Keep ZAP enabled
- Educate users not to move spam to other folders
- Use Junk Email folder (ZAP can still act there)
```

### 6.6 Allow & Block Lists

**Sender Allow/Block Lists:**

```
Use Cases:

✅ Allow List (Use Sparingly):
- Trusted partner always marked as spam
- Legitimate bulk email (newsletters)
- Known false positive source

⚠️ Use with Caution:
- Bypasses all filtering
- If sender compromised, malicious email delivered
- Review quarterly, remove if no longer needed

✅ Block List (More Common):
- Known spammer
- Persistent unwanted sender
- Malicious domain

Configuration:
1. Anti-spam policy → Allow/Block lists
2. Add senders or domains:
   - Individual: sender@domain.com
   - Domain: @domain.com
   - Wildcard: *@*.spam.com (not recommended)
```

**Tenant Allow/Block List (Organization-Wide):**

```
Location: Microsoft Defender Portal
Settings → Email & collaboration → Tenant allow/block lists

Categories:
1. Domains and email addresses
   - Allow: trusted@partner.com
   - Block: spam@evil.com

2. Files
   - Block: Known malicious file hash
   - Allow: False positive file hash

3. URLs
   - Block: Known phishing URLs
   - Allow: False positive URLs

4. Spoofed senders
   - Allow: Legitimate spoofing (mailing lists)
   - Block: Malicious spoofers

🆕 2025 Feature: Temporary allow entries
- Allow for 30 days, then auto-expire
- Forces periodic review
```

### 6.7 Anti-Malware Policies

**EOP Anti-Malware (Built-in):**

All Exchange Online includes anti-malware scanning:

```
Anti-Malware Policy: "Default"
│
├─ Malware Detection Response:
│  └─ What to do with detected malware:
│     └─ Quarantine message (recommended)
│     OR
│     └─ Delete message (not recommended)
│
├─ Common Attachment Filter:
│  ├─ Block these file types:
│  │  ├─ .exe (executable)
│  │  ├─ .bat (batch file)
│  │  ├─ .cmd (command script)
│  │  ├─ .scr (screensaver)
│  │  └─ [~75 risky file types]
│  │
│  └─ Action: Quarantine
│
├─ Notifications:
│  ├─ Notify internal senders: ✓
│  ├─ Notify external senders: ❌ (don't reveal detection)
│  └─ Notify admin: security@contoso.com
│
└─ Applied to: All users
```

**Common Attachment Filter:**

**Blocked File Types (Examples):**

| Extension | Type | Risk | Blocked by Default |
|-----------|------|------|-------------------|
| .exe | Executable | Very High | ✅ Yes |
| .bat, .cmd | Script | Very High | ✅ Yes |
| .vbs, .js | Script | Very High | ✅ Yes |
| .scr | Screensaver | High | ✅ Yes |
| .msi | Installer | High | ✅ Yes |
| .jar | Java archive | High | ✅ Yes |
| .com | MS-DOS program | High | ✅ Yes |
| .docm, .xlsm | Macro-enabled Office | Medium | ⚠️ No (but Safe Attachments scans) |
| .pdf | PDF document | Low | ❌ No (but Safe Attachments scans) |
| .zip, .rar | Archive | Medium | ❌ No (but contents scanned) |

**🎯 Best Practice:** Use common attachment filter for known risky file types, and Safe Attachments for behavioral analysis of others.

### 6.8 Creating Anti-Spam Policies

**Method 1: Microsoft Defender Portal**

```
1. security.microsoft.com
2. Email & collaboration → Policies & rules
3. Threat policies → Anti-spam
4. Click "+ Create policy" → Inbound

Step 1: Name policy
- Name: "Executive Anti-Spam"
- Description: "Stricter spam filtering for executives"

Step 2: Users, groups, domains
- Users: ceo@contoso.com, cfo@contoso.com
- Groups: Executive Team
- Domains: (optional)

Step 3: Bulk email threshold and spam properties
- Bulk email threshold: 5 (stricter than default 7)
- Mark as spam:
  ✓ Empty messages
  ✓ Embedded tags in HTML
  ✓ JavaScript or VBScript in HTML
  ✓ Form tags in HTML
  ✓ Frame or iframe tags
  ✓ Image links to remote sites
  ✓ SPF record hard fail
  ✓ Sender ID filtering hard fail

Step 4: Actions
- Spam: Move to Junk Email folder
- High confidence spam: Quarantine
- Phishing: Quarantine
- High confidence phishing: Quarantine
- Bulk: Move to Junk Email folder

Step 5: Quarantine retention: 30 days

Step 6: Allow & Block lists
- Allowed senders: (add if needed)
- Allowed domains: (add if needed)
- Blocked senders: (add if needed)
- Blocked domains: (add if needed)

Step 7: Review and submit
```

**Method 2: PowerShell**

```powershell
# Connect
Connect-IPPSSession

# Create anti-spam policy
New-HostedContentFilterPolicy -Name "Executive Protection" `
  -BulkThreshold 5 `
  -HighConfidenceSpamAction Quarantine `
  -SpamAction MoveToJmf `
  -BulkSpamAction MoveToJmf `
  -PhishSpamAction Quarantine `
  -HighConfidencePhishAction Quarantine `
  -QuarantineRetentionPeriod 30 `
  -EnableEndUserSpamNotifications $true `
  -EndUserSpamNotificationFrequency 1

# Create rule to apply policy
New-HostedContentFilterRule -Name "Executive Protection Rule" `
  -HostedContentFilterPolicy "Executive Protection" `
  -SentTo "ceo@contoso.com","cfo@contoso.com" `
  -Priority 0
```

### 6.9 Monitoring Anti-Spam

**Reports:**

```
1. Defender Portal → Reports → Email & collaboration
2. Spam detections report shows:
   - Spam emails detected
   - Malware emails detected
   - Quarantined items
   - ZAP actions taken
   - Top spam sources
   - Spam by verdict (SCL distribution)

3. Message trace:
   - Track specific email
   - View spam verdict and SCL
   - See which policy applied
   - Check why email was marked spam
```

**Advanced Hunting:**

```kql
// Find all spam emails in last 7 days
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Spam"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, ThreatTypes, DetectionMethods
| order by Timestamp desc

// ZAP actions
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where Action == "ZAP"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, ThreatTypes, DeliveryLocation
```

**🎯 Exam Tip:**
- **SCL** = Spam confidence level (0-9, higher = more spam)
- **BCL** = Bulk complaint level (0-9, higher = more complaints)
- **ZAP** = Zero-hour auto purge (retroactive email removal)
- **Common Attachment Filter** = Block risky file types (.exe, .bat, etc.)
- ZAP for **malware** = Always on, **cannot** be disabled
- ZAP for **spam/phishing** = Can be enabled/disabled per policy

---

## 7. Quarantine and User Submissions

### 7.1 Quarantine Overview

**What is Quarantine?**

Quarantine is a **holding area** for suspicious emails, preventing delivery to user mailboxes while allowing review and release if legitimate.

**Quarantine Types:**

```
1. Admin-Managed Quarantine
   └─ Emails quarantined by policies
      ├─ Anti-spam: High confidence spam
      ├─ Anti-phishing: Impersonation attempts
      ├─ Anti-malware: Virus/malware detected
      ├─ Safe Attachments: Malicious attachment
      └─ Safe Links: Malicious URL blocked

2. User-Accessible Quarantine (End-user quarantine)
   └─ Users can view their own quarantined emails
      ├─ Review messages
      ├─ Release to inbox (if policy allows)
      ├─ Request release (admin approval required)
      └─ Report false positives

3. Quarantine Policies (🆕 2024-2025)
   └─ Control what users can do with quarantined emails
      ├─ View only
      ├─ Release to self
      ├─ Release to others
      └─ Request release
```

### 7.2 Quarantine Policies

**🆕 Feature (2024-2025):** Quarantine policies provide granular control over user permissions.

**Policy Structure:**

```
Quarantine Policy: "Limited User Access"
│
├─ End-user spam notifications:
│  ├─ Enable notifications: ✓
│  ├─ Frequency: Every 4 days
│  └─ Language: English
│
├─ User permissions:
│  ├─ View message header: ✓
│  ├─ Preview message: ✓
│  ├─ Release message: ✓ (specific messages only)
│  ├─ Block sender: ✓
│  ├─ Request release: ✓ (admin approval)
│  ├─ Delete from quarantine: ✓
│  └─ Allow sender: ❌ (admin only)
│
└─ Applied to:
   └─ Anti-spam policy: High confidence spam
```

**Pre-Built Quarantine Policies:**

| Policy Name | Users Can | Best For |
|-------------|-----------|----------|
| **AdminOnlyAccessPolicy** | View only, request release | Malware, high-risk phishing |
| **DefaultFullAccessPolicy** | Release, block sender, delete | Standard spam |
| **NotificationEnabledPolicy** | Release, notifications enabled | Spam with user review |

### 7.3 End-User Quarantine Experience

**User Access Methods:**

```
Method 1: Quarantine Portal
1. User navigates to: https://security.microsoft.com/quarantine
2. Signs in with work account
3. Sees list of quarantined emails:

┌──────────────────────────────────────────────┐
│ Quarantined messages                          │
├──────────────────────────────────────────────┤
│ From          | Subject       | Reason       │
├──────────────────────────────────────────────┤
│ sales@vendor  | Invoice Q3    | Spam         │
│ ceo@evil.com  | Urgent wire   | Phishing     │
│ unknown@bad   | Your package  | Malware      │
└──────────────────────────────────────────────┘

4. User actions:
   - Preview: View email content safely
   - Release: Deliver to inbox
   - Request release: Ask admin for approval
   - Block sender: Add to personal block list
   - Delete: Permanently delete from quarantine

Method 2: End-User Spam Notifications (Email Digest)
1. User receives periodic email summary
2. Subject: "You have X quarantined messages"
3. Lists quarantined emails
4. One-click actions:
   - Release
   - Block sender
   - Review (opens quarantine portal)
```

**🆕 October 2025 Update - Quarantine Preview Enhancements:**

Microsoft simplified the quarantine email preview experience:
- **Removed:** Plain text view option (unified experience)
- **Limited:** URL hover previews (security enhancement)
- **Simplified:** "Load external content" button for some scenarios
- **Improved:** Secure, isolated rendering environment

### 7.4 Admin Quarantine Management

**Admin View:**

```
1. Defender Portal → Email & collaboration → Review → Quarantine
2. Filter by:
   - Recipient: user@contoso.com
   - Sender: attacker@evil.com
   - Subject: contains "invoice"
   - Date range: Last 7 days
   - Reason: Spam, Phishing, Malware, etc.

3. View details:
   - Email headers
   - Spam verdict
   - Detection reason
   - Policy that quarantined it

4. Actions:
   - Release: To specific users or all
   - Release and report false positive: To Microsoft
   - Delete: Permanently remove
   - Download message: For analysis
   - Preview: View safely
```

**Bulk Actions:**

```
Scenario: Release 50 emails quarantined by mistake

1. Filter quarantined emails:
   - Sender: legitimate-sender@vendor.com
   - Date: Last 3 days
   - Reason: Spam

2. Select all matching emails

3. Bulk release:
   - Release to: All recipients
   - Report as false positive: ✓
   - Allow sender: ✓ (future emails bypass quarantine)

4. Submit

Result: All 50 emails delivered, sender allowlisted
```

### 7.5 User Submissions

**What are Submissions?**

Users and admins can submit emails to Microsoft for analysis:
- **False Positives:** Clean email incorrectly blocked
- **False Negatives:** Malicious email incorrectly allowed
- **Suspected Phishing:** Potentially malicious email

**Submission Types:**

```
1. User Submissions (End-User)
   └─ Users report suspicious emails from Outlook
      ├─ Report Phishing
      ├─ Report Junk
      └─ Report Not Junk (false positive)

2. Admin Submissions
   └─ Admins submit emails for deeper analysis
      ├─ Should have been blocked (false negative)
      ├─ Should not have been blocked (false positive)
      └─ Request re-scan or policy review

3. Automated Feedback (🆕 2025)
   └─ Automatic response to user submissions
      ├─ AI-powered instant feedback
      ├─ Reduces admin workload
      └─ Educates users in real-time
```

**🆕 September 2025 Feature: Automated End User Feedback**

**How It Works:**

```
Traditional Flow:
1. User reports phishing
2. Email sent to SOC mailbox
3. SOC analyst reviews
4. Analyst replies to user (manual)
5. Takes hours/days

🆕 Automated Flow:
1. User reports phishing
2. MDO automatically investigates
3. AI determines verdict
4. User gets instant automated response:
   ┌────────────────────────────────────┐
   │ Thank you for reporting!           │
   │                                    │
   │ We investigated your submission:   │
   │ Verdict: Confirmed phishing        │
   │                                    │
   │ Actions taken:                     │
   │ - Blocked sender                   │
   │ - Removed from other mailboxes     │
   │ - Updated threat intelligence      │
   │                                    │
   │ Stay vigilant!                     │
   │ - IT Security Team                 │
   └────────────────────────────────────┘
5. Takes seconds, not hours!

Benefits:
✅ Instant user feedback
✅ Reduced SOC workload
✅ Improved user satisfaction
✅ Faster threat response
```

### 7.6 Report Message Add-in

**Outlook Report Message Button:**

```
Installation:
- Built-in for Microsoft 365
- Available in Outlook (desktop, web, mobile)

User Experience:
1. User receives suspicious email
2. Click "Report message" button in ribbon
3. Choose option:
   ├─ Phishing
   ├─ Junk
   └─ Not Junk

4. Email submitted to Microsoft and/or custom mailbox

Configuration:
Settings → Email & collaboration → User reported settings
├─ Enable Report Message button: ✓
├─ Customization:
│  ├─ Button name: "Report Security Issue"
│  ├─ Confirmation message: Custom text
│  └─ Reporting options: Phishing, Junk, Not Junk
├─ Submission destination:
│  ├─ Microsoft only
│  ├─ Custom mailbox: security@contoso.com
│  └─ Both Microsoft and custom mailbox
└─ User experience:
   ├─ Move reported email to Deleted Items: ✓
   └─ Before submitting popup: Show reporting options
```

### 7.7 Admin Submission Portal

**Submitting Emails to Microsoft:**

```
1. Defender Portal → Email & collaboration → Review → Submissions
2. Click "+ Submit to Microsoft for analysis"
3. Choose submission type:
   - Email
   - URL
   - File
   - Email attachment

4. For Email submission:
   Step 1: Select email
   - Network message ID (from message trace)
   - OR: Upload .eml/.msg file

   Step 2: Choose submission reason
   - Should have been blocked as:
     * Phish
     * Spam
     * Malware
   - Should not have been blocked (false positive)

   Step 3: Submit

5. Microsoft analyzes:
   - Uses automated + human review
   - Updates threat intelligence
   - Improves filters globally

6. Results:
   - Available in Submissions page
   - Shows: Allowed, Blocked, or Pending
   - Can take 24-48 hours
```

**Submission Results:**

```
Result Types:

✅ Microsoft agrees - Will be blocked
   - Email was malicious
   - Microsoft updated filters
   - Future emails from sender will be blocked

❌ Microsoft disagrees - Will continue to allow
   - Email was legitimate
   - No action taken
   - Consider custom filtering if needed

⚠️ Under investigation
   - Analysis in progress
   - Check back in 24-48 hours

ⓘ Inconclusive
   - Not enough data to determine
   - Monitor and re-submit if issue persists
```

### 7.8 Quarantine Retention

**Retention Period:**

```
Default Retention:
- Spam: 30 days
- Phishing: 30 days
- Malware: 30 days
- Bulk: 30 days
- High confidence phishing: 30 days

Configuration:
- Set per anti-spam policy
- Range: 1-30 days
- After expiration: Permanently deleted

Recommendation:
- Standard users: 30 days (gives time to review)
- High-volume spam: 15 days (reduce storage)
- Compliance requirements: 30 days (audit trail)
```

### 7.9 Troubleshooting Quarantine

**Issue 1: User Can't Access Quarantine**

```
Symptoms:
- User navigates to quarantine portal
- Sees "No messages" or access denied

Causes & Solutions:

1. No quarantined emails for user
   Check: Admin quarantine view (filter by user)
   Fix: If emails present, check quarantine policy permissions

2. Quarantine policy denies access
   Check: Policy applied to quarantine type
   Fix: Assign policy that allows user access

3. User lacks license
   Check: User has Exchange Online license?
   Fix: Assign appropriate license

4. Authentication issue
   Check: User signed in with correct account?
   Fix: Sign out and sign in again
```

**Issue 2: User Not Receiving Spam Notifications**

```
Symptoms:
- Quarantined emails exist
- User not getting digest emails

Causes & Solutions:

1. Notifications disabled in policy
   Check: Quarantine policy settings
   Fix: Enable end-user spam notifications

2. Frequency too high
   Check: Notification frequency (e.g., every 7 days)
   Fix: User has no NEW quarantined emails since last notification

3. Notifications going to Junk
   Check: User's Junk folder
   Fix: Add noreply@microsoft.com to safe senders

4. Email blocked by other filter
   Check: External email rules/gateways
   Fix: Allow quarantine notification emails
```

**Issue 3: Released Email Not Appearing in Inbox**

```
Symptoms:
- User releases email from quarantine
- Email not delivered to inbox

Causes & Solutions:

1. Delivery delay
   Wait: 5-15 minutes
   Check: Inbox and Junk folder

2. User inbox rule moved it
   Check: Inbox rules that auto-move emails
   Fix: Check other folders

3. Email re-quarantined
   Check: Another policy triggered after release
   Fix: Add sender to allow list before releasing

4. Mailbox full
   Check: Mailbox quota
   Fix: Clean up mailbox, archive old emails
```

**🎯 Exam Tip:**
- Quarantine = Holding area for suspicious emails
- **Quarantine policies** (🆕 2024-2025) = Control user permissions
- **End-user quarantine** = Users can self-service review their quarantined items
- **Admin submissions** = Send false positives/negatives to Microsoft for analysis
- **🆕 Automated feedback** (Sept 2025) = Instant AI-powered user responses
- **Report Message** add-in = Built-in Outlook button for reporting phishing
- Retention = Default **30 days**, configurable 1-30 days

---

## 8. Threat Explorer and Real-Time Detections

### 8.1 Overview

**What is Threat Explorer?**

**Threat Explorer** (MDO Plan 2) and **Real-time detections** (MDO Plan 1) are **email threat hunting** tools providing visibility into:
- Email threats detected and blocked
- Email campaigns targeting your organization
- Top targeted users
- Malware families and attack vectors

**Plan Comparison:**

| Feature | Real-time Detections (Plan 1) | Threat Explorer (Plan 2) | Exam Importance |
|---------|-------------------------------|--------------------------|-----------------|
| **Time range** | Last 7 days | Last 30 days | ⭐⭐⭐⭐ |
| **Filtering** | Basic | Advanced | ⭐⭐⭐⭐ |
| **Views** | Malware, Phish, Submissions | All email, Malware, Phish, Submissions, Content malware | ⭐⭐⭐⭐⭐ |
| **Export** | ✅ Yes | ✅ Yes | ⭐⭐⭐ |
| **URL click data** | ❌ No | ✅ Yes (🆕 URLClickEvents) | ⭐⭐⭐⭐ |
| **Threat campaigns** | ❌ No | ✅ Yes | ⭐⭐⭐⭐⭐ |
| **Automated investigation** | ❌ No | ✅ Yes (trigger AIR) | ⭐⭐⭐⭐⭐ |
| **Take action** | ⚠️ Limited | ✅ Full (soft delete, hard delete, move) | ⭐⭐⭐⭐⭐ |

### 8.2 Threat Explorer Interface

**Main Components:**

```
Threat Explorer Layout:

┌────────────────────────────────────────────────┐
│ [Filters] Date: Last 7 days ▼                  │
│          Recipients: All ▼                     │
│          Detection tech: All ▼                 │
│          [More filters...]                     │
├────────────────────────────────────────────────┤
│ [View] All email ▼  | Malware | Phish | ...   │
├────────────────────────────────────────────────┤
│ [Chart] Email volume over time                 │
│         ┌─────────────────────────────────┐   │
│         │     ▂▄█▆▃▅▂  (Email volume)     │   │
│         └─────────────────────────────────┘   │
├────────────────────────────────────────────────┤
│ [Details] Email list                           │
│ ┌──────────────────────────────────────────┐  │
│ │ From      | Subject    | Recipients | ...│  │
│ ├──────────────────────────────────────────┤  │
│ │ evil@bad  | Invoice    | user@con.. |  │  │
│ │ phish@... | Password   | exec@con.. |  │  │
│ │ spam@...  | Offer      | all@cont.. |  │  │
│ └──────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
```

### 8.3 Explorer Views

**View Types:**

**1. All email**
```
Shows: Every email (malicious and clean)
Use: General email flow visibility, baseline analysis
Filters: Sender, recipient, subject, detection status
Example: "Show all emails from external domains in last 7 days"
```

**2. Malware**
```
Shows: Emails with malware detected
Use: Track malware campaigns, identify patient zero
Details: Malware family, file name, file hash
Example: "Show all Emotet malware in last 30 days"
```

**3. Phish**
```
Shows: Phishing emails (credential theft, impersonation)
Use: Investigate phishing campaigns, targeted attacks
Details: Impersonation type (user/domain/none), verdict
Example: "Show all CEO impersonation attempts this month"
```

**4. Submissions**
```
Shows: User and admin submissions to Microsoft
Use: Track false positives, see submission verdicts
Details: Submission type, result, action taken
Example: "Show all user-reported phishing emails"
```

**5. Content malware (🆕 Plan 2 only)**
```
Shows: Malicious files in SharePoint/OneDrive/Teams
Use: Track file-based threats outside email
Details: File location, malware family, affected users
Example: "Show all ransomware detected in SharePoint"
```

**6. URL clicks (🆕 2025 - Plan 2 only)**
```
Shows: Safe Links URL clicks and blocks
Use: Identify users clicking malicious links
Details: URL, click time, verdict, action taken
Example: "Show all blocked phishing URL clicks"
```

### 8.4 Advanced Filtering

**Common Filter Combinations:**

**Hunt 1: Phishing Emails Targeting Executives**

```
Filters:
- View: Phish
- Recipients: ceo@contoso.com, cfo@contoso.com
- Date: Last 30 days
- Detection technology: Impersonation
- Sender domain: (external)

Result: All phishing emails targeting leadership
Action: Review patterns, implement stricter policies
```

**Hunt 2: Malware from Specific Sender**

```
Filters:
- View: Malware
- Sender address: attacker@evil.com
- Date: All time (or custom range)
- Malware family: Any
- Delivery action: Any

Result: All malware from this sender over time
Action: Block sender, hunt for other variants
```

**Hunt 3: Zero-Day Attachments**

```
Filters:
- View: All email
- Detection technology: File detonation
- Attachment: Has attachment
- File type: .exe, .zip, .pdf
- Date: Last 7 days

Result: Emails where Safe Attachments detonated file
Action: Analyze zero-day malware, share IOCs
```

**Hunt 4: User-Reported Phishing That Reached Inbox**

```
Filters:
- View: Submissions
- Submission type: User reported
- Submission result: Should have been blocked
- Delivery location: Inbox
- Date: Last 30 days

Result: Phishing that bypassed filters
Action: Submit to Microsoft, tune policies
```

### 8.5 Email Entity Page

**Deep Dive into Individual Email:**

```
When you click an email in Threat Explorer:

Email Entity Page Opens:
┌────────────────────────────────────────────────┐
│ Email Summary                                  │
│ From: attacker@evil.com                        │
│ To: user@contoso.com                           │
│ Subject: Urgent! Account suspended             │
│ Date: 2025-10-22 14:30:00                      │
│ Verdict: Phishing (High confidence)            │
├────────────────────────────────────────────────┤
│ [Tabs]                                         │
│ └─ Analysis | Timeline | Similar emails | ...  │
└────────────────────────────────────────────────┘

Tab 1: Analysis
├─ Detection details:
│  ├─ Detection technology: Impersonation + URL
│  ├─ Threat types: Phish, Spoofing
│  ├─ Verdict confidence: High
│  └─ DMARC/SPF/DKIM: Fail / Fail / None
│
├─ URLs in email:
│  └─ https://phishing-site.com/login
│     ├─ Verdict: Malicious
│     ├─ Blocked by Safe Links
│     └─ Click data: 0 clicks (blocked before delivery)
│
├─ Attachments:
│  └─ invoice.pdf
│     ├─ SHA256: abc123...
│     ├─ Verdict: Clean
│     └─ Safe Attachments: Passed
│
└─ Original email actions:
   ├─ Policy action: Quarantined
   ├─ User action: Reported as phishing
   └─ Admin action: Deleted from quarantine

Tab 2: Timeline
├─ 14:30:00 - Email sent
├─ 14:30:15 - Email received by EOP
├─ 14:30:20 - Anti-spam scan: Pass
├─ 14:30:25 - Anti-phishing scan: Detected impersonation
├─ 14:30:30 - Safe Links: URL blocked
├─ 14:30:35 - Action: Moved to quarantine
├─ 14:45:00 - User reported as phishing
└─ 15:00:00 - Admin deleted from quarantine

Tab 3: Similar emails
└─ Shows other emails from same campaign:
   ├─ Same sender domain: 5 emails
   ├─ Similar subject: 12 emails
   ├─ Same malware family: 0 emails
   └─ Same URLs: 8 emails

Tab 4: Header analysis
└─ Full email headers for forensic analysis
```

### 8.6 Campaign Views (Plan 2 Only)

**What are Campaigns?**

**Campaigns** are coordinated attacks targeting many users:
- Same sender or sender group
- Similar email content
- Same malicious URLs or attachments
- Sent in short time window (hours/days)

**Campaign Tracking:**

```
1. Defender Portal → Email & collaboration → Campaigns
2. View active campaigns:

Campaign Example:
┌────────────────────────────────────────────────┐
│ Campaign: CEO Wire Transfer Fraud             │
│ Status: Active                                 │
│ First seen: 2025-10-20                         │
│ Latest: 2025-10-22                             │
│ Targets: 150 organizations, 2,500 users        │
├────────────────────────────────────────────────┤
│ Attack Details:                                │
│ - Type: Business email compromise (BEC)       │
│ - Tactic: CEO impersonation                   │
│ - Subject: "Urgent wire transfer needed"      │
│ - Sender: ceo-[random]@gmail.com              │
│ - Goal: Wire transfer fraud                   │
├────────────────────────────────────────────────┤
│ Impact on Your Organization:                   │
│ - Targeted: 12 users                          │
│ - Blocked: 10 emails                          │
│ - Delivered: 2 emails (moved to Junk)        │
│ - Clicked: 0 users                            │
│ - Compromised: 0 users ✅                      │
├────────────────────────────────────────────────┤
│ Recommendations:                               │
│ - Review anti-phishing policy                 │
│ - Educate users on BEC tactics                │
│ - Enable priority account protection          │
└────────────────────────────────────────────────┘

3. Click campaign → View all related emails
4. Take action:
   - Delete from all mailboxes
   - Block sender
   - Add to block list
   - Create detection rule
```

**Campaign Types:**

```
Common Campaign Categories:

1. Credential Phishing
   - Fake login pages
   - Password reset scams
   - "Verify your account" emails

2. Business Email Compromise (BEC)
   - CEO fraud
   - Vendor payment redirection
   - W-2 data theft

3. Malware Distribution
   - Ransomware delivery
   - Banking trojans
   - Info stealers

4. Spam Campaigns
   - Pharmaceutical spam
   - Fake products
   - Lottery scams
```

### 8.7 Taking Action in Explorer

**Available Actions:**

**🆕 September 2025: Enhanced Take Action Wizard**

```
Take Action Options:

1. Soft Delete
   - Moves to Deleted Items
   - User can recover
   - 🆕 Includes sender's copy cleanup
   - Use: Suspected spam, moderate risk

2. Hard Delete (🆕)
   - Permanently removes email
   - Cannot be recovered by user
   - 🆕 Extends to malicious calendar invites
   - Use: Confirmed malware, high-risk phishing

3. Move to Junk
   - Moves to Junk Email folder
   - User can still access
   - Use: Spam, low-risk phishing

4. Move to Inbox
   - Restore false positive to inbox
   - Use: Legitimate email mistakenly quarantined

5. Move to Deleted Items
   - Similar to soft delete
   - Less aggressive than hard delete

Scope:
- Single mailbox
- Multiple mailboxes (bulk action)
- All users in organization (use with caution!)

🆕 Sender's Copy Cleanup (Sept 2025):
- Automatically cleans up Sent Items folder
- Applies to soft delete and hard delete
- Removes attacker's sent copies
- Available in: Explorer, Email entity, Summary panel, Advanced hunting
```

**Example Workflow:**

```
Scenario: Phishing campaign delivered to 50 users

Step 1: Identify campaign in Explorer
- Filter: Phish view, last 24 hours
- Find: 50 matching emails from attacker@evil.com

Step 2: Review email details
- Check: Email entity page
- Confirm: Definitely malicious (fake O365 login)

Step 3: Take action
- Select all 50 emails
- Action: Hard delete
- Scope: All recipients
- ✓ Remove from Sent Items (🆕 sender's copy cleanup)
- ✓ Submit to Microsoft as phishing
- ✓ Block sender

Step 4: Monitor
- Check: Action center for completion
- Verify: Emails removed from all mailboxes
- Confirm: No users clicked links (if any did → force password reset)

Step 5: Follow-up
- User education: Send awareness email about this attack
- Policy tuning: Adjust anti-phishing threshold if needed
- Threat hunting: Search for similar emails from other senders
```

### 8.8 Exporting Data

**Export Options:**

```
Export Uses:
- Long-term retention (Explorer limited to 30 days)
- External analysis (SIEM, Excel, BI tools)
- Compliance reporting
- Incident documentation

How to Export:
1. Apply filters in Explorer
2. Click "Export" button
3. Choose format:
   - CSV (recommended for most uses)
   - JSON (API/programmatic use)
4. Download file (up to 200,000 records)

Exported Data Includes:
- NetworkMessageId (unique identifier)
- RecipientEmailAddress
- SenderFromAddress
- Subject
- Timestamp
- ThreatTypes
- DetectionMethods
- DeliveryAction
- DeliveryLocation
- URLs (if present)
- AttachmentCount
- FileTypes
```

### 8.9 Monitoring and Reporting

**Threat Explorer Insights:**

```
Use Cases:

1. Daily Threat Review
   - Filter: Last 24 hours
   - View: Phish + Malware
   - Review: New threats, adjust policies

2. Weekly Campaign Analysis
   - Filter: Last 7 days
   - View: Campaigns
   - Identify: Trends, recurring threats

3. Monthly Executive Report
   - Filter: Last 30 days
   - View: All email
   - Metrics:
     * Total emails processed
     * Threats detected (malware, phish, spam)
     * Top targeted users
     * Effectiveness of policies

4. User Behavior Analysis
   - Filter: Specific user
   - View: URL clicks
   - Identify: High-risk users who click suspicious links
   - Action: Additional training

5. Threat Intelligence
   - Filter: Malware view
   - Group by: Malware family
   - Track: New malware families, zero-days
   - Share: IOCs with threat intel platforms
```

**🎯 Exam Tip:**
- **Threat Explorer** = MDO **Plan 2** (advanced hunting, 30 days)
- **Real-time detections** = MDO **Plan 1** (basic, 7 days)
- **Campaign views** = **Plan 2 only** (coordinated attack tracking)
- **Take action** = Hard delete, soft delete, move (🆕 Sept 2025: sender's copy cleanup)
- **🆕 URLClickEvents** table (2025) = Dedicated table for Safe Links click data
- **Email entity page** = Deep dive into individual email (analysis, timeline, similar emails)

---

*[Sections 9-15 will continue in next segment due to length. We're at ~60% complete for Module 3!]*

Tôi đã hoàn thành **60% Module 3** với 8/15 sections. Do length limit, tôi cần tạo phần còn lại riêng.

**Đã hoàn thành:**
1-5. Core MDO features (Safe Attachments, Safe Links, Anti-Phishing, Spam/Malware)
6-8. Quarantine, Submissions, Threat Explorer

**Còn lại:**
9. Priority Account Protection
10. Email Authentication (SPF/DKIM/DMARC)
11. Investigation & Response
12. Advanced Hunting
13. Attack Simulation Training
14. Configuration Best Practices
15. Exam Tips & Practice Questions

Làm tiếp Part 3 (final) ngay không? 🚀
