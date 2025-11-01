# SC-200: Mitigate threats using Microsoft Defender XDR

## I. Introduction to Microsoft Defender XDR threat protection

### 1. Extended Detection & Response (XDR) - Use Cases

#### 1.1 Detection of Threat

**Attack Scenario:**
- Victim receives malicious email on personal email account (not protected by Microsoft Defender for Office 365) or via USB drive
- When attachment opens, malware infects the computer
- User is unaware that an attack occurred

**Microsoft Defender for Endpoint (MDE) Detection:**
- Detects the attack and raises an alert
- Provides threat details to Security team
- Communicates to Intune that risk level on this endpoint has changed

**Disable User Access:**
- Intune Compliance Policy configured with MDE risk level severity is triggered
- Marks the account as noncompliant with organization's policy
- Conditional Access in Microsoft Entra ID blocks user access to apps

#### 1.2 Remediation

**MDE Remediates Threat via:**
- Automated remediation
- Security analyst approval of automated remediation
- Analyst manual investigation of threat

**Enterprise-Wide Remediation:**
- Adds information about the attack to Microsoft Threat Intelligence system
- Shares across all Microsoft MDE customers

#### 1.3 Share Intelligence and Restore Access

**Restore Access:**
- Once infected devices are remediated, MDE signals Intune to change device risk status
- Microsoft Entra ID Conditional Access then allows access to enterprise resources

**Remediate Threat Variants:**
- Threat signals in Microsoft Threat Intelligence are used by other Microsoft tools
- Microsoft Defender for Office 365 and Microsoft Defender for Cloud use these signals
- Detect and remediate threats in email, Office collaboration, Azure, and more

#### 1.4 Access Control Flow

**When Device is Compromised (Access Restricted):**
- Conditional Access knows about device risk because MDE notified Intune
- Intune updated the compliance status in Microsoft Entra ID
- User is restricted from accessing corporate resources
- User can still do general internet productivity tasks (YouTube, Wikipedia, etc.)
- No access to corporate resources requiring authentication

**Access Restored:**
- After threat remediation and cleanup
- MDE triggers Intune to update Microsoft Entra ID
- Conditional Access restores user's access to corporate resources

**Benefits:**
- Mitigates risk by ensuring attackers can't access corporate resources
- Minimizes impact on user productivity
- Reduces disruption of business processes

---

### 2. Microsoft Defender XDR in Security Operations Center (SOC)

#### 2.1 Modern SOC Integration Overview

Microsoft Defender XDR and Microsoft Sentinel are integrated in a Modern SOC to provide comprehensive security operations.

#### 2.2 Security Operations Model - Functions and Tools

##### Key Teams in SOC:

**1. Triage and Automation (Tier 1)**

**Functions:**
- **Automation:** Near real-time resolution of known incident types
- **Triage:** Rapid remediation of high volume of well-known incidents requiring quick human judgment
- Approve automated remediation workflows
- Identify anomalies that warrant escalation to Tier 2

**Key Learnings:**
- **90% True Positive:** Quality standard for alert feeds to avoid false alarms
- **Alert Ratio:** XDR alerts produce most high-quality alerts
- **Automation Enabler:** Reduces manual effort, provides automated investigation with human review
- **Tool Integration:** Single console (Microsoft Defender XDR) for endpoint, email, identity saves significant time
- **Focus:** Keep focus narrow on user productivity, email, endpoint AV alerts, first response for user reports

**2. Investigation and Incident Management (Tier 2)**

**Functions:**
- Escalation point from Triage (Tier 1)
- Monitor alerts indicating sophisticated attackers
- Handle behavioral alerts, business-critical asset alerts
- Monitor ongoing attack campaigns
- Deeper investigation into complex multi-stage attacks
- Pilot new/unfamiliar alert types
- Document processes for Triage team

**Incident Management:**
- Coordinate with communications, legal, leadership, business stakeholders
- Handle non-technical aspects of incidents

**3. Hunt and Incident Management (Tier 3)**

**Functions:**
- **Hunt:** Proactively hunt for undetected threats
- Assist with escalations and advanced forensics
- Refine alerts and automation
- Hypothesis-driven model (not reactive)
- Red/purple team integration

**Major Event Handling:**
- Handle business-impacting events
- Advanced investigation capabilities

#### 2.3 Common Incident Lifecycle Example

**Step-by-step flow:**
1. **Triage (Tier 1)** analyst claims malware alert from queue
2. Investigates using Microsoft Defender XDR console
3. Observes that malware requires advanced remediation (device isolation, cleanup)
4. **Escalates to Investigation (Tier 2)** who takes lead
5. Tier 1 can stay involved to learn
6. Investigation team uses Microsoft Sentinel or SIEM for broader context
7. Verifies conclusions, proceeds with remediation, closes case
8. **Later, Hunt (Tier 3)** reviews closed incidents for:
   - Detections eligible for auto-remediation
   - Multiple similar incidents with common root cause
   - Process/tool/alert improvements

**Example Outcome:**
- Tier 3 found user fell for tech scam
- Scammers had admin access on endpoint
- Flagged as higher priority alert for future

##### 2.4 Threat Intelligence Function

**Provides:**
- Context and insights to support all other functions
- Uses Threat Intelligence Platform (TIP) in larger organizations

**Activities:**
- Reactive technical research for active incidents
- Proactive research on attacker groups, attack trends, emerging techniques
- Strategic analysis to inform business and technical processes
- High-profile attack analysis

---

### 3. Microsoft Security Graph

#### 3.1 What is Microsoft Graph?

**Microsoft Graph** provides a unified programmability model to access data in:
- Microsoft 365
- Windows
- Enterprise Mobility + Security

**Single Endpoint:** `https://graph.microsoft.com` (v1.0 or beta)

##### 3.2 What's in Microsoft Graph?

**Microsoft 365 Core Services:**
- Bookings, Calendar, Delve, Excel
- Microsoft Purview eDiscovery, Microsoft Search
- OneDrive, OneNote, Outlook/Exchange
- People (Outlook contacts), Planner
- SharePoint, Teams, To Do, Viva Insights

**Enterprise Mobility + Security:**
- Advanced Threat Analytics
- Advanced Threat Protection
- Microsoft Entra ID
- Identity Manager
- Intune

**Windows Services:**
- Activities, devices, notifications
- Universal Print

**Dynamics 365 Business Central**

##### 3.3 Microsoft Graph Security API

**Architecture:**
- Intermediary service (broker)
- Single programmatic interface connecting multiple security providers
- Requests federated to all applicable security providers
- Results aggregated and returned in common schema

##### 3.4 Use Cases for Developers

**Build intelligent security services that:**
- Integrate and correlate security alerts from multiple sources
- Stream alerts to SIEM solutions
- Automatically send threat indicators to Microsoft security solutions
  - Enable alert, block, or allow actions
- Unlock contextual data to inform investigations
- Discover opportunities to learn from data
- Train security solutions
- Automate SecOps for greater efficiency

##### 3.5 Microsoft Graph Security API Versions

**Two Versions:**
1. **Microsoft Graph REST API v1.0** - Stable, production-ready
2. **Microsoft Graph REST API Beta** - Preview status, subject to change

##### 3.6 Advanced Hunting

**For Security Operations Analysts:**
- Both API versions support advanced hunting
- Uses `runHuntingQuery` method
- Query in Kusto Query Language (KQL)

**Example Query:**
```
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
{
  "Query": "DeviceProcessEvents 
           | where InitiatingProcessFileName =~ \"powershell.exe\" 
           | project Timestamp, FileName, InitiatingProcessFileName 
           | order by Timestamp desc 
           | limit 2"
}
```

**Tool:** Can use Graph Explorer to run hunting queries

---

### 4. Investigate security incidents in Microsoft Defender XDR

#### 4.1 Overview

**Cloud Guide demonstrates:**
- Microsoft Defender XDR and Microsoft Sentinel working together
- Investigating security incidents in a hybrid environment

##### 4.2 Key Investigation Capabilities

**Integrated Investigation:**
- Defender XDR provides unified incident view
- Sentinel adds SIEM capabilities for broader context
- Hybrid environment support (on-premises + cloud)

**Investigation Features:**
- Correlated alerts across multiple domains
- Attack timeline and kill chain visualization
- Evidence collection and analysis
- Automated investigation and response
- Manual investigation tools and workflows

##### 4.3 Investigation Workflow

**Typical Steps:**
1. Incident detected and raised in Defender XDR
2. Alerts correlated into single incident
3. Investigation graph shows attack scope
4. Evidence and response tab shows suspicious entities
5. Use Sentinel for deeper analysis if needed
6. Take remediation actions
7. Document findings and close incident

---

## II. Mitigate incidents using Microsoft Defender

### 1. Use the Microsoft Defender Portal

#### 1.1 Portal Overview

**Microsoft Defender Portal** (https://security.microsoft.com) is a specialized workspace for security teams that:
- Combines protection, detection, investigation, and response to email, collaboration, identity, device, and app threats
- Brings together signals from different sources for holistic view of Microsoft 365 environment
- Single pane of glass integrating multiple Microsoft security portals

**Key Features:**
- Quick access to information
- Simpler layouts
- Related information brought together
- Role-based access control for personalized experience

#### 1.2 Integrated Products

**Microsoft Defender for Office 365:**
- Prevention, detection, investigation and hunting features
- Protects email and Office 365 resources

**Microsoft Defender for Endpoint:**
- Preventative protection, post-breach detection
- Automated investigation and response for devices

**Microsoft Defender XDR:**
- Extended Detection and Response (XDR) solution
- Automatically analyzes threat data across domains
- Builds picture of attack on single dashboard

**Microsoft Defender for Cloud Apps:**
- Cross-SaaS and PaaS solution
- Deep visibility, strong data controls, enhanced threat protection

**Microsoft Defender for Identity:**
- Cloud-based security solution
- Uses on-premises Active Directory signals
- Identifies, detects, investigates advanced threats and compromised identities

**Microsoft Defender Vulnerability Management:**
- Continuous asset visibility
- Intelligent risk-based assessments
- Built-in remediation tools

**Microsoft Defender for IoT:**
- Secures Operational Technology (OT) environments
- Specialized hardware and software monitoring

**Microsoft Sentinel:**
- Streams all Defender XDR incidents and advanced hunting events
- Keeps incidents and events synchronized

#### 1.3 Related Portals

**Microsoft Purview Portal:**
- Manage compliance needs across Microsoft 365
- Information governance, classification, case management

**Microsoft Entra ID:**
- Manage organization's identities
- Setup MFA, track user sign-ins, edit company branding

**Microsoft Entra ID Protection:**
- Detect potential vulnerabilities affecting identities
- Investigate suspicious incidents
- Setup automated responses

**Azure Information Protection:**
- Configure and manage AIP client and scanner
- Automatically classify and protect email and docs

**Microsoft Defender for Cloud:**
- Protect data centers
- Advanced threat protection for Azure and non-Azure workloads

#### 1.4 Microsoft Defender XDR Unified RBAC

**Purpose:** Map permissions across different Defender products to unified model

**Key Roles:**

**Security Operations Roles:**
- Security data basics (read)
- Alerts (manage)
- Response (manage)
- Email quarantine (manage)
- Email advanced actions (manage)

**Authorization and Settings:**
- Authorization (read and manage)
- Security settings (all permissions)
- System settings (read and manage)

**Security Posture:**
- Secure Score (read and manage)
- Vulnerability management (read)
- Exception handling (manage)

**Important Notes:**
- Microsoft recommends least privilege principle
- Global Administrator should be limited to emergency scenarios
- Starting February 2025: Unified RBAC default for new Defender for Endpoint tenants
- Starting March 2025: Unified RBAC default for new Defender for Identity tenants

---

### 2. Manage Incidents

#### 2.1 What is an Incident?

**Definition:** Collection of correlated alerts that make up the story of an attack

**Benefits:**
- Comprehensive view of attack
- See where attack started
- Understand tactics used
- Assess how far attack has progressed
- View scope of impact (devices, users, mailboxes)
- Severity assessment

**Automatic Capabilities:**
- Microsoft Defender XDR automatically aggregates malicious/suspicious events
- Groups related alerts into incidents
- Can automatically investigate and resolve through AI (if enabled)

**Timeframe:** Incidents from last 30 days shown in queue

#### 2.2 Prioritize Incidents

**Microsoft Defender XDR Capabilities:**
- Applies correlation analytics
- Aggregates related alerts and investigations
- Triggers unique alerts for end-to-end visibility
- Provides broader attack story

**Incident Queue Features:**
- Shows incidents from last 30 days (default)
- Most recent incident at top
- Customizable columns for visibility
- Automatic incident naming based on alert attributes

**Available Filters:**

**Status:**
- Active
- Resolved

**Severity:**
- High, Medium, Low, Informational
- Higher severity = bigger impact, requires immediate attention

**Assignment:**
- Assigned to you
- Handled by automation
- Unassigned

**Service Sources:**
- Microsoft Defender for Endpoint
- Microsoft Cloud App Security
- Microsoft Defender for Identity
- Microsoft Defender for Office 365

**Categories:**
- Focus on specific tactics, techniques, attack components
- Multiple category option available

**Additional Filters:**
- Tags
- Entities (name or ID)
- Data sensitivity (requires Microsoft Purview Information Protection)
- Device groups
- OS platform
- Classification (true alerts, false alerts, not set)
- Automated investigation state
- Associated threat

#### 2.3 Preview Incidents

**Three interaction methods:**
1. **Circle:** Opens details window on right side with preview
2. **Greater than symbol (>):** Displays related records below current record
3. **Link:** Navigates to full page for line item

#### 2.4 Manage Incidents

**Access:** Select incident from Incidents queue

**Management Capabilities:**

**Edit Incident Name:**
- Auto-assigned based on alert attributes
- Can modify to align with naming convention

**Assign Incidents:**
- Select "Assign to me"
- Takes ownership of incident and all associated alerts

**Set Status:**
- Active: Under investigation
- In Progress: Currently being worked
- Resolved: Remediation complete

**Classification:**
- **True Positive:** Real threat with type specified
- **Informational, Expected Activity:** Security tests, red team, trusted app behavior
- **False Positive:** Technically inaccurate or misleading

**Add Comments:**
- Track changes and investigation progress
- View historical events
- Comments recorded in Comments and history section

**Add Tags:**
- Custom tags for grouping incidents
- Flag incidents with common characteristics
- Filter queue by specific tags later

**System Tags (Auto-applied):**
- Attack type (credential phishing, BEC fraud)
- Automatic actions taken
- Critical asset identification

---

### 3. Investigate Incidents

#### 3.1 Incident Page Structure

**Incident Overview:**
- Snapshot of key information
- Attack categories (MITRE ATT&CK framework)
- Scope section with impacted assets
- Alerts timeline (chronological order)
- Evidence section with remediation status

**Key Sections:**

**Attack Categories:**
- Visual and numeric view of attack progression
- Kill chain alignment

**Scope:**
- Top impacted assets
- Risk level, investigation priority, tagging

**Alerts Timeline:**
- Chronological order of alerts
- Reasons for alert linkage

**Evidence Summary:**
- Number of different artifacts
- Remediation status
- Action requirements

#### 3.2 Investigation Tabs

**Alerts Tab:**
- All related alerts
- Severity, entities involved
- Alert sources
- Linkage reasons
- Ordered chronologically by default
- Click alert for in-depth investigation

**Devices Tab:**
- All devices with related alerts
- Click device name for Device page
- View alerts triggered and related events

**Users Tab:**
- Users identified as part of incident
- Links to Microsoft Defender for Cloud Apps page

**Mailboxes Tab:**
- Mailboxes identified in incident
- Further investigation capabilities

**Apps Tab:**
- Apps identified as part of incident

**Investigations Tab:**
- All automated investigations triggered by alerts
- Shows remediation actions or pending approvals
- Navigate to Investigation details page
- Pending actions tab for approval

#### 3.3 Evidence and Responses

**Automatic Investigation:**
- Microsoft Defender XDR automatically investigates supported events
- Provides autoresponse and information about:
  - Important files
  - Processes
  - Services
  - Emails
  - More

**Entity Verdicts:**
- Malicious
- Suspicious
- Clean

**Remediation Status:** Shows overall incident status and next steps

#### 3.4 Graph Visualization

**Purpose:** Visualize associated cybersecurity threats

**Shows:**
- Patterns and correlations from various data points
- Attack story
- Entry point
- Indicators of compromise
- Activity observed on devices
- File detections
- Worldwide instances
- Organization-specific occurrences

**Interaction:** Click circles for detailed information

---

### 4. Manage and Investigate Alerts

#### 4.1 Alert Management

**Access:** Select alert from Alerts queue or Device page Alerts tab

**Metadata Fields:**

**Severity Levels:**

**High (Red):**
- Associated with APT (Advanced Persistent Threats)
- High risk, severe damage potential
- Examples: credential theft tools, ransomware, security sensor tampering

**Medium (Orange):**
- EDR post-breach behaviors
- Possible APT indicators
- Attack stage behaviors, anomalous registry changes, suspicious file execution

**Low (Yellow):**
- Prevalent malware threats
- Hack-tools, non-malware hack tools
- Exploration commands, log clearing

**Informational (Grey):**
- Not harmful to network
- Drives security awareness

**Note:** Microsoft Defender AV vs Defender for Endpoint severity differs:
- AV: Absolute severity of detected threat
- Endpoint: Severity of behavior, risk to device and organization

**Categories (MITRE ATT&CK Aligned):**
- Collection: Locating and collecting data for exfiltration
- Command and control: Connecting to attacker infrastructure
- Credential access: Obtaining valid credentials
- Defense evasion: Avoiding security controls
- Discovery: Gathering information about resources
- Execution: Launching attacker tools and malicious code
- Exfiltration: Extracting data to external location
- Exploit: Exploit code and exploitation activity
- Initial access: Gaining initial entry
- Lateral movement: Moving between devices
- Malware: Backdoors, trojans, malicious code
- Persistence: Creating autostart points
- Privilege escalation: Obtaining higher permissions
- Ransomware: Encrypting files, extorting payment
- Suspicious activity: Atypical activity
- Unwanted software: PUAs affecting productivity

#### 4.2 Alert Actions

**Link to Another Incident:**
- Create new incident
- Link to existing incident

**Assign Alerts:**
- "Assign to me" option

**Suppress Alerts:**
- Create suppression rules for innocuous alerts
- Known tools or processes
- Rules take effect from creation point forward
- Two contexts:
  - Suppress alert on this device
  - Suppress alert in my organization

**Change Status:**
- New
- In Progress
- Resolved

**Classification:**
- True positive / False positive
- "Determination" field for true positive extra fidelity
- Used to monitor alert quality

**Add Comments:**
- Track changes
- View alert history
- Recorded in Comments and history section

#### 4.3 Alert Investigation

**Alert Page Components:**
- Alert title
- Affected assets
- Details side pane
- Alert story

**Investigation Process:**
1. Select affected assets or entities in alert story tree
2. Details pane auto-populates with information
3. Entities are clickable and expandable
4. Blue stripe indicates entity in focus
5. Selecting entity switches context
6. Review further information and manage entity

**Alert Story:**
- Details why alert triggered
- Related events before and after
- Related entities
- Entities expandable with expand icon

**Take Action:**
- Details pane offers controls for actions
- Mark alert status as Resolved
- Classify as False alert or True alert
- Select determination if true positive
- Create suppression rule if false positive with LOB application

---

### 5. Manage Automated Investigations

#### 5.1 Automated Investigation and Remediation (AIR)

**Purpose:** Address multitude of threats efficiently and effectively

**Challenges Addressed:**
- Seemingly never-ending flow of threats
- High volume of alerts
- Need for immediate action

**Benefits:**
- Uses inspection algorithms based on security analyst processes
- Immediate action to resolve breaches
- Significantly reduces alert volume
- Allows SOC to focus on sophisticated threats

#### 5.2 How Automated Investigation Starts

**Trigger:** When alert is triggered, security playbook activates

**Example:**
1. Malicious file detected on device
2. Alert triggered
3. Automated investigation begins
4. Checks if file present on other devices
5. Details available during and after investigation

**Verdicts:**
- Malicious
- Suspicious
- No threats found

#### 5.3 Investigation Details

**Access:** Select triggering alert to view details

**Tabs Available:**

**Alerts:** Alert(s) that started investigation

**Devices:** Device(s) where threat was seen

**Evidence:** Entities found malicious during investigation

**Entities:** Details about each analyzed entity with determination

**Log:** Chronological, detailed view of all investigation actions

**Pending Actions:** Actions awaiting approval (if any)

#### 5.4 Investigation Scope Expansion

**Automatic Expansion:**
- Other alerts from same device added to ongoing investigation
- Same threat on other devices adds those devices
- If incriminated entity seen on another device, scope expands
- General security playbook starts on new device

**Approval Requirement:**
- If 10+ devices found during expansion, requires approval
- Visible on Pending actions tab

#### 5.5 Threat Remediation

**Verdict Generation:** For each piece of evidence investigated

**Remediation Actions Examples:**
- Send file to quarantine
- Stop a service
- Remove scheduled task
- Disable driver
- Remove registry key

**Action Determination:** Based on:
- Automation level set for organization
- Other security settings
- PUA (Potentially Unwanted Applications) protection

**Action Tracking:** All actions (pending or completed) viewable in Action Center

#### 5.6 Automation Levels

**Full Automation (Recommended):**
- Remediation actions taken automatically on malicious artifacts
- All actions viewable in Action Center History tab
- Can undo actions if necessary

**Semi-automation Options:**

**1. Require approval for any remediation:**
- Approval required for ALL remediation actions
- Pending actions in Action Center Pending tab

**2. Require approval for core folders remediation:**
- Approval required for files/executables in core folders (e.g., \windows\*)
- Automatic remediation for non-core folders
- Pending actions in Pending tab
- Completed actions in History tab

**3. Require approval for non-temp folders remediation:**
- Approval required for files/executables NOT in temp folders
- Automatic remediation for temp folders:
  - \users\*\appdata\local\temp\*
  - \documents and settings\*\local settings\temp\*
  - \windows\temp\*
  - \users\*\downloads\*
- Pending actions in Pending tab
- Completed actions in History tab

**No Automated Response (Not Recommended):**
- No automated investigation runs
- No remediation actions taken or pending
- Other threat protection features still active
- Reduces security posture

**Important:** Full automation is reliable, efficient, safe, and recommended

---

### 6. Use the Action Center

#### 6.1 Unified Action Center Overview

**Location:** Microsoft Defender portal

**Purpose:** Lists pending and completed remediation actions in one location for:
- Devices
- Email & collaboration content
- Identities

**Benefits:**
- Brings together remediation actions across Defender for Endpoint and Defender for Office 365
- Common language for all remediation actions
- Unified investigation experience
- "Single pane of glass" for security operations

#### 6.2 Action Center Structure

**Pending Tab:**
- List of ongoing investigations requiring attention
- Recommended actions for approval or rejection
- Only appears if pending actions exist

**History Tab (Audit Log):**
- Remediation actions from automated investigation
- Actions approved by security operations team (some can be undone)
- Commands run in Live Response sessions (some can be undone)
- Actions by Microsoft Defender Antivirus (some can be undone)

#### 6.3 Review Pending Actions

**Access:** Automated Investigations → Action center

**Verdicts Generated:**
- Malicious
- Suspicious
- No threats found

**Actions Based On:**
- Type of threat
- Resulting verdict
- Device group configuration

**Approval Process:**
1. Select item on Pending tab
2. Select investigation from categories
3. Panel opens with approval/reject options
4. View details: file/service details, investigation details, alert details
5. Select "Open investigation page" link for full details
6. Can select multiple investigations for bulk approval/reject

#### 6.4 Review Completed Actions

**Process:**
1. Select History tab
2. Expand time period if needed for more data
3. Select item for detailed information about remediation action

#### 6.5 Undo Completed Actions

**When to Undo:**
- Device or file determined not a threat

**Supported Actions:**

**Sources:**
- Automated investigation
- Microsoft Defender Antivirus
- Manual response actions

**Undoable Actions:**
- Isolate device
- Restrict code execution
- Quarantine a file
- Remove a registry key
- Stop a service
- Disable a driver
- Remove a scheduled task

**Remove File from Quarantine (Multiple Devices):**
1. On History tab, select file with Action type "Quarantine file"
2. In right pane, select "Apply to X more instances of this file"
3. Select Undo

#### 6.6 Action Source Details

**Action Source Column Values:**

| Action Source | Description |
|--------------|-------------|
| Manual device action | Manual action on device (isolation, file quarantine) |
| Manual email action | Manual action on email (soft-delete, remediate) |
| Automated device action | Automated action on entity (file, process) |
| Automated email action | Automated action on email content |
| Advanced hunting action | Actions via advanced hunting |
| Explorer action | Actions via Explorer |
| Manual live response action | Actions via live response |
| Live response action | Actions via Defender for Endpoint APIs |

#### 6.7 Submissions Portal

**Purpose:** Submit emails, URLs, attachments to Microsoft for scanning

**Available For:** Microsoft 365 organizations with Exchange Online mailboxes

**Submission Analysis Provides:**
- Email authentication check (pass/fail)
- Policy hits information
- Payload reputation/detonation
- Grader analysis (human review)

**Requirements:**
- Security Administrator or Security Reader role
- Can submit messages up to 30 days old
- Messages not purged by user/admin

**Throttling Rates:**
- Max 150 submissions per 15 minutes
- Max 3 same submissions per 24 hours
- Max 1 same submission per 15 minutes

**Submission Types:**
1. **Email:** Network message ID or upload .msg/.eml file
2. **URL:** Enter full URL
3. **Email Attachment:** Upload file

**Submission Reasons:**
- Shouldn't have been blocked (False positive)
- Should have been blocked (False negative):
  - Phish
  - Malware
  - Spam (email only)

**User Reported Messages:**
- View submissions from Report Message add-in
- Report Phishing add-in
- Built-in Outlook on the web reporting
- Convert user reports to admin submissions

**Admin Actions:**
- Mark as and notify users (No threats found, Phishing, Junk)
- Submit to Microsoft for analysis
- Trigger investigation

---

### 7. Explore Advanced Hunting

#### 7.1 Advanced Hunting Overview

**Definition:** Query-based threat-hunting tool

**Capabilities:**
- Explore up to 30 days of raw data
- Proactively inspect events in network
- Locate threat indicators and entities
- Flexible access to data
- Unconstrained hunting for known and potential threats

**Additional Use:** Build custom detection rules that run automatically

**Data Sources:**
- Microsoft Defender for Endpoint
- Microsoft Defender for Office 365
- Microsoft Defender for Cloud Apps
- Microsoft Defender for Identity

**Requirement:** Microsoft Defender XDR must be turned on

#### 7.2 Data Freshness and Update Frequency

**Event/Activity Data:**
- Tables: alerts, security events, system events, routine assessments
- Nearly immediate (after successful sensor transmission)
- Available almost immediately after collection

**Entity Data:**
- Tables: users and devices information
- Sources: Active Directory entries, event logs
- Updated every 15 minutes with new information
- Full consolidation every 24 hours for comprehensive records

**Time Zone:** All time information in UTC

#### 7.3 Data Schema

**Schema Components:** Multiple tables with event or entity information

**Schema Reference Access:**
- Select "View reference" next to table name
- Select "Schema reference" to search for table

**For Each Table:**
- Table description (data type and source)
- All columns
- Action types (for event tables)
- Sample queries

**Key Schema Tables:**

| Table Name | Description |
|-----------|-------------|
| AlertEvidence | Files, IPs, URLs, users, devices associated with alerts |
| AlertInfo | Alerts from Defender products with severity and categorization |
| CloudAppEvents | Events in Office 365 and other cloud apps |
| DeviceEvents | Multiple event types including security control events |
| DeviceFileCertificateInfo | Certificate information of signed files |
| DeviceFileEvents | File creation, modification, file system events |
| DeviceImageLoadEvents | DLL loading events |
| DeviceInfo | Machine information including OS |
| DeviceLogonEvents | Sign-ins and authentication events |
| DeviceNetworkEvents | Network connection and related events |
| DeviceNetworkInfo | Network properties (adapters, IPs, MACs, networks, domains) |
| DeviceProcessEvents | Process creation and related events |
| DeviceRegistryEvents | Registry entry creation and modification |
| DeviceTvmSecureConfigurationAssessment | TVM assessment events |
| DeviceTvmSoftwareInventory | Software installed on devices |
| DeviceTvmSoftwareVulnerabilities | Software vulnerabilities and available updates |
| EmailAttachmentInfo | Files attached to emails |
| EmailEvents | Email events (delivery, blocking) |
| EmailPostDeliveryEvents | Security events post-delivery |
| EmailUrlInfo | Information about URLs in emails |
| IdentityDirectoryEvents | On-premises domain controller events |
| IdentityInfo | Account information from various sources |
| IdentityLogonEvents | Authentication events (AD and online services) |
| IdentityQueryEvents | Queries for AD objects |

#### 7.4 Custom Detections

**Purpose:** Proactively monitor and respond to:
- Various events and system states
- Suspected breach activity
- Misconfigured endpoints

**Features:**
- Alerts for rule-based detections
- Automatic response actions for files and devices
- Regular interval execution
- Alert generation on matches

#### 7.5 Create Detection Rules

**Step 1: Prepare Query**
- Go to Advanced hunting
- Select existing query or create new
- Run query to identify errors
- Understand possible results

**Important:** Each rule limited to 100 alerts per run

**Required Columns:**
- Timestamp
- DeviceId
- ReportId

**Query Example:**
```
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 5
```

**Step 2: Create Rule and Provide Details**
- Detection name
- Frequency (see step 3)
- Alert title
- Severity (potential risk level)
- Category (threat type)
- MITRE ATT&CK techniques
- Description
- Recommended actions

**Step 3: Rule Frequency**

**Initial Run:** Checks past 30 days immediately after creation

**Frequency Options:**
- Every 24 hours → checks past 30 days
- Every 12 hours → checks past 48 hours
- Every 3 hours → checks past 12 hours
- Every hour → checks past 4 hours
- Continuous (NRT) → near real-time checking

**Step 4: Choose Impacted Entities**
- Identify main affected entity (device or user)
- One column per entity type
- Only columns returned by query can be selected

**Step 5: Specify Actions**

**Actions on Devices (DeviceId column):**
- Isolate device (full network isolation)
- Collect investigation package
- Run antivirus scan
- Initiate investigation

**Actions on Files (SHA1 or InitiatingProcessSHA1 column):**
- Allow/Block (add to custom indicator list)
- Quarantine file (delete and move to quarantine)

**Step 6: Set Rule Scope**
- All devices
- Specific device groups
- Only data from in-scope devices queried
- Actions taken only on in-scope devices

**Step 7: Review and Turn On**
- Review rule
- Select "Create" to save
- Rule runs immediately based on configured frequency

---

### 8. Investigate Microsoft Entra Sign-in Logs

#### 8.1 Sign-in Investigation

**Purpose:** Perform sign-in investigations including conditional access policies

**Query Tables (with KQL):**

| Location | Table |
|----------|-------|
| Microsoft Defender XDR Threat Hunting | AADSignInEventsBeta |
| Microsoft Entra ID Log Analytics | SigninLogs |

#### 8.2 Access Sign-in Logs

**Path:**
1. Azure portal
2. Select Microsoft Entra ID
3. Select Sign-in Logs (in Monitoring Group)

**Query Output Columns:**
- Date
- User
- Application
- Status
- Conditional Access (policy applied)

---

### 9. Understand Microsoft Secure Score

#### 9.1 Secure Score Overview

**Two Components:**

**Microsoft Secure Score (365):**
- Measurement of organization's security posture
- Higher number = more recommended actions taken

**Cloud Secure Score (Risk-based):**
- Representation of cloud security posture

**Part of:** Exposure Management tools in Microsoft Defender portal

#### 9.2 Benefits

**Capabilities:**
- Protect organization from threats
- Centralized dashboard monitoring
- Robust visualizations of metrics and trends
- Integration with other Microsoft products
- Score comparison with similar organizations
- Third-party solution tracking

#### 9.3 Products Included

**Microsoft Products:**
- Microsoft Defender for Office
- Exchange Online
- Microsoft Entra ID
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity
- Microsoft Defender for Cloud Apps
- Microsoft Purview Information Protection
- Microsoft Teams
- App governance

**Third-Party Products:**
- Citrix ShareFile
- Docusign
- GitHub
- Okta
- Salesforce
- ServiceNow
- Zoom

**Note:** Can mark improvement actions as covered by third party or alternate mitigation

#### 9.4 Take Action to Improve Score

**Recommended Actions Tab:**
- Lists security recommendations
- Addresses possible attack surfaces

**Status Categories:**
- To address
- Planned
- Risk accepted
- Resolved through third party
- Resolved through alternate mitigation
- Completed

**Features:**
- Search functionality
- Filter options
- Grouping capabilities

---

### 10. Analyze Threat Analytics

#### 10.1 Threat Analytics Overview

**Source:** Threat intelligence solution from expert Microsoft security researchers

**Purpose:** Assist security teams facing emerging threats

**Emerging Threats Include:**
- Active threat actors and their campaigns
- Popular and new attack techniques
- Critical vulnerabilities
- Common attack surfaces
- Prevalent malware

#### 10.2 Access Threat Analytics

**Two Methods:**
1. Upper left navigation menu → Expand "Threat intelligence"
2. Dedicated Threat analytics dashboard card

**Dashboard Shows:**
- Threats to organization by impact
- Threats by exposure

**Key Concepts:**
- High impact threats: Greatest potential to cause harm
- High exposure threats: Assets most vulnerable to

#### 10.3 Why Threat Analytics?

**Critical Capabilities:**
- Quickly identify and react to emerging threats
- Learn if currently under attack
- Assess threat impact to assets
- Review resilience against threats
- Identify mitigation, recovery, prevention actions

#### 10.4 Threat Analytics Dashboard

**Latest Threats Section:**
- Most recently published/updated threat reports
- Number of active and resolved alerts

**High-impact Threats Section:**
- Threats with highest impact to organization
- Sorted by highest number of active and resolved alerts

**Highest Exposure Section:**
- Threats with highest exposure levels first
- Exposure level calculated from:
  - Severity of associated vulnerabilities
  - Number of exploitable devices in organization

#### 10.5 Threat Analytics Report Sections

**Overview:**
- Preview of detailed analyst report
- Charts showing organizational impact
- Exposure through misconfigured/unpatched devices

**Assessment Sections:**

**Assess Impact on Organization:**
- Related incidents count and severity
- Alerts over time (Active vs Resolved)
- Impacted assets (devices, email accounts)
- Prevented email attempts (last 7 days)

**Review Security Resilience:**
- Secure configuration status
- Vulnerability patching status

**Analyst Report:**
- Detailed expert write-up
- Attack chain descriptions
- Tactics/techniques (MITRE ATT&CK mapped)
- Exhaustive recommendations
- Threat hunting guidance

**Related Incidents Tab:**
- List of all related incidents
- Assign incidents
- Manage alerts

**Impacted Assets Tab:**
- Impacted devices (unresolved Defender for Endpoint alerts)
- Impacted mailboxes (triggered Defender for Office 365 alerts)

**Prevented Email Attempts Tab:**
- Emails blocked before delivery
- Emails sent to junk mail folder
- Threat indicators identified

**Exposure & Mitigations Tab:**
- Actionable recommendations
- Security updates for vulnerabilities
- Supported security configurations
- Cloud-delivered protection
- PUA protection
- Real-time protection
- Data from threat and vulnerability management

#### 10.6 Threat Tags and Filters

**Available Threat Tags:**
- Ransomware
- Phishing
- Vulnerability
- Activity group

**Report Types Filter:**
- Tools and techniques
- Specific report types

**Benefits:**
- View most relevant reports by category
- Filter by threat tag or report type
- Efficient review of threat report list

#### 10.7 Email Notifications

**Setup Process:**
1. Settings → Microsoft Defender XDR → Email notifications
2. Threat analytics → Create notification rule
3. Provide rule name (required) and description (optional)
4. Toggle rule on/off
5. Choose report types (all updates or specific tags/types)
6. Add recipients
7. Send test email
8. Review and create rule

**Note:** Name and description only accept English letters and numbers (no spaces, dashes, punctuation)

---

### 11. Analyze Reports

#### 11.1 Reports Overview

**Location:** Reports blade in Microsoft Defender portal

**Coverage:**
- Microsoft Defender for Endpoint
- Microsoft Defender for Office 365

#### 11.2 General Reports

**Security Report:**
- Security trends information
- Protection status tracking for:
  - Identities
  - Data
  - Devices
  - Apps
  - Infrastructure

#### 11.3 Endpoints Reports

**Threat Protection:**
- Security detections and alerts details

**Device Health and Compliance:**
- Health state monitoring
- Antivirus status
- Operating system platforms
- Windows 10 versions for devices

**Vulnerable Devices:**
- Vulnerable devices information
- Exposure by severity level
- Exploitability
- Age
- Additional metrics

**Web Protection:**
- Web activity information
- Web threats detected

**Firewall:**
- Connections blocked by firewall
- Related devices
- Block reasons
- Ports used

**Device Control:**
- Organization's media usage data

**Attack Surface Reduction Rules:**
- Detections information
- Misconfiguration details
- Suggested exclusions

#### 11.4 Email & Collaboration Reports

**Email & Collaboration Reports:**
- Microsoft recommended actions
- Improve email and collaboration security

**Manage Schedules:**
- Schedule management for security team reports

**Reports for Download:**
- Download one or more reports

**Exchange Mail Flow Reports:**
- Deep link to Exchange admin center

---

### 12. Configure the Microsoft Defender Portal

#### 12.1 Settings Overview

**Purpose:** Configure related Microsoft Defender products

**Primary Setting:** Email notifications configuration

#### 12.2 Email Notification Types

| Notification Type | Description |
|------------------|-------------|
| Incidents | When new incidents are created |
| Threat Analytics | When new threat analytic reports are created |

#### 12.3 Manage Incident Email Notifications

**Access Path:**
1. Navigation pane → Settings
2. Microsoft Defender XDR
3. Email notifications
4. Select Incidents

**Add New Notification:**
1. Select "Add incident email notification"
2. Enter name and description → Next
3. Select device and alert criteria → Next
4. Enter recipients email address → Next
5. Select "Create rule" button

#### 12.4 Manage Threat Analytics Email Notifications

**Access Path:**
1. Navigation pane → Settings
2. Microsoft Defender XDR
3. Email notifications
4. Select Threat Analytics

**Add New Notification:**
1. Select "Create a notification rule"
2. Enter name and description → Next
3. Select threat analytics criteria → Next
4. Enter recipients email address → Next
5. Select "Create rule" button

---

## III. Remediate risks with Microsoft Defender for Office 365

### 1. Introduction to Microsoft Defender for Office 365

#### 1.1 Overview

**Microsoft Defender for Office 365** is a cloud-based email filtering service that protects organizations against:
- Unknown malware and viruses
- Zero-day protection
- Harmful links in real time

**Key Capabilities:**
- Rich reporting
- URL trace capabilities
- Insight into attacks in organization

#### 1.2 Benefits

**Industry-leading Protection:**
- Uses 6.5 trillion signals daily from email
- Quickly and accurately detects threats
- Protects against sophisticated attacks (phishing, zero-day malware)
- 2018 Statistics:
  - Blocked 5 billion phish emails
  - Analyzed 300k phish campaigns
  - Protected 4 million unique users

**Actionable Insights:**
- Correlates signals from broad range of data
- Helps identify and prioritize potential problems
- Provides recommendations for remediation
- Empowers administrators to proactively secure organization

**Automated Response:**
- Advanced automated response options
- Addresses post-breach investigation challenges
- Saves time, money, and resources
- Solves expertise and resource gaps

**Training & Awareness:**
- In-product notifications about risks
- Attack simulator for realistic threat simulations
- Train users to be more aware and vigilant
- User reporting capabilities for suspicious content

#### 1.3 Deployment Scenarios

**Filtering-Only Scenario:**
- Cloud-based email protection for on-premises Exchange Server
- Protection for any on-premises SMTP email solution

**Cloud-Hosted Protection:**
- Enabled to protect Exchange Online cloud-hosted mailboxes

**Hybrid Deployment:**
- Protects messaging environment in mixed scenarios
- Controls mail routing with mix of on-premises and cloud mailboxes
- Uses Exchange Online Protection for inbound email filtering

---

### 2. Automate, Investigate, and Remediate

#### 2.1 Automated Investigation and Response (AIR)

**Purpose:** Save time with automated capabilities

**Why Important:**
- Time is of essence in cyberattacks
- Sooner threats identified and mitigated, the better
- Saves security operations team time and effort

**Capabilities:**
- Set of security playbooks
- Can be launched automatically (when alert triggered)
- Can be launched manually (from Explorer view)

#### 2.2 AIR Workflow Example

**Step 1: Alert Generation**
- Native alert generated by Office 365
- Example: URL recently weaponized detected by Safe Links
- Attackers send benign URLs initially to bypass security
- Weaponize URLs after delivery to activate attack

**Step 2: AIR Playbook Triggered**
- Microsoft Defender for Office 365 triggers AIR playbook
- Auto investigation completes
- Alert resolved automatically

**Step 3: Investigation Graph**
- Microsoft Defender Summary Investigation Graph shows:
  - Evidence
  - Entities: URLs, emails, users, activities, devices
  - Relationships between entities
  - Automatically investigated items

**Step 4: Investigation Findings**

**Emails:**
- Identified as relevant to investigation
- Based on: sender, IP, domain, URL, email attributes
- Subset identified as malicious
- Sent from internal user (strong indicator of compromise)

**User Pivot:**
- Identifies anomalies for user:
  - Suspicious sign-in
  - Mass downloads of documents

**Threats Identified:**
- Compromised user
- User anomalies
- Compromised device threats

**Step 5: Auto Remediations**
- Block the URL
- Delete emails in mailboxes related to URL
- Trigger Microsoft Entra workflows:
  - Password reset
  - MFA for compromised user

**Core Elements:**
- Automatic action capability
- Manual approval option (policy-based)

#### 2.3 Remediation Actions in AIR

**Remediation Actions Include:**
- Soft delete email messages or clusters
- Block URL (time-of-click)
- Turn off external mail forwarding
- Turn off delegation

**Process:**
- Actions typically require approval by security operations team
- Found in Pending actions tab under investigation
- Can be approved or rejected by security team

**Note:** Whenever automated investigation is running or completed, one or more remediation actions will be awaiting approval

---

### 3. Configure, Protect, and Detect

#### 3.1 Policy Configuration

**Location:** Microsoft Defender portal

**Configuration:**
- Security team defines policies
- Policies determine behavior and protection level
- Applies to predefined threats

**Policy Flexibility:**
- Fine-grained threat protection settings
- Set at multiple levels:
  - User level
  - Organization level
  - Recipient level
  - Domain level

**Important:** Review policies regularly as new threats emerge daily

#### 3.2 Safe Attachments

**Purpose:** Protects against unknown malware and viruses

**Features:**
- Zero-day protection
- Safeguards messaging system
- Messages/attachments without known signature routed to special environment
- Uses machine learning and analysis techniques to detect malicious intent

**Action Options:**

**Off:**
- Attachments won't be scanned for malware

**Monitor:**
- Continues delivering message after malware detected
- Tracks scanning results

**Block:**
- Blocks current and future emails with detected malware
- Blocks attachments

**Replace:**
- Blocks attachments with detected malware
- Continues to deliver message body to user

**Dynamic Delivery:**
- Immediately delivers message body without attachments
- Reattaches attachments after scanning if safe

**Redirect Options:**
- Enable redirect: Forward blocked/replaced/monitored attachments to security admin
- Apply selection if scanning times out or errors occur

**Policy Targeting:**
- Target by domain, username, or group membership
- Exceptions can be configured

**Bypass Filtering:**
- Create transport rule (mail flow rule) in EAC
- Useful for trusted internal senders (scans, faxes)
- Set message header: `X-MS-Exchange-Organization-SkipSafeAttachmentProcessing`
- Not recommended for all internal messages (compromised account risk)

#### 3.3 Safe Links

**Purpose:** Proactively protects users from malicious URLs

**Protection:**
- In email messages
- In Office documents
- Protection remains every time link is selected
- Malicious links dynamically blocked
- Good links can be accessed

**Supported Apps:**

**Desktop:**
- Microsoft 365 apps for enterprise (Windows/Mac)
- Word, Excel, PowerPoint, Visio on Windows
- Office for the web (Word, Excel, PowerPoint, OneNote)

**Mobile:**
- Office apps on iOS and Android

**Collaboration:**
- Microsoft Teams channels and chats

**Key Features:**
- Client and location agnostic
- Behavior consistent across locations and devices
- Supports Office 2016 clients with Office 365 credentials

**Default Policy:**
- Controls global settings
- Which links to block
- Which links to wrap
- Can't delete but can edit

**Recommendation:** Apply Safe Links policies to ALL users

**Configuration Options:**

**Action for Unknown URLs:**
- Selecting "On" allows URLs to be rewritten and checked

**Use Safe Attachments for Downloadable Content:**
- Enables URL detection to scan files hosted on websites
- Example: `https://contoso.com/maliciousfile.pdf` opened in hypervisor
- Warning shown if file found malicious

**Apply Safe Links to Internal Messages:**
- Same protection level for links sent within organization

**Do Not Track When Users Click:**
- Enables/disables storing Safe Links click data
- Microsoft recommends leaving unselected (enables tracking)

**Do Not Allow Users to Click Through:**
- Prevents users from proceeding to malicious website

**Do Not Rewrite Following URLs:**
- Add URLs known to be safe
- Example: Partner websites frequently accessed
- Bypasses Safe Links for these URLs

**Bypass Filtering:**
- Create transport rule
- Message header: `X-MS-Exchange-Organization-SkipSafeLinksProcessing`

#### 3.4 Anti-phishing Policies

**Purpose:** Check incoming messages for phishing indicators

**Evaluation Process:**
- Messages covered by Defender for Office 365 policies
- Multiple machine learning models analyze messages
- Action taken based on configured policies

**Note:** No default anti-phishing policy exists

**Impersonation Protection:**

**What is Impersonation:**
- Sender or sender's email domain looks similar to real sender/domain
- Domain example: `contoso.com` vs `ćóntoso.com`
- User example: `michelle@contoso.com` vs `michele@contoso.com`

**Characteristics:**
- Impersonated domain might be legitimate (registered, authenticated)
- Intent is to deceive recipients

**Configuration Options:**
- Set of users to protect
- Domains to protect
- Actions for protected users:
  - Redirect messages
  - Send to junk folders
- Safety tips
- Trusted senders and domains
- Anti-spoofing settings (included in policy)

**Exclusive Features:** Settings are exclusive to Microsoft Defender for Office 365 anti-phishing

---

### 4. Simulate Attacks

#### 4.1 Threat Investigation and Response Tools

**Purpose:** Enable security team to anticipate, understand, and prevent malicious attacks

**Note:** Capabilities now found in Microsoft Defender XDR (Extended Detection and Response)

**Includes:**
- Microsoft Defender for Office 365
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity

**Benefits:**
- Unified view of threats across organization
- Investigate and respond to threats across Microsoft 365 environment

#### 4.2 Available Tools

**Threat Trackers:**
- Provide latest intelligence on cybersecurity issues
- View information about latest malware
- Take countermeasures before becoming actual threat

**Types:**
- Noteworthy trackers
- Trending trackers
- Tracked queries
- Saved queries

**Threat Explorer (Real-time Detections):**
- Real-time report for identifying and analyzing recent threats
- Configurable for custom time periods
- Also referred to as "Explorer"

**Attack Simulator:**
- Run realistic attack scenarios in organization
- Identify vulnerabilities

**Available Simulations:**
- Spear phishing
- Credential harvest
- Attachment attacks
- Password spray
- Brute force password attacks

#### 4.3 Threat Explorer Features

**Initial View:**
- Variety of threat families impacting organization over time
- Top threats
- Top targeted users

**Graph Categories:**
- All email (shown by default)
- Multiple filter options available

**Filter Options:**
- Sender address
- Recipients
- Detection technology used

**Detection Technology:**
- Identifies if email blocked by:
  - Microsoft Defender for Cloud sandboxing
  - Exchange Online Protection (EOP) filter
- Graph adjusts to reflect examined category

**Deeper Threat Analysis:**

**Threat Information:**
- Thorough description of malware family behavior
- Definition of threat
- Message traces of emails delivering threat
- Technical details
- Global details
- Advanced analysis

**Top Targeted Users Tab:**
- Each instance user was sent malware attachment
- View details:
  - Specific recipients
  - Subject
  - Sender domain
  - Sender IP

**Delivery Action Column:**
- Email caught and blocked before reaching user
- Delivered as spam

**Status Information:**
- Shows if user received and opened email
- Enables reaching out to user
- Take remediation steps (scan device)

---

## IV. Manage Microsoft Entra Identity Protection

### 1. Review Identity Protection Basics

#### 1.1 Overview

**Microsoft Entra Identity Protection** enables organizations to:
- Automate detection and remediation of identity-based risks
- Investigate risks using data in portal
- Export risk detection data to third-party utilities

**Requirements:** Microsoft Entra ID Premium P2 license

**Microsoft Signals:** Analyzes 6.5 trillion signals per day to identify and protect customers from threats

**Signal Integration:**
- Fed to Conditional Access for access decisions
- Fed to SIEM tools for further investigation

#### 1.2 Risk Detection Types

| Risk Detection Type | Description |
|---------------------|-------------|
| Anonymous IP address | Sign in from anonymous IP (Tor browser, anonymizer VPNs) |
| Atypical travel | Sign in from atypical location based on recent sign-ins |
| Malware-linked IP address | Sign in from malware-linked IP |
| Unfamiliar sign-in properties | Sign in with properties not seen recently |
| Leaked credentials | User's valid credentials have been leaked |
| Password spray | Multiple usernames attacked using common passwords |
| Microsoft Entra threat intelligence | Known attack pattern identified |
| New country | Discovered by Microsoft Defender for Cloud Apps |
| Activity from anonymous IP | Discovered by MDCA |
| Suspicious inbox forwarding | Discovered by MDCA |

#### 1.3 Permissions

**Required Roles:**
- Security Reader
- Security Operator
- Security Administrator
- Global Reader Administrator

**Role Capabilities:**

| Role | Can Do | Can't Do |
|------|--------|----------|
| Security Administrator | Full access to Identity Protection | Reset password for user |
| Security Operator | View reports, Dismiss user risk, Confirm safe sign-in, Confirm compromise | Configure/change policies, Reset password, Configure alerts |
| Security Reader | View all reports and Overview | Configure/change policies, Reset password, Configure alerts, Give feedback |

**Note:** Security Operator cannot access Risky sign-ins report

**Conditional Access Administrators:** Can create policies that factor in sign-in risk

#### 1.4 License Requirements

**Microsoft Entra ID Premium P2 Required For:**
- User risk policy
- Sign-in risk policy (via Identity Protection or Conditional Access)
- Full access to security reports (Overview, Risky users, Risky sign-ins, Risk detections)
- Notifications (Users at risk detected alerts, Weekly digest)
- MFA registration policy

**Limited/No Access in Free and Premium P1:**
- Limited information on risky users/sign-ins
- No risk details or risk level shown
- No notifications

---

### 2. Implement and Manage User Risk Policy

#### 2.1 Risk Policy Types

**Two Risk Policies:**

**Sign-in Risk Policy:**
- Detects suspicious actions during sign-in
- Focused on sign-in activity itself
- Analyzes probability sign-in performed by someone other than user

**User Risk Policy:**
- Detects probability user account compromised
- Detects risk events atypical of user's behavior

**Purpose:** Automate response to risk detections and allow user self-remediation

#### 2.2 Prerequisites

**For User Self-remediation:**
- Users must be registered for:
  - Self-service password reset (SSPR)
  - Multifactor authentication (MFA)
- Recommend enabling combined security information registration experience
- Allows users to unblock themselves without admin intervention

#### 2.3 Choosing Risk Levels

**Microsoft's Recommendations:**
- **User risk policy threshold:** High
- **Sign-in risk policy:** Medium and higher

**Balancing Act:**

**High Threshold:**
- Reduces policy trigger frequency
- Minimizes user challenges
- Excludes Low and Medium risk detections
- Does not block attackers from exploiting compromised identity

**Low Threshold:**
- Introduces extra user interrupts
- Increased security posture

**Consideration:** Organizations must balance user experience and security posture

#### 2.4 Exclusions

**Exclusion Considerations:**
- Allow excluding users (e.g., emergency access or break-glass admin accounts)
- Organizations determine when to exclude accounts from specific policies
- Based on how accounts are used

**Best Practices:**
- Review all exclusions regularly for applicability
- Configured trusted network locations used by Identity Protection
- Helps reduce false positives

---

### 3. Monitor, Investigate, and Remediate Elevated Risky Users

#### 3.1 Identity Protection Reports

**Three Reports Available:**
1. Risky users
2. Risky sign-ins
3. Risk detections

**Location:** Microsoft Entra admin center → Identity → Protection → Identity Protection

**Export Capabilities:**
- Download events in .CSV format for external analysis
- Risky users and sign-ins: Most recent 2,500 entries
- Risk detections: Most recent 5,000 records

**Microsoft Graph API:**
- Integrate to aggregate data with other organizational sources

#### 3.2 Risky Users Report

**Information Provided:**
- Which users are at risk, remediated, or dismissed
- Details about detections
- History of all risky sign-ins
- Risk history

**Administrator Actions:**
- Reset user password
- Confirm user compromise
- Dismiss user risk
- Block user from signing in
- Investigate further using Azure ATP

#### 3.3 Risky Sign-ins Report

**Data Period:** Up to past 30 days (one month)

**Information Provided:**
- Sign-ins classified as: at risk, confirmed compromised, confirmed safe, dismissed, remediated
- Real-time and aggregate risk levels
- Detection types triggered
- Conditional Access policies applied
- MFA details
- Device information
- Application information
- Location information

**Administrator Actions:**
- Confirm sign-in compromise
- Confirm sign-in safe

#### 3.4 Risk Detections Report

**Data Period:** Up to past 90 days (three months)

**Information Provided:**
- Each risk detection including type
- Other risks triggered simultaneously
- Sign-in attempt location

**Additional Features:**
- Link to detection in Microsoft Defender for Cloud Apps portal
- View additional logs and alerts

**AI Confirmation:**
- System detects false positives or remediated user risk
- Dismisses risk state
- "AI confirmed sign-in safe" detail surfaces

#### 3.5 Remediation Options

**All Active Risk Detections:**
- Contribute to user risk level calculation
- User risk level: Low, Medium, High
- Indicates probability of account compromise

**Remediation Methods:**

**1. Self-remediation with Risk Policy:**
- Users self-remediate with MFA and SSPR
- Unblock themselves when risk detected
- Must be previously registered for MFA and SSPR
- Detections considered closed after remediation

**2. Manual Password Reset:**
- Two options:
  - **Generate temporary password:** Immediate safe state, requires contacting user
  - **Require user to reset password:** Self-recovery, no help desk contact needed (requires MFA and SSPR registration)

**3. Dismiss User Risk:**
- Use when password reset isn't option (e.g., user deleted)
- All events closed
- User no longer at risk
- Doesn't affect existing password (not safe state)

**4. Close Individual Risk Detections Manually:**
- Lowers user risk level
- Done in response to investigation
- Actions:
  - Confirm user compromised
  - Dismiss user risk
  - Confirm sign-in safe
  - Confirm sign-in compromised

#### 3.6 Unblocking Users

**Unblock Based on User Risk:**
- Reset password
- Dismiss user risk
- Exclude user from policy
- Disable policy

**Unblock Based on Sign-in Risk:**
- Sign in from familiar location or device
- Exclude user from policy
- Disable policy

#### 3.7 PowerShell Management

**Microsoft Graph PowerShell SDK Preview:**
- Manage risk using PowerShell
- Preview modules and sample code: Azure GitHub repo

#### 3.8 Microsoft Graph API

**Three APIs:**

**riskDetection:**
- Query for list of user and sign-in linked risk detections
- Associated information about detection

**riskyUsers:**
- Query for information about users detected as risky

**signIn:**
- Query for Microsoft Entra ID sign-ins
- Specific properties related to risk state, detail, level

**API Setup Steps:**
1. Retrieve domain name
2. Create new app registration
3. Configure API permissions
4. Configure valid credential

**Sample Queries:**
- Get offline risk detections: `$filter=detectionTimingType eq 'offline'`
- Get users who passed MFA triggered by risky sign-ins: `$filter=riskDetail eq 'userPassedMFADrivenByRiskBasedPolicy'`

---

### 4. Implement Security for Workload Identities

#### 4.1 Workload Identity Protection

**Extension of Identity Protection:**
- Protect applications, service principals, Managed Identities
- Detect, investigate, remediate identity-based risks

**What is Workload Identity:**
- Identity allowing application or service principal access to resources
- Sometimes in context of user

**Differences from User Accounts:**
- Can't perform multifactor authentication
- Often no formal lifecycle process
- Need to store credentials or secrets somewhere
- Harder to manage, higher risk for compromise

#### 4.2 Requirements

**License:** Microsoft Entra ID Premium P2

**Required Roles:**
- Security administrator
- Security operator
- Security reader

**Portal Access:**
- Risky workload identities (preview) blade
- Workload identity detections tab in Risk detections blade

#### 4.3 Risk Detection Types

| Detection Name | Detection Type | Description |
|----------------|----------------|-------------|
| Microsoft Entra threat intelligence | Offline | Activity consistent with known attack patterns |
| Suspicious Sign-ins | Offline | Unusual sign-in properties or patterns for service principal |
| Unusual addition of credentials to OAuth app | Offline | Suspicious addition of privileged credentials (discovered by MDCA) |
| Admin confirmed account compromised | Offline | Admin selected 'Confirm compromised' in UI or API |
| Leaked Credentials (preview) | Offline | Valid credentials leaked (public code on GitHub or data breach) |

**Suspicious Sign-ins Details:**
- Learns baseline behavior in 2-60 days
- Fires if unfamiliar properties appear:
  - IP address / ASN
  - Target resource
  - User agent
  - Hosting/non-hosting IP change
  - IP country
  - Credential type

#### 4.4 Conditional Access Protection

**Capabilities:**
- Block access for specific accounts when marked "at risk"
- Applied to single-tenant service principals registered in tenant

**Out of Scope:**
- Third-party SaaS
- Multi-tenanted apps
- Managed identities

---

### 5. Explore Microsoft Defender for Identity

#### 5.1 Overview

**Former Names:**
- Azure Advanced Threat Protection (Azure ATP)

**Purpose:** Cloud-based security solution using on-premises Active Directory signals

**Capabilities:**
- Identify, detect, investigate advanced threats
- Detect compromised identities
- Investigate malicious insider actions

#### 5.2 Benefits for SecOp Analysts

**Enable Teams To:**
- Monitor users, entity behavior, activities with learning-based analytics
- Protect user identities and credentials stored in Active Directory
- Identify and investigate suspicious user activities
- Investigate advanced attacks throughout kill chain
- Provide clear incident information on simple timeline for fast triage

#### 5.3 Components

**Defender for Identity Portal:**
- Create Defender for Identity instance
- Display data from sensors
- Monitor, manage, investigate threats in network environment

**Defender for Identity Sensor:**
- Directly installed on servers:
  - **Domain controllers:** Direct monitoring of DC traffic (no dedicated server or port mirroring needed)
  - **AD FS:** Direct monitoring of network traffic and authentication events

**Defender for Identity Cloud Service:**
- Runs on Azure infrastructure
- Deployed in US, Europe, Asia
- Connected to Microsoft's intelligent security graph


---

## V. Safeguard Your Environment with Microsoft Defender for Identity

### 1. Introduction to Microsoft Defender for Identity

#### 1.1 Overview

**Microsoft Defender for Identity** is a cloud-based security solution leveraging on-premises Active Directory signals to:
- Identify, detect, investigate advanced threats
- Detect compromised identities
- Investigate malicious insider actions

#### 1.2 Key Benefits

**Monitor Users and Entity Behavior:**
- Monitors and analyzes user activities and information across network
- Analyzes permissions and group membership
- Creates behavioral baseline for each user
- Identifies anomalies with adaptive built-in intelligence
- Reveals suspicious activities, advanced threats, compromised users, insider threats
- Proprietary sensors monitor organizational domain controllers
- Provides comprehensive view of all user activities from every device

**Protect User Identities:**
- Provides insights on identity configurations
- Suggests security best-practices
- Security reports and user profile analytics
- Dramatically reduces organizational attack surface
- Visual Lateral Movement Paths show attacker's potential path
- Assists in preventing risks in advance
- Identifies users/devices authenticating with clear-text passwords

**Identify Suspicious Activities Across Kill Chain:**
- Attacks typically start with accessible entity (low-privileged user)
- Move laterally to valuable assets
- Large range of detections from reconnaissance to domain dominance

#### 1.3 Attack Detection Examples

**Reconnaissance Stage:**
- **LDAP Reconnaissance:** Attackers gain critical domain information
  - Maps domain structure
  - Identifies privileged accounts
  - Triggered by suspicious LDAP enumeration queries or queries targeting sensitive groups

**Compromised Credentials:**
- **Brute Force Attacks:** Multiple authentication attempts
  - Multiple passwords on different accounts
  - One password on many accounts (password spray)
  - Detection when multiple authentication failures occur (Kerberos, NTLM, password spray)

**Lateral Movement:**
- **Pass-the-Ticket:** Steal Kerberos ticket from one computer
  - Use to gain access to another computer
  - Detection: Kerberos ticket used on two or more different computers

**Domain Dominance:**
- **DCShadow Attack:** Change directory objects using malicious replication
  - Performed from any machine creating rogue domain controller
  - Alert triggered when machine tries to register as rogue DC

---

### 2. Configure Microsoft Defender for Identity Sensors

#### 2.1 Setup Steps

**High-Level Configuration:**
1. Create instance on Microsoft Defender for Identity management portal
2. Specify on-premises AD service account in portal
3. Download and install sensor package
4. Install sensor on all domain controllers
5. Integrate VPN solution (optional)
6. Exclude sensitive accounts
7. Configure required permissions for SAM-R calls
8. Configure integration with Microsoft Defender for Cloud Apps
9. Configure integration with Microsoft Defender XDR (optional)

#### 2.2 Sensor Architecture

**Installation:**
- Installed directly on domain controllers
- Accesses event logs directly from DC
- Parses logs and network traffic
- Sends only parsed information to cloud service (percentage of logs)

**Core Functionality:**
- Capture and inspect DC network traffic (local traffic)
- Receive Windows events directly from DCs
- Receive RADIUS accounting information from VPN provider
- Retrieve data about users and computers from AD domain
- Perform resolution of network entities (users, groups, computers)
- Transfer relevant data to cloud service

#### 2.3 Sensor Requirements

**Operating System Support:**
- Windows Server 2008 R2 SP1 (not Server Core)
- Windows Server 2012
- Windows Server 2012 R2
- Windows Server 2016 (including Core, not Nano Server)
- Windows Server 2019 (including Core, not Nano Server)
- KB4487044 required for Server 2019
- Can be read-only domain controller (RODC)

**Hardware Requirements:**
- 10 GB disk space (binaries, logs, performance logs)
- Minimum 2 cores
- Minimum 6 GB RAM
- Power option set to high performance
- Can be deployed on various DC loads and sizes

**Virtual Machine Considerations:**
- Dynamic memory not supported
- Memory ballooning feature not supported

#### 2.4 Sensor Installation

**Installation Process:**
1. Download and extract sensor file
2. Run Microsoft Defender for Identity sensor setup.exe
3. Follow setup wizard
4. Select language and click Next
5. Wizard auto-detects if DC or dedicated server
6. Configure installation path (default: %programfiles%\Microsoft Defender for Identity sensor)
7. Enter access key from portal
8. Click Install

**Post-Installation Configuration:**
1. Launch browser and sign into portal
2. Go to Configuration → System → Sensors
3. Click on sensor to configure
4. Enter description (optional)
5. Configure Domain Controllers (FQDN) - required for standalone sensor
6. Configure Capture Network adapters
7. Click Save

**Domain Controller List Requirements:**
- All DCs whose traffic monitored via port mirroring must be listed
- At least one DC should be global catalog
- Enables resolving computer and user objects in other domains

**Network Adapter Configuration:**
- For sensors: All network adapters for communication with other computers
- For standalone sensor: Network adapters configured as destination mirror port

---

### 3. Review Compromised Accounts or Data

#### 3.1 Security Alerts Overview

**Microsoft Defender for Identity Security Alerts:**
- Explain suspicious activities detected by sensors
- Identify actors and computers involved in each threat
- Alert evidence contains direct links to involved users and computers

**Alert Categories (Cyber-Attack Kill Chain Phases):**
- Reconnaissance phase alerts
- Compromised credential phase alerts
- Lateral movement phase alerts
- Domain dominance phase alerts
- Exfiltration phase alerts

**Each Alert Includes:**
- Alert title (official Microsoft Defender for Identity name)
- Description (brief explanation)
- Evidence (additional relevant information and related data)
- Excel download (detailed report for analysis)

**Viewing Alerts:**
- Alerts viewable within Microsoft Defender for Cloud Apps

#### 3.2 Investigation Scenario Example

**Attack Timeline:**

**Step 1: User and IP Address Reconnaissance (SMB)**
- User learned IP addresses of two accounts
- Enumerated SMB sessions on domain controller
- Activity log shows command that was run

**Step 2: Overpass-the-Hash Attack**
- Alert points to overpass-the-hash attack
- User account part of lateral movement path
- Evidence shows attack progression

**Step 3: Identity Theft (Pass-the-Ticket)**
- Theft of ticket from domain administrator to infiltrated PC
- Defender for Cloud Apps shows which resources accessed using stolen tickets

**Step 4: Remote Command Execution**
- Stolen credentials used to run remote command on DC
- Activity Log shows command created new user in Administrators group

**Attack Summary:**
1. Infiltrated a PC
2. Determined IP addresses of other users' PCs (including domain admin)
3. Performed overpass-the-hash attack (stole NTLM hash)
4. Gained access to domain administrator's PC
5. Stole identity of domain administrator
6. Accessed domain controller
7. Created new user account with domain admin permissions

**Result:** Attacker effectively compromised environment with domain admin permissions, can perform attacks like Skeleton Key attack

---

### 4. Integrate with Other Microsoft Tools

#### 4.1 Microsoft Defender for Identity Cloud Service

**Infrastructure:**
- Runs on Azure infrastructure
- Deployed in US, Europe, Asia
- Connected to Microsoft's intelligent security graph

#### 4.2 Integration with Microsoft Defender for Cloud Apps

**Benefits of Integration:**
- See on-premises activities for all users
- Advanced insights on users combining:
  - Alerts across cloud and on-premises
  - Suspicious activities across environments
- Microsoft Defender for Identity policies appear in Defender for Cloud Apps policies page
- Unified view of threats

**Capabilities:**
- Microsoft Defender for Identity reporting within Defender for Cloud Apps
- Single interface for monitoring
- Part of Microsoft Defender XDR monitoring strategy

#### 4.3 Integration with Microsoft Defender for Endpoint

**Complete Threat Protection Solution:**
- Microsoft Defender for Identity: Monitors traffic on domain controllers
- Microsoft Defender for Endpoint: Monitors endpoints
- Together: Single interface to protect environment

**Integration Benefits:**
- Select endpoint to view Microsoft Defender for Identity alerts in Defender for Endpoint portal
- Insight into system running processes
- Locate event sequences leading to network compromise

**Investigation Example:**
- High severity alerts pointing to malware installation
- Clicking alert verifies Pass-The-Hash (PtH) attack using Mimikatz
- Actions show timeline of events surrounding credential theft
- Complete picture of attack chain

**Unified Experience:**
- Single pane of glass for entire environment
- Correlate on-premises and endpoint activities
- Streamlined investigation and response


---

## VI. Secure Your Cloud Apps and Services with Microsoft Defender for Cloud Apps

### 1. Understand the Defender for Cloud Apps Framework

#### 1.1 Cloud Access Security Broker (CASB)

**Gartner Definition:**
- Security policy enforcement points between cloud service consumers and providers
- Combine and interject enterprise security policies
- Consolidate multiple types of security policy enforcement

**CASB Analogy:**
- Intermediaries between users and cloud services
- Like firewalls for corporate networks
- Apply monitoring and security controls over users and data

**Microsoft Defender for Cloud Apps:**
- CASB helping identify and combat cyberthreats
- Across Microsoft and third-party cloud services
- Integrates with Microsoft solutions
- Provides: simple deployment, centralized management, innovative automation

#### 1.2 Information Flow

**Defender for Cloud Apps Functions as Intermediary:**
- Between apps, data, and users
- Monitors and controls all cloud service access
- Applies security policies consistently

#### 1.3 Framework Elements

**Four Key Elements:**

**1. Discover and Control Shadow IT:**
- Identify cloud apps, IaaS, PaaS services used by organization
- Average: 1,000+ unknown apps (Shadow IT)
- Understanding apps helps control risk

**2. Protect Sensitive Information Anywhere in Cloud:**
- Understand, classify, protect sensitive information at rest
- Data Loss Prevention (DLP) capabilities
- Cover various data leak points in organizations
- Avoid accidental data exposure

**3. Protect Against Cyberthreats and Anomalies:**
- Detect unusual behavior across apps and users
- Identify potential ransomware
- Multiple detection methods:
  - Anomaly detection
  - User Entity Behavioral Analytics (UEBA)
  - Rule-based activity detections
- Shows who is using apps and how they're using them

**4. Assess Cloud App Compliance:**
- Assess if apps comply with regulations and industry standards
- Compare apps and usage against compliance requirements
- Prevent data leaks to noncompliant apps
- Limit access to regulated data

---

### 2. Explore Cloud Apps with Cloud Discovery

#### 2.1 Cloud Discovery Purpose

**What Cloud Discovery Shows:**
- What's happening in network
- Expected cloud apps and unexpected ones
- Signs of Shadow IT
- Nonsanctioned apps (non-compliant with security/compliance policies)

**Analysis Capability:**
- Analyzes traffic logs against catalog of 16,000+ cloud apps
- Ranks and scores each app based on 80+ risk factors
- Provides visibility into cloud use, Shadow IT, and risks

#### 2.2 Cloud Discovery Dashboard

**Dashboard Overview:**
- At-a-glance view of app usage
- Open alerts
- Risk levels of apps
- Top app users
- App Headquarters map (where apps come from)
- Filterable data for specific views

#### 2.3 Review Process

**Step-by-Step Dashboard Review:**

**1. High-level Usage Overview:**
- Overall cloud app use
- Top users
- Source IP addresses
- Identify users using cloud apps most
- Pay attention to these users going forward

**2. App Category Analysis:**
- Which category of apps organization uses most
- How much usage is in Sanctioned apps

**3. Discovered Apps Tab:**
- All apps in specific category
- Deeper dive into app usage

**4. App Risk Overview:**
- Risk score for discovered apps
- Each app assessed against risk factors:
  - Security and compliance
  - Regulatory measures
- Risk score: 1 to 10

**5. App Headquarters Map:**
- View where discovered apps are located
- Based on their headquarters

#### 2.4 Managing Risky Apps

**Flag as Unsanctioned:**
- If app poses risk, flag it as Unsanctioned in Discovered apps pane

**Automatic Blocking:**
- With Microsoft Defender for Endpoint: Unsanctioned app automatically blocked
- Without threat protection solution: Run script against data source to block app
- Users see notification when trying to access blocked app

---

### 3. Protect with Conditional Access App Control

#### 3.1 Real-time Protection

**Purpose:**
- Cloud Discovery shows what happened after the fact
- Primary goal: Stop breaches and leaks in real time
- Enable BYOD while protecting organization

**Integration:**
- Integrates with identity providers (IdPs)
- Access and session controls through Conditional Access App Control
- With Microsoft Entra ID: Controls integrated directly into Defender for Cloud Apps

#### 3.2 Capabilities

**Monitor and Control:**
- User app access in real time
- User sessions in real time
- Integrates with Microsoft Entra Conditional Access

**Easy Configuration:**
- Selectively enforce access and session controls
- Based on any condition in Conditional Access
- Conditions define: who, what, where

**Built-in Policies:**
- Microsoft Entra ID includes built-in policies
- Configure for easy deployment
- After configuring conditions in Entra ID:
  - Select Session under Access controls
  - Click "Use Conditional Access App Control"
- Custom controls defined in Defender for Cloud Apps portal

#### 3.3 Access and Session Policies

**Policy Capabilities:**

**Prevent Data Exfiltration:**
- Block download, cut, copy, print of sensitive documents
- Example: On unmanaged devices

**Protect on Download:**
- Instead of blocking download of sensitive documents
- Require labeling and protection with Azure Information Protection
- Ensures document protected and user access restricted

**Prevent Upload of Unlabeled Files:**
- Enforce use of labeling
- Ensure file has right label before upload
- Block file upload until content classified

**Monitor User Sessions for Compliance:**
- Monitor risky users when sign in to apps
- Log actions from within session
- Investigate and analyze user behavior
- Understand where and when to apply session policies

**Block Access:**
- Block for specific apps and users
- Based on several risk factors
- Example: Block user using client certificate as device management

**Block Custom Activities:**
- Apps have unique scenarios that carry risk
- Example: Sending messages with sensitive content (Microsoft Teams, Slack)
- Scan messages for sensitive content
- Block in real time

#### 3.4 Example: Block Sensitive Content in Teams

**Scenario:** Create session policy in Microsoft Teams blocking IM messages with sensitive content

**Prerequisites:**
- Previously created Conditional Access policy
- Set "Use custom controls" with "Use Conditional Access App Control"

**Configuration Steps:**
1. Create new session policy in Microsoft Defender for Cloud Apps
2. Use template: "Block sending of messages based on real-time content inspection"
3. Under Activity source: Select "Send Teams message" as application
4. Enable Content Inspection
5. Define sensitive information as:
   - Matching preset expression
   - Custom expression
   - Regular expression
6. Under Actions: Select "Block" to block message
7. Create alerts to notify administrators

**Result:** When user tries to send sensitive message in Teams, they see notification

---

### 4. Classify and Protect Sensitive Information

#### 4.1 Information Protection Overview

**Why Information Protection:**
- Employees may accidentally upload file to wrong place
- Send confidential information to wrong person
- Lost or wrongfully exposed information has serious consequences:
  - Legal
  - Financial
  - Reputational

**Microsoft Defender for Cloud Apps:**
- Natively integrates with Azure Information Protection
- Cloud-based service for classifying and protecting files/emails

**Requirement:** Enable app connector for Microsoft 365

#### 4.2 Information Protection Phases

**Phase 1: Discover Data**

**Connect Apps:**
- Ensure apps connected to Microsoft Defender for Cloud Apps
- Can scan for and classify data
- Apply policies and controls

**Two Connection Methods:**
1. Use app connector
2. Use Conditional Access App Control

**Phase 2: Classify Sensitive Information**

**Decide What's Sensitive:**
- Context of organization matters
- Microsoft Defender for Cloud Apps includes:
  - 100+ predefined sensitive information types
  - Default labels in Azure Information Protection

**Sensitive Information Types:**
- Handle passport numbers, national/regional identity numbers
- Define how to process specific data types

**Default Labels in Azure Information Protection:**

| Label | Description |
|-------|-------------|
| Personal | Data for personal, non-business use only |
| Public | Data for public consumption (marketing, blog posts) |
| General | Can't be shared publicly, but shareable with external partners (timelines, org charts) |
| Confidential | Could damage organization if shared with unauthorized people (sales data, forecasts) |
| Highly Confidential | Very sensitive data causing serious damage if shared (customer details, passwords, source code) |

**Enable Integration:**
- In Settings pane: Select "Automatically scan new files for Azure Information Protection classification labels"

**Phase 3: Protect Data**

**File Policies:**
- Scan content of files in real time
- Scan data at rest
- Apply governance actions automatically

**Automatic Actions:**
- Trigger alerts and email notifications
- Change sharing access for files
- Quarantine files
- Remove file or folder permissions
- Move files to trash folder

**Create File Policy:**

**Basic Settings:**
| Field | Description |
|-------|-------------|
| Policy severity | How important policy is, whether to trigger notification |
| Category | Informative label (default: DLP for File policies) |
| Create filter | Decide which apps trigger policy (narrow as possible to avoid false positives) |

**Scope Settings:**
| Field | Options |
|-------|---------|
| Apply to (1st) | All files excluding selected folders OR Selected folders (Box, SharePoint, OneDrive, Dropbox) |
| Apply to (2nd) | All file owners OR File owners from selected user groups OR All file owners excluding selected groups |

**Inspection Method:**
- Built-in DLP
- Data Classification Services (DCS) - Microsoft recommends DCS for unified labeling experience

**Governance:**
- Select governance actions to perform when match detected

**Phase 4: Monitor and Report**

**Dashboard Monitoring:**
- Check dashboard for alerts
- Monitor overall environment health

**Review File-Related Alerts:**
- Go to Alerts pane
- Select DLP in Category field

**Alert Actions:**
- Investigate to understand what triggered alert
- Dismiss alerts that can be ignored
- Export alerts to CSV for further analysis

---

### 5. Detect Threats

#### 5.1 Anomaly Detection Overview

**Purpose:** Protect against cyberthreats and anomalies (framework element)

**Built-in Capabilities:**
- Out-of-the-box anomaly detection policies
- Utilize User and Entity Behavioral Analytics (UEBA)
- Machine learning for advanced threat detection
- Across cloud environment

**Important Note:** Anomaly detections are nondeterministic by nature (only trigger when behavior deviates from norm)

#### 5.2 Learning Period

**Initial 7 Days:**
- Microsoft Defender for Cloud Apps learns environment
- Looks at:
  - IP addresses, devices, locations users access
  - Which apps and services used
  - Calculates risk score of activities
- Contributes to baseline for comparison

**Machine Learning:**
- Profile users
- Recognize normal sign-in patterns
- Reduce false positive alerts

#### 5.3 Risk Evaluation

**Anomaly Detection Process:**
- Scan user activity
- Evaluate for risk
- Look at 30+ different indicators

**Risk Factors Grouped Into:**
- Risky IP address
- Login failures
- Admin activity
- Inactive accounts
- Location
- Impossible travel
- Device and user agent
- Activity rate

**Alert Triggering:**
- When something different from baseline occurs
- Different from user's regular activity

#### 5.4 Popular Anomaly Detection Policies

**Impossible Travel:**
- Activities from same user in different locations
- Time period shorter than expected travel time between locations

**Activity from Infrequent Country:**
- Activity from location not recently visited
- Never visited by user or any user in organization

**Malware Detection:**
- Scans files in cloud apps
- Runs suspicious files through Microsoft threat intelligence engine
- Determines if associated with known malware

**Ransomware Activity:**
- File uploads to cloud that might be infected with ransomware

**Activity from Suspicious IP Addresses:**
- Activity from IP identified as risky by Microsoft Threat Intelligence

**Suspicious Inbox Forwarding:**
- Detects suspicious inbox forwarding rules on user's inbox

**Unusual Multiple File Download Activities:**
- Multiple file download activities in single session
- Compared to baseline learned
- Could indicate attempted breach

**Unusual Administrative Activities:**
- Multiple administrative activities in single session
- Compared to baseline
- Could indicate attempted breach

#### 5.5 Configure Discovery Anomaly Detection Policy

**Policy Purpose:**
- Look for unusual increases in cloud application usage
- Examines:
  - Downloaded data increases
  - Uploaded data increases
  - Transactions increases
  - User increases
- Each increase compared to baseline
- Most extreme increases trigger security alerts

**Configuration Options:**
- Application filter
- Selected data views
- Selected start date
- Set sensitivity (how many alerts policy should trigger)

#### 5.6 Fine-tune Policies

**Why Fine-tune:**
- Anomaly detections susceptible to false positives
- Too many false positives lead to alert fatigue
- Risk missing important alerts in noise

**Fine-tuning Options:**
- Include different levels of suppression
- Address scenarios triggering false positives (e.g., VPN activities)
- Determine sensitivity according to coverage needed
- Higher sensitivity uses stricter detection logic algorithms

**Suppression Types:**

| Suppression Type | Description |
|-----------------|-------------|
| System | Built-in detections always suppressed |
| Tenant | Common activities based on previous tenant activity (e.g., ISP previously alerted) |
| User | Common activities based on specific user's previous activity (e.g., commonly used location) |

**Sensitivity Levels:**

| Sensitivity Level | Suppression Types Affected |
|------------------|----------------------------|
| Low | System, Tenant, and User |
| Medium | System and User |
| High | System Only |

**Additional Configuration:**
- Whether alerts for activity from infrequent country/region should analyze:
  - Failed and successful logins OR
  - Successful logins only
- Same for:
  - Anonymous IP addresses
  - Suspicious IP addresses
  - Impossible travel

#### 5.7 Scope Anomaly Detection Policy

**Purpose:** Apply policy only to specific users and groups

**Example Use Case:**
- Activity from infrequent country/region detection
- Ignore specific user who travels frequently

**Scoping Process:**
1. Sign in to Microsoft Defender Portal
2. Expand Cloud apps section
3. Select Policies → Policy management
4. Set Type filter to "Anomaly detection policy"
5. Select policy to scope
6. Under Scope: Change from "All users and groups" to "Specific users and groups"
7. Select Include: Users/groups for whom policy applies
8. Select Exclude: Users for whom policy won't apply (even if members of included groups)
9. Select Update to commit changes

**Result:** Only scoped users/groups trigger alerts for this policy

