# SC-200: Mitigate threats using Microsoft Defender for Endpoint

## I. Protect against threats with Microsoft Defender for Endpoint

### 1. Threat and Vulnerability Management
**Core Capabilities**:
- Real-time vulnerability discovery without agents or periodic scans
- Prioritizes issues based on threat landscape, detections, sensitive data, and business context
- Built-in remediation through Microsoft Intune and Endpoint Manager integration
- Creates security tasks/tickets automatically

**Solutions Provided**:
- Real-time EDR insights correlated with endpoint vulnerabilities
- Vulnerability assessment data in context of exposure discovery
- Built-in remediation processes

### 2. Attack Surface Reduction Components

| Component | Description |
|-----------|-------------|
| **Attack Surface Reduction Rules** | Intelligent rules to stop Office, script, and mail-based malware vectors |
| **Hardware-based Isolation** | Protects system integrity during startup and runtime |
| **Application Control** | Applications must earn trust to run (zero-trust model) |
| **Exploit Protection** | Applies mitigation techniques to apps organization-wide |
| **Network Protection** | Extends SmartScreen protection to network traffic |
| **Web Protection** | Secures against web threats and regulates unwanted content |
| **Controlled Folder Access** | Prevents ransomware from modifying files in key system folders |
| **Device Control** | Monitors and controls removable storage and USB drives |

### 3. Next Generation Protection
**Microsoft Defender Antivirus Features**:
- Cloud-delivered protection for instant threat detection
- Always-on scanning with behavior monitoring and heuristics
- Dedicated protection updates via machine learning

**Network Configuration Requirements**:
- Sensor uses WinHTTP (independent of WinINet)
- Runs in system context using LocalSystem account
- Auto-discovery methods: Transparent proxy, WPAD
- No special configuration needed if transparent proxy/WPAD implemented

### 4. Endpoint Detection and Response (EDR)
**Key Features**:
- Near real-time advanced attack detection
- Alerts aggregated into incidents by attack technique
- 6-month behavioral telemetry retention
- Continuous collection: process info, network activities, kernel optics, user sign-ins, registry/file changes

**Security Operations Dashboard**:
- High-level overview of detection locations
- Highlights where response actions needed
- Incident investigation capabilities

### 5. Automated Investigation and Remediation
**Benefits**:
- Uses inspection algorithms and playbooks
- Automatic remediation of breaches
- Significantly reduces alert volume
- Enables SOC focus on sophisticated threats

**Investigation Process**:
- Malware detection triggers automated investigation
- System examines alerts and takes immediate action
- Resolves breaches without manual intervention

### 6. Advanced Hunting
**Query Tool Features**:
- Proactive threat hunting across organization
- Uses Kusto Query Language (KQL)
- Custom detection rule creation
- Flexible data access for known and potential threats

**Supported KQL Operators**:
```
where       - Filter tables by predicate
summarize   - Aggregate input table content
join        - Merge two tables
count       - Count records in input set
top/limit   - Return first N records
project     - Select/rename/drop columns
extend      - Create calculated columns
makeset()   - Return JSON array of distinct values
find        - Find rows matching predicate
```

**Query Best Practices**:
1. Apply time filters first (highly optimized)
2. Use `has` keyword over `contains` for full tokens
3. Search specific columns instead of full text
4. When joining tables, put smaller table first (left)
5. Project only needed columns from both sides of join

**Example Query**:
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "powershell_ise.exe", "pwsh.exe")
| where ProcessCommandLine has_any("WebClient", "DownloadFile", "DownloadData", "DownloadString")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| top 100 by Timestamp
```

---

## II. Deploy the Microsoft Defender for Endpoint Environment

### 1. Create Your Environment

**Initial Setup Preferences** (Security Administrator required):
- **Data Storage Location**: US, EU, or UK (cannot change after setup)
- **Data Retention**: Default 6 months
- **Preview Features**: Default ON (can change later)

**Access Portal Settings**:
1. Go to https://security.microsoft.com
2. Select Settings → Endpoints

**Network Configuration**:
- Not required if endpoints don't use proxy
- Sensor uses WinHTTP to communicate with service
- Runs in system context with LocalSystem account
- Auto-discovery via Transparent proxy or WPAD

### 2. Operating System Compatibility

**Windows Support**:
- Windows 7 SP1 Enterprise/Pro (requires ESU)
- Windows 8.1 Enterprise/Pro
- Windows 10/11 (Enterprise, Education, Pro, Pro Education)
- Windows 10 Enterprise LTSC 2016+, IoT
- Windows Server 2008 R2 SP1+ (requires ESU for 2008)
- Windows Server 2012 R2, 2016, 2019, 2022
- Windows Virtual Desktop

**macOS Support**:
- Three latest released versions
- Capabilities: Antivirus, EDR, vulnerability management
- Deployment: Microsoft Endpoint Manager, Jamf
- Updates: Microsoft AutoUpdate

**Linux Support**:
- RHEL 7.2+, CentOS 7.2+, Ubuntu 16 LTS+, SLES 12+, Debian 9+, Oracle Linux 7.2
- Capabilities: Antivirus, EDR, vulnerability management
- Full CLI for configuration and management
- Deployment: Puppet, Ansible, existing config management tools

**Android Support**:
- Android 6.0 and higher
- Android Enterprise (Work Profile) and Device Administrator modes
- Features: Web protection, anti-phishing, unsafe connection blocking, custom indicators, malware/PUA scanning
- Integration with Microsoft Endpoint Manager and Conditional Access

**iOS Support**:
- iOS 11.0 and higher
- Enrolled/unenrolled devices supported
- Supervised/unsupervised enrolled devices
- Features: Web protection, anti-phishing, unsafe connection blocking, custom indicators, jailbreak detection

### 3. Onboard Devices

**Device Discovery Configuration**:
1. Access Microsoft Defender XDR portal
2. Navigate: Settings → Device discovery
3. Select: **Standard discovery (recommended)**

**Onboarding Process**:
1. Verify device meets minimum requirements
2. Go to Settings → Endpoints → Device Management → Onboarding
3. Select operating system from dropdown
4. Follow configuration steps provided
5. Run detection test to verify reporting

**Windows Deployment Options**:
- Group Policy
- Microsoft Endpoint Configuration Manager
- Mobile Device Management (Intune)
- Local script (up to 10 devices)
- VDI onboarding script (non-persistent devices)
- System Center Configuration Manager 2012/2012 R2/1511/1602

**Offboarding Devices**:
- Navigate: Settings → Endpoints → Device Management → Offboarding
- Select OS and follow directions

### 4. Manage Access with RBAC

**Role-Based Access Control Features**:
- Create custom roles and groups in security operations team
- Grant appropriate portal access
- Precise control over what users can see and do

**Important Notes**:
- New customers (from Feb 16, 2025): Only Unified RBAC (URBAC) access
- Existing customers: Keep current roles and permissions
- Use roles with fewest permissions (principle of least privilege)
- Global Administrator: Highly privileged, use only for emergencies

**RBAC Framework Controls**:
1. **Control Actions**: Create custom roles with granular capability access
2. **Control Visibility**: Create device groups by criteria (names, tags, domains), grant role access via Azure AD groups

**Default Access Roles**:
- **Full Access**: Security Administrator or Global Administrator in Azure AD
- **Read-Only**: Security Reader role in Azure AD
- **Global Administrator**: Unrestricted access to all devices regardless of device group

### 5. Create and Manage Roles

**Steps to Create Roles**:
1. Access portal with Security administrator role
2. Navigate: Settings → Endpoints → Permissions → Roles
3. Select "Turn on roles"
4. Select "+ Add item"
5. Enter role name, description, permissions
6. Select Next to assign to Azure AD Security group
7. Filter and select Azure AD group
8. Select Save

**Permission Categories**:

**View Data**:
- Security operations: View all security operations data
- Threat and vulnerability management: View TVM data

**Active Remediation Actions**:
- Security operations: Response actions, approve/dismiss remediation, manage allow/block lists
- TVM Exception handling: Create and manage exceptions
- TVM Remediation handling: Submit requests, create tickets, manage activities
- TVM Application handling: Block/unblock vulnerable applications
- TVM Security baselines: Manage assessment profiles

**Additional Permissions**:
- Alert investigation: Manage alerts, start investigations, run scans, collect packages, manage tags
- Manage security settings: Configure suppression, folder exclusions, onboard/offboard devices, email notifications
- Manage endpoint security in Intune: Full Endpoint Security access
- Live response capabilities: Basic commands (read-only) or Advanced commands (file download/upload, script execution)

### 6. Configure Device Groups

**Purpose**:
- Limit access to alerts and data
- Configure different auto-remediation settings
- Assign remediation levels for automated investigations
- Filter devices in investigations

**Device Group Creation**:
1. Navigate: Settings → Endpoints → Permissions → Device groups
2. Select "+ Add device group"
3. Enter group name and remediation settings
4. Specify matching rule (device name, domain, tags, OS platform)
5. Preview devices matched by rule
6. Select User access tab
7. Assign Azure AD user groups with RBAC roles
8. Select Close

**Device Group Features**:
- Set automated remediation level per group
- Devices matched to highest ranked group only
- Rank groups relative to each other
- RBAC-based access control

### 7. Configure Advanced Features

**Access**: Settings → Endpoints → Advanced features

**Key Advanced Features**:

| Feature | Description |
|---------|-------------|
| **Automated Investigation** | Enables automated investigation and remediation |
| **Live Response** | Start live response sessions (requires Automated investigation ON) |
| **Live Response for Servers** | Live response sessions on servers |
| **Live Response Unsigned Scripts** | Run unsigned scripts in live response |
| **Always Remediate PUA** | Remediate potentially unwanted apps across all devices |
| **Restrict Correlation** | Limit alert correlations to scoped device groups |
| **EDR in Block Mode** | Block malicious artifacts even when Defender AV in passive mode |
| **Autoresolve Remediated Alerts** | Auto-resolve alerts with "No threats found" or "Remediated" status |
| **Allow or Block File** | Block potentially malicious files network-wide |
| **Custom Network Indicators** | Create indicators for IPs, domains, URLs (allow/block) |
| **Tamper Protection** | Locks Defender AV, prevents security settings changes |
| **Show User Details** | Display user info from Azure AD (picture, name, title, department) |

**Integration Features**:
- **Skype for Business**: Communicate with users (Skype, email, phone)
- **Microsoft Defender for Identity**: Pivot to identity security product
- **Office 365 Threat Intelligence**: Incorporate O365 data (requires E5 license)
- **Microsoft Threat Experts**: Targeted attack notifications
- **Microsoft Defender for Cloud Apps**: Forward signals for cloud app visibility
- **Web Content Filtering**: Block unwanted content, track web activity
- **Microsoft Purview Compliance**: Share endpoint alerts for insider risk management
- **Microsoft Intune**: Device risk-based conditional access
- **Device Discovery**: Find unmanaged devices on corporate network
- **Preview Features**: Access upcoming features
- **Download Quarantined Files**: Backup files for download from quarantine

**Requirements for Integrations**:
- Appropriate licenses (E5, Threat Intelligence add-on, EMS E3, Windows E5)
- Active environments (Intune-managed Windows devices Azure AD joined)
- Cloud-based protection enabled
- Network protection in block mode

---

## III. Implement Windows Security Enhancements

### 1. Attack Surface Reduction Overview

**Definition**: Hardening places where threats are likely to attack

**Components**:

| Component | Description | Requirements |
|-----------|-------------|--------------|
| **Attack Surface Reduction Rules** | Intelligent rules to stop malware vectors | Microsoft Defender Antivirus |
| **Hardware-based Isolation** | System integrity protection and validation | - |
| **Application Control** | Applications must earn trust to run | - |
| **Exploit Protection** | Protect OS and apps from exploits | Works with 3rd party AV |
| **Network Protection** | Extend protection to network traffic | Microsoft Defender Antivirus |
| **Web Protection** | Secure devices against web threats | - |
| **Controlled Folder Access** | Prevent ransomware file changes | Microsoft Defender Antivirus |
| **Device Control** | Monitor and control removable storage | - |

### 2. Attack Surface Reduction Rules

**Rule Settings**:
- **Not configured**: Disable rule
- **Block**: Enable rule
- **Audit**: Evaluate impact without blocking
- **Warn**: Enable but allow user bypass

**Available Rules**:
1. Block executable content from email client and webmail
2. Block Office applications from creating child processes
3. Block Office applications from creating executable content
4. Block Office applications from injecting code into other processes
5. Block JavaScript/VBScript from launching downloaded executables
6. Block execution of potentially obfuscated scripts
7. Block Win32 API calls from Office macros
8. Use advanced protection against ransomware
9. Block credential stealing from lsass.exe
10. Block process creations from PSExec and WMI commands
11. Block untrusted/unsigned processes from USB
12. Block executables not meeting prevalence, age, or trusted list criteria
13. Block Office communication apps from creating child processes
14. Block Adobe Reader from creating child processes
15. Block persistence through WMI event subscription

**Exclusions**:
- Specify individual files or folders
- Use folder paths or fully qualified resource names
- Applied only when excluded app/service starts
- Cannot specify which rules exclusions apply to

**Audit Mode**:
- Evaluate impact before deployment
- Monitor audit data and add exclusions for line-of-business apps
- Deploy without impacting productivity

**Notifications**:
- Displayed on device when rule triggered
- Customizable with company details and contact info
- Appears in Microsoft Defender portal

### 3. Configuration Methods

**Supported Platforms**:
- Windows 10 Pro/Enterprise version 1709+
- Windows 11
- Windows Server 1803+, 2016, 2019, 2022
- Windows Server 2012 R2

**Configuration Tools**:

**1. Microsoft Intune - Device Configuration**:
```
Device configuration → Profiles → Endpoint protection
→ Windows Defender Exploit Guard → Attack Surface Reduction
→ Select settings for each rule
→ Add exclusions (CSV format: C:\folder, %ProgramFiles%\folder\file, C:\path)
```

**2. Intune - Endpoint Security**:
```
Endpoint Security → Attack surface reduction → Create Policy
→ Attack surface reduction rules
→ Configure settings per rule
→ Add folders, apps, exclusions
```

**3. Mobile Device Management (MDM)**:
```
CSP: ./Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules
Value format: GUID=setting|GUID=setting
Settings: 0=Disable, 1=Block, 2=Audit

Example OMA-URI:
./Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules
Value: 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=2|3B576869-A4EC-4529-8536-B80A7769E899=1

Exclusions CSP:
./Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionOnlyExclusions
Value: c:\path|e:\path|c:\allowed.exe
```

**4. Microsoft Endpoint Configuration Manager**:
```
Assets and Compliance → Endpoint Protection → Windows Defender Exploit Guard
→ Create Exploit Guard Policy
→ Select Attack Surface Reduction
→ Choose block/audit actions
```

**5. Group Policy**:
```
Computer configuration → Administrative templates
→ Windows components → Microsoft Defender Antivirus
→ Windows Defender Exploit Guard → Attack surface reduction
→ Configure Attack surface reduction rules → Enabled
→ Show options: Enter Rule ID (Value name), State (Value)
States: 0=Disable, 1=Block, 2=Audit

Exclusions:
→ Exclude files and paths → Enabled
→ Show: Enter file/folder (Value name), 0 (Value)
```

**6. PowerShell**:
```powershell
# Enable rule
Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Enabled

# Audit mode
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions AuditMode

# Disable rule
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Disabled

# Multiple rules
Set-MpPreference -AttackSurfaceReductionRules_Ids <rule1>,<rule2>,<rule3>,<rule4> -AttackSurfaceReductionRules_Actions Enabled,Enabled,Disabled,AuditMode

# Add to existing rules (not overwrite)
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Enabled

# View current rules
Get-MpPreference

# Add exclusions
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "<fully qualified path>"
```

**Event Logging**:
- Location: Applications and Services Logs → Microsoft → Windows
- View all ASR events in Windows Event Viewer

---

## IV. Perform Device Investigations

### 1. Device Inventory List

**Overview**:
- Shows devices where alerts generated
- Default: Devices with alerts from last 30 days
- Access from navigation menu or investigation pages (Incidents, Alerts)

**Gradual Population**:
- Populated during onboarding as devices report sensor data
- Download complete endpoint list as CSV for offline analysis

**Key Metrics**:

**Risk Level**:
- Overall risk assessment based on active alerts
- Factors: Alert types and severity
- Lowering actions: Resolve alerts, approve remediation, suppress alerts

**Exposure Level**:
- Current exposure based on pending security recommendations
- Levels: Low, Medium, High
- Low exposure = less vulnerable to exploitation

**"No data available" reasons**:
- Device stopped reporting for 30+ days (inactive)
- Unsupported OS
- Stale agent

**Health State**:
- **Active**: Actively reporting sensor data
- **Inactive**: No signals for 7+ days
- **Misconfigured**: Impaired communications or unable to send sensor data
  - Sub-types: No sensor data, Impaired communications

**Antivirus Status** (Windows 10 only):
- **Disabled**: Virus & threat protection turned off
- **Not reporting**: Not reporting status
- **Not updated**: Not up to date

### 2. Investigate Device

**Access Points**:
- Devices list
- Alerts queue
- Security operations dashboard
- Individual alert/file/IP/domain details view

**Device Page Components**:

**1. Device Details Section**:
- Domain, OS, health state information
- Investigation package download link (if available)

**2. Response Actions**:
- Manage tags
- Isolate device
- Restrict app execution
- Run antivirus scan
- Collect investigation package
- Initiate Live Response Session
- Initiate automated investigation
- Consult a threat expert
- Action center

**3. Tabs**:

**Overview Tab - Cards**:

**Active Alerts Card**:
- Overall number from last 30 days
- Grouped: New and In progress
- Sub-categorized by severity
- Click alert ring number for sorted queue view

**Logged On Users Card**:
- Users logged on in past 30 days
- Most and least frequent users
- "See all users" opens details pane: user type, sign-in type, first/last seen

**Security Assessments Card**:
- Overall exposure level
- Security recommendations
- Installed software
- Discovered vulnerabilities

**Alerts Tab**:
- Filtered version of Alerts queue
- Shows: Description, severity, status, classification, investigation state, category, assigned to, last activity
- Filter capabilities available

**Timeline Tab**:
- Chronological view of events and alerts observed on device
- Correlate events, files, IP addresses
- Drill down into specific time periods
- View temporal sequence of events

**Timeline Features**:
- **Search**: Look for specific timeline events
- **Filter by date**: Calendar icon to select day, week, 30 days, custom range
- **Time jump**: Highlight section to jump to specific moment
- **Export**: Export timeline for current date or up to 7 days range

**Event Details**:
- **Contained by Application Guard**: Browser event restricted by isolated container
- **Active threat detected**: Threat detection while running
- **Remediation unsuccessful**: Remediation attempt failed
- **Remediation successful**: Threat stopped and cleaned
- **Warning bypassed**: User dismissed SmartScreen warning
- **Suspicious script detected**: Potentially malicious script found running
- **Alert category**: If event generated alert (e.g., "Lateral Movement")

**Flag Events**:
- Highlight important events
- Mark events requiring deep dive
- Build clean breach timeline
- Filter to show only flagged events

**Event Details Panel**:
- General event information
- Related entities graph (when applicable)
- "Hunt for related events" launches advanced hunting query

**Security Recommendations Tab**:
- Generated from Threat & Vulnerability Management
- Shows: Description, potential risks of non-compliance
- Click recommendation for details panel

**Software Inventory Tab**:
- View software on device
- Shows weaknesses or threats
- Click software name for: Security recommendations, vulnerabilities, installed devices, version distribution

**Discovered Vulnerabilities Tab**:
- Name, severity, threat insights
- Click vulnerability for description and details

**Missing KBs Tab**:
- Lists missing security updates (Knowledge Base IDs)

### 3. Behavioral Blocking

**Overview**:
- Addresses fileless malware, polymorphic threats, human-operated attacks
- Uses AI and ML for detection
- Identifies and stops threats based on behaviors and process trees
- Works even after threat starts running

**Components Working Together**:
- Next-generation protection (Defender Antivirus)
- Endpoint detection and response (EDR)
- Defender for Endpoint features
- Immediate attack stopping and progression prevention

**Client Behavioral Blocking**:

**How It Works**:
1. Microsoft Defender Antivirus detects suspicious behaviors on device
2. Monitors and sends behaviors + process trees to cloud protection
3. Machine learning classifies artifacts within milliseconds
4. Malicious artifacts blocked immediately on device
5. Alert generated and visible in portal

**Effectiveness**:
- Prevents attacks from starting
- Stops attacks that began executing
- Feedback-loop blocking prevents attacks on other devices

**Behavior-Based Detection Naming** (MITRE ATT&CK Matrix):

| Tactic | Detection Name |
|--------|----------------|
| Initial Access | Behavior:Win32/InitialAccess.*!ml |
| Execution | Behavior:Win32/Execution.*!ml |
| Persistence | Behavior:Win32/Persistence.*!ml |
| Privilege Escalation | Behavior:Win32/PrivilegeEscalation.*!ml |
| Defense Evasion | Behavior:Win32/DefenseEvasion.*!ml |
| Credential Access | Behavior:Win32/CredentialAccess.*!ml |
| Discovery | Behavior:Win32/Discovery.*!ml |
| Lateral Movement | Behavior:Win32/LateralMovement.*!ml |
| Collection | Behavior:Win32/Collection.*!ml |
| Command and Control | Behavior:Win32/CommandAndControl.*!ml |
| Exfiltration | Behavior:Win32/Exfiltration.*!ml |
| Impact | Behavior:Win32/Impact.*!ml |
| Uncategorized | Win32/Generic.*!ml |

**Feedback-Loop Blocking** (Rapid Protection):

**How It Works**:
1. Suspicious behavior/file detected (e.g., by Defender Antivirus)
2. Artifact info sent to multiple classifiers
3. Rapid protection loop engine inspects and correlates with other signals
4. Decision made whether to block file
5. Rapid blocking of confirmed malware
6. Protection driven across entire ecosystem

**Benefits**:
- Attack stopped on initial device
- Protection extended to other org devices
- Prevention in other organizations
- Stops attack from broadening foothold

**EDR in Block Mode**:

**Functionality**:
- Blocks malicious artifacts/behaviors observed post-breach
- Works behind the scenes for post-breach remediation
- Integrated with Threat & Vulnerability Management

**When Enabled**:
- Detection status shows "Blocked" or "Prevented"
- Completed actions visible in Action Center
- Blocks unwanted software even when Defender AV in passive mode

**Security Recommendation**:
- SOC team gets recommendation to enable if not already on

### 4. Device Discovery

**Purpose**:
- Find unmanaged devices on corporate network
- No extra appliances or process changes needed
- Uses onboarded endpoints to collect, probe, or scan network

**Discovery Capabilities**:
- **Enterprise endpoints**: Workstations, servers, mobile devices not yet onboarded
- **Network devices**: Routers, switches
- **IoT devices**: Printers, cameras

**Risks of Unmanaged Devices**:
- Unpatched printers
- Network devices with weak security
- Servers with no security controls

**Post-Discovery Actions**:
- Onboard unmanaged endpoints
- Reduce attack surface
- Identify and assess vulnerabilities
- Detect configuration gaps

**Discovery Methods**:

**Basic Discovery**:
- Endpoints passively collect network events
- Uses SenseNDR.exe binary
- No network traffic initiated
- Extracts data from network traffic seen by onboarded device
- Limited visibility of unmanaged endpoints

**Standard Discovery** (Recommended):
- Active device finding to enrich data
- Uses passive method + common discovery protocols
- Multicast queries find more devices
- Smart, active probing for additional device information
- Minimal network activity generated

**Device Assessment**:

**Onboarding Status Filter**:
- **Onboarded**: Endpoint onboarded to Defender for Endpoint
- **Can be onboarded**: Discovered device with supported OS, not currently onboarded (highly recommended to onboard)
- **Unsupported**: Discovered but not supported by Defender for Endpoint
- **Insufficient info**: Supportability cannot be determined (enable standard discovery on more devices)

**Location**: Device inventory → Computers and Mobile tab

**Security Recommendation**:
- Onboard devices to Defender for Endpoint available in Threat & Vulnerability Management experience

---

## V. Perform Actions on a Device

### 1. Device Actions Overview

**Containment Actions**:
- Isolate device
- Restrict app execution
- Run antivirus scan

**Investigation Actions**:
- Initiate automated investigation
- Collect investigation package
- Initiate Live Response session

**Action Center**: Provides information on actions taken on device or file

### 2. Isolate Devices from Network

**Purpose**: Prevent attacker from controlling compromised device and performing data exfiltration or lateral movement

**How It Works**:
- Disconnects device from network
- Retains connectivity to Defender for Endpoint service
- Device continues to be monitored

**Selective Isolation** (Windows 10 version 1709+):
- Enable Outlook, Microsoft Teams, Skype for Business connectivity
- Maintains business communication while isolated

**Process**:
1. Select "Isolate device" on device page
2. Type comment
3. Select Confirm
4. Action center shows scan information
5. Device timeline includes isolation event
6. User receives notification

### 3. Restrict App Execution

**Requirements**:
- Windows 10 version 1709 or later
- Microsoft Defender Antivirus enabled
- Windows Defender Application Control code integrity policy compliance

**How It Works**:
- Applies code integrity policy
- Only allows files signed by Microsoft-issued certificate
- Prevents attacker from controlling compromised devices

**Reversible**: Can remove restrictions at any time

**Process**:
1. Select "Restrict app execution" on device page
2. Type comment
3. Select Confirm
4. Action center shows information
5. Device timeline updated
6. User receives notification

### 4. Run Antivirus Scan

**Requirements**:
- Windows 10 version 1709 or later
- Can run alongside other AV solutions
- Works in Passive mode

**Scan Types**:
- **Quick scan**: Rapid scan of common locations
- **Full scan**: Comprehensive system scan

**CPU Impact**:
- Limited by 'ScanAvgCPULoadFactor' value
- Default: 50% maximum CPU load
- Configurable

**Process**:
1. Select "Run antivirus scan"
2. Choose scan type (quick or full)
3. Add comment
4. Confirm scan
5. Action center shows scan information
6. Device timeline updated

### 5. Initiate Automated Investigation

**Capabilities**:
- Starts general purpose automated investigation
- Additional alerts added to ongoing investigation
- Devices with same threat added to investigation
- Reduces manual investigation workload

### 6. Collect Investigation Package

**Purpose**: Identify device state and understand attacker tools/techniques

**Contents**:

| Folder | Description |
|--------|-------------|
| **Autoruns** | Registry ASEP content for attacker persistency analysis |
| **Installed Programs** | CSV list of installed programs |
| **Network Connections** | ActiveNetConnections.txt, Arp.txt, DnsCache.txt, IpConfig.txt, firewall logs |
| **Prefetch Files** | Recent file usage tracking, application deletion traces |
| **Processes** | CSV of running processes |
| **Scheduled Tasks** | CSV of automated routines |
| **Security Event Log** | Login/logout and security events |
| **Services** | CSV of services and states |
| **SMB Sessions** | Inbound/outbound sessions for data exfiltration detection |
| **System Information** | SystemInformation.txt with OS and network details |
| **Temp Directories** | Files in %Temp% for each user |
| **Users and Groups** | Group membership information |
| **WdSupportLogs** | MpCmdRunLog.txt and MPSupportFiles.cab |
| **CollectionSummaryReport.xls** | Collection summary with data points, commands, status, errors |

**Download Process**:
1. Select "Collect investigation package"
2. Specify reason
3. Select Confirm
4. Download ZIP file from Action center

### 7. Live Response Session

**Overview**: Instantaneous remote shell access to device for in-depth investigation and immediate response

**Capabilities**:
- Run basic and advanced commands
- Download files (malware samples, PowerShell script outputs)
- Background file downloads
- Upload and run PowerShell scripts/executables from library
- Take or undo remediation actions

**Prerequisites**:
- Supported Windows 10 version or later
- Live response enabled in Advanced features
- Device has Automation Remediation level assigned
- Appropriate RBAC permissions
- Optional: Unsigned script execution enabled

**Dashboard Information**:
- Session creator
- Session start time
- Session duration
- Upload files to library
- Command console and log

**Basic Commands** (read-only permissions):

| Command | Description |
|---------|-------------|
| cd | Change directory |
| cls | Clear console screen |
| connect | Start live response session |
| connections | Show active connections |
| dir | List files and subdirectories |
| getfile <file_path> | Download file in background |
| drivers | Show installed drivers |
| fg <command_id> | Return download to foreground |
| fileinfo | Get file information |
| findfile | Locate files by name |
| help | Command help information |
| persistence | Show persistence methods |
| processes | Show running processes |
| registry | Show registry values |
| scheduledtasks | Show scheduled tasks |
| services | Show services |
| trace | Set logging mode to debug |

**Advanced Commands** (elevated permissions):

| Command | Description |
|---------|-------------|
| analyze | Analyze entity with incrimination engines |
| getfile | Get file from device (with auto prerequisites) |
| run | Run PowerShell script from library |
| library | List files in live response library |
| putfile | Put file from library to device |
| remediate | Remediate entity (varies by type) |
| undo | Restore remediated entity |

**File Operations**:
- **Download**: `getfile "C:\windows\some_file.exe"` (background download)
- **Foreground**: `fg 1234` (bring to foreground)
- **Upload to library**: Upload file → Browse → Description → Confirm
- **Run script**: `run <script_name>`

**Output Options**:
- Table format (default): `-output table`
- JSON format: `-output json`
- Pipe to file: `[command] > [filename].txt`

**Limitations**:
- Max 10 concurrent live response sessions
- 1 session per user at a time
- 1 device per session at a time
- 5-minute inactive timeout
- File size limits: getfile 3GB, fileinfo 10GB, library 250MB
- 2-hour latency for commands

---

## VI. Perform Evidence and Entities Investigations

### 1. Investigate Files

**Access Points**:
- Search feature
- Alert process tree
- Incident graph
- Artifact timeline
- Device timeline

**File View Sections**:

**File Details Card**:
- MD5 hash
- Virus Total detection ratio
- Microsoft Defender AV detection
- File prevalence (worldwide and organization)

**Alerts Tab**:
- Associated alerts list
- Customizable columns
- Same info as Alerts queue (minus device group)

**Observed in Organization Tab**:
- Date range selection
- Devices where file observed (max 100)
- Export to CSV for complete list
- Time slider for precise event tracking

**Deep Analysis Tab**:
- Submit file for deep analysis
- Uncover file behavior details
- View analysis reports
- Results include: behaviors, observables, dropped files, registry modifications, IP communications

**File Names Tab**:
- All names file observed with in organization

**Response Actions**:
- Stop and quarantine file
- Add/edit indicator
- Download file
- Consult threat expert
- Action center

### 2. Deep File Analysis

**Execution Environment**:
- Secure, fully instrumented cloud environment
- Supported: PE files (.exe, .dll)
- Several minutes processing time

**Analysis Report Contains**:
- Observed behaviors
- Malicious activity indicators
- Associated artifacts (dropped files, registry mods, IP contacts)
- Threat intelligence matching

**Submission Methods**:
1. From file profile page (Deep analysis tab)
2. After file observed on Windows 10 device
3. Manual upload through portal

**Prerequisites**:
- File in Defender backend sample collection OR
- Observed on Windows 10 device supporting submission

**Troubleshooting**:
- Ensure file is PE format (.exe, .dll)
- Verify service has file access
- Check sample collection policy (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection, AllowSampleCollection=1)
- Wait and retry if queue full

### 3. File Response Actions

**Stop and Quarantine File**:

**Requirements**:
- Windows 10 version 1703+
- File not from trusted third-party publishers
- Not signed by Microsoft
- Defender AV in at least Passive mode

**Actions Performed**:
- Stop running processes
- Quarantine files
- Delete persistent data (registry keys)
- Limited to 1,000 devices max

**Restore from Quarantine**:
```cmd
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" –Restore –Name EUS:Win32/CustomEnterpriseBlock –All
```

**Add Indicator (Block/Allow File)**:

**Prerequisites**:
- Turn on Block or allow feature in Settings
- Defender Antivirus ON
- Cloud-based protection enabled

**Indicator Actions**:
- Block file: Prevent read, write, execute
- Raise alert when execution attempted
- Apply across organization
- Remove indicator to stop blocking

**Download File**:
- Password-protected .zip archive
- Record reason for download
- Set password for archive
- If file not stored: "Collect file" button appears
- Disabled if not seen in 30 days

### 4. Investigate User Accounts

**Access Points**:
- Dashboard (Users at risk)
- Alert queue
- Device details page

**User Details Pane**:
- Related open incidents
- Active alerts
- SAM name, SID
- Number of devices logged on to
- First and last seen dates
- Role and log-on types
- Integration-dependent additional details

**Tabs**:

**Overview Tab**:
- Incident details
- Device list (expand for log-on event details)

**Alerts Tab**:
- Filtered Alert queue view
- User context alerts
- Last activity date
- Alert description, device, severity, status
- Assignment information

**Observed in Organization Tab**:
- Date range selection
- Device list where user logged on
- Most/least frequent users per device
- Total observed users per device
- Expandable items for device details

### 5. Investigate IP Addresses

**Purpose**: Identify devices communicating with suspected/known malicious IPs (C2 servers)

**IP View Sections**:

**IP Worldwide**:
- ASN (Autonomous System Number)
- Reverse DNS names
- Registration details

**Reverse DNS Names**:
- Associated domain names

**Alerts Related to IP**:
- List of associated alerts

**IP in Organization**:
- Prevalence details in organization

**Prevalence Section**:
- Number of devices connected
- First and last seen dates
- Filter by time period (default 30 days)

**Most Recent Observed Devices**:
- Chronological view of events
- Associated alerts observed

**Investigation Process**:
1. Select IP from Search dropdown
2. Enter IP address
3. Press Enter or search icon
4. View registration details, reverse IPs
5. Analyze device communication prevalence
6. Review communicating devices

### 6. Investigate Domains

**Purpose**: Identify communication with known malicious domains

**Access Methods**:
- Search feature
- Domain link from Device timeline

**URL View Sections**:

**URL Worldwide**:
- URL details link
- Related open incidents count
- Active alerts count

**Incident Card**:
- Bar chart of active alerts in incidents (past 180 days)

**Prevalence Card**:
- URL prevalence over time
- Default: Past 30 days
- Customizable: 1 day to 6 months range

**Alerts Tab**:
- Associated alerts list
- Filtered Alert queue view
- Shows: domain, severity, status, incident, classification, investigation state
- Customizable columns
- Adjustable items per page

**Observed in Organization Tab**:
- Chronological event view
- Associated alerts timeline
- Customizable table with: time, device, event description
- Date filtering
- Timeline area selection

**Investigation Process**:
1. Select URL from Search dropdown
2. Enter URL in search field
3. Press Enter
4. View URL details
5. Filter by timeline
6. Select device name to investigate further

---

## VII. Configure and Manage Automation

### 1. Configure Advanced Features for Automation

**Automation-Related Settings** (Settings → Endpoints → Advanced features):

| Feature | Description |
|---------|-------------|
| **Automated Investigation** | Enables automated investigation and remediation capabilities |
| **Enable EDR in Block Mode** | Blocks malicious artifacts/behaviors via post-breach EDR, doesn't change detection/alerting |
| **Automatically Resolve Alerts** | Resolves alerts when automated investigation finds no threats or successfully remediates |
| **Allow or Block File** | Requires Defender AV ON and cloud-based protection enabled |

**Autoresolve Remediated Alerts**:
- Default ON for tenants created on/after Windows 10 v1809
- Resolves alerts with "No threats found" or "Remediated" status
- Influences Device risk level calculation
- Manual analyst actions won't be overwritten

**Allow or Block File Requirements**:
- Microsoft Defender Antivirus as active antimalware
- Cloud-based protection enabled
- Blocks file read, write, execute across organization
- Configure via Add Indicator tab on file profile

### 2. Manage Automation Uploads and Folder Settings

**File Content Analysis**:
- Automatically upload files/email attachments for cloud inspection
- Specify file extension names (e.g., exe, bat)
- Automatic upload during automated investigation

**Memory Content Analysis**:
- Automatically investigate process memory content
- Memory content uploaded during automated investigation

**Configuration Path**: Settings → Endpoints → Rules → Automation uploads

**Settings**:
- Toggle content analysis ON/OFF
- Configure file extension names (comma-separated)
- Configure attachment extension names

**Automation Folder Exclusions**:

**Purpose**: Specify folders to skip during automated investigation

**Configurable Attributes**:
- **Folders**: Specific folder and subfolders
- **Extensions**: File extensions to exclude in directory
- **File Names**: Specific file names to exclude

**Security Benefits**:
- Prevent attacker exploitation of excluded folders
- Explicitly define which files to ignore

**Configuration Path**: Settings → Endpoints → Rules → Automation folder exclusions

**Add Exclusion Process**:
1. Select "New folder exclusion"
2. Enter folder path
3. Specify extensions (optional)
4. Specify file names (optional)
5. Add description
6. Select Save

### 3. Configure Automated Investigation and Remediation

**Setup Process**:

**Step 1: Turn On Features** (Global/Security Administrator):
1. Navigate: Settings → Endpoints → General → Advanced features
2. Turn on "Automatically resolve alerts"
3. Select "Save preferences"

**Note**: Automated Investigation now enabled by default (no longer in advanced features)

**Step 2: Set Up Device Groups**:
1. Navigate: Endpoints → Permissions → Device groups
2. Select "+ Add device group"
3. Configure:
   - Name and description
   - Automation level
   - Device selection criteria
   - User access (Azure AD groups)
4. Select Done

**Automation Levels**:

| Level | Description | Approval Required |
|-------|-------------|-------------------|
| **Full - remediate threats automatically** | All remediation actions automatic, view in Action Center History tab, can undo if needed | No |
| **Semi - require approval for any remediation** | Approval required for ANY remediation action, view in Action Center Pending tab | Yes - All actions |
| **Semi - require approval for core folders** | Approval for files/executables in core folders (Windows\*), automatic for non-core folders | Yes - Core folders only |
| **Semi - require approval for non-temp folders** | Approval for files NOT in temp folders, automatic for temp folders | Yes - Non-temp only |
| **No automated response (no automation)** | No automated investigation runs, no remediation actions (NOT RECOMMENDED) | N/A |

**Core Folders**: Operating system directories (e.g., \windows\*)

**Temporary Folders Examples**:
- \users\*\appdata\local\temp\*
- \documents and settings\*\local settings\temp\*
- \windows\temp\*
- \users\*\downloads\*
- \program files\ and \program files (x86)\*

**Quick Configuration**: Settings → General → Auto remediation (list of device groups with current levels)

### 4. Block At-Risk Devices with Conditional Access

**Purpose**: Contain threats by blocking risky devices from corporate resources

**Requirements**:
- Microsoft Intune environment
- Intune-managed Windows 10+ devices
- Azure AD joined devices

**Required Roles**:
- **Defender portal**: Security Administrator (for roles), Defender for Endpoint Administrator (for advanced settings)
- **Intune**: Security Administrator with management permissions
- **Azure AD portal**: Security Administrator or Conditional Access Administrator

**Implementation Steps**:

**Step 1: Enable Intune Connection in Defender**:
1. Navigate: Settings → Endpoints → General → Advanced features
2. Toggle "Microsoft Intune connection" to ON
3. Select "Save preferences"

**Step 2: Enable Defender Integration in Intune**:
1. Sign in to Microsoft Intune admin center
2. Navigate: Endpoint security → Microsoft Defender for Endpoint
3. Set "Allow Microsoft Defender for Endpoint to enforce Endpoint Security Configurations" to ON
4. Select Save

**Step 3: Create Compliance Policy in Intune**:
1. Navigate: Devices → Manage Devices → Compliance
2. Select "+ Create policy"
3. Platform: Windows 10 and later → Create
4. Enter Name and Description → Next
5. Expand "Microsoft Defender for Endpoint"
6. Set "Require device to be at or under machine risk score":
   - **Clear**: Most secure, no existing threats allowed
   - **Low**: Low-level threats only
   - **Medium**: Low or medium threats
   - **High**: Least secure, all threat levels compliant
7. Next → Configure "Actions for noncompliance"
8. Next → Assign scope tags
9. Next → Assign to groups/users/devices
10. Create

**Step 4: Create Azure AD Conditional Access Policy**:
1. Azure portal → Azure AD Conditional Access
2. Select "+ New policy" → "Create new policy"
3. Enter policy Name
4. Select "Users or workload entities" → Add groups
5. "Cloud apps or actions" → Choose apps (e.g., Office 365 SharePoint, Exchange)
6. "Conditions" → Select client apps and browsers → Done
7. "Grant" → Select "Grant access" → "Require device to be marked as compliant"
8. Select "Enable policy"
9. Create

---

## VIII. Configure Alerts and Detections

### 1. Configure Advanced Features for Alerts

**Alert-Focused Settings** (Settings → Endpoints → Advanced features):

| Feature | Description |
|---------|-------------|
| **Live Response** | Remote shell connection for users with appropriate RBAC permissions |
| **Live Response Unsigned Script Execution** | Run unsigned scripts in Live Response sessions |
| **Custom Network Indicators** | Allow or block connections to IPs, domains, URLs from custom indicator lists |

**Configuration**: Toggle each feature ON/OFF as needed

### 2. Configure Alert Notifications

**Purpose**: Send email notifications to specified recipients for new alerts

**Requirements**:
- "Manage security settings" permissions
- Basic permissions: Security Administrator or Global Administrator roles

**Notification Features**:
- Alert severity level triggers
- Add/remove recipients
- New recipients notified about alerts after addition
- RBAC integration: Recipients only see alerts for their device groups
- Global administrator: Manage notifications for all device groups

**Email Notification Contents**:
- Basic alert information
- Portal link for further investigation

**Create Notification Rule**:
1. Navigate: Settings → Endpoints → Email notifications
2. Select "+ Add item"
3. Configure General Information:
   - Rule name
   - Include organization name
   - Include tenant-specific portal link
   - Include device information
4. Select Devices:
   - All devices (Global admin only) OR
   - Selected device groups
5. Choose Alert severity levels
6. Select Next
7. Enter recipient email addresses
8. Select "Add recipient" for each
9. Send test email to verify
10. Select "Save notification rule"

### 3. Manage Alert Suppression

**Purpose**: Suppress innocuous alerts from appearing in portal (e.g., known tools/processes)

**Alert Tuning**: Create rules for specific alerts to reduce noise

**Manage Rules**:
1. Navigate: Settings → Microsoft Defender XDR → Rules → Alert tuning
2. View list of all alert tuning rules
3. Select rule checkbox
4. Available actions:
   - Turn rule on/off
   - Edit rule
   - Delete rule
5. Option to release already suppressed alerts when editing

### 4. Manage Indicators (IoCs)

**Overview**: Essential endpoint protection feature for detection, prevention, and exclusion

**Supported Sources**:
- Cloud detection engine
- Automated investigation and remediation engine
- Endpoint prevention engine (Defender AV)

**How Engines Use Indicators**:

| Engine | Behavior |
|--------|----------|
| **Cloud Detection** | Scans collected data, matches indicators, takes action per IoC settings |
| **Endpoint Prevention** | Defender AV honors indicators - blocks/alerts per settings |
| **Automated Investigation** | "Allow" = ignore bad verdict, "Block" = treat as bad |

**Supported Actions**:
- Allow
- Alert only
- Alert and block

**Indicator Types**:
- Files
- IP addresses
- URLs/Domains
- Certificates

**Limit**: 15,000 indicators per tenant

**Manage Indicators**:
1. Navigate: Settings → Endpoints → Indicators (Rules area)
2. Select entity type tab
3. Update indicator details → Save OR
4. Select Delete to remove

### 5. Create File Indicators

**Purpose**: Ban potentially malicious files, prevent malware propagation

**Prerequisites**:
- Defender Antivirus with Cloud-based protection enabled
- Antimalware client 4.18.1901.x or later
- Windows 10 version 1703+, Windows Server 2016/2019
- Turn on "Block or allow" feature in Settings
- Supports PE files (.exe, .dll) - coverage expanding

**Important Notes**:
- Cannot block files if classification in device cache before action
- Trusted signed files treated differently
- May have performance implications for trusted files
- Block enforcement: Few minutes to 30 minutes

**Creation Methods**:

**Method 1: From Settings Page**:
1. Navigate: Settings → Endpoints → Indicators → Files tab
2. Select "+ Add item"
3. Configure indicator details
4. Select Save

**Method 2: Contextual Indicator (from file details)**:
1. On file details page → Response actions
2. Select "Add indicator"
3. Add indicator hash
4. Choose to raise alert and block
5. Blocked files won't show in Action center
6. Alerts visible in Alerts queue

**Remove Indicator**:
- Via "Edit Indicator" action on file profile page
- Via Settings → Rules → Indicators

### 6. Create IP and URL/Domain Indicators

**Purpose**: Allow or block IPs, URLs, domains based on custom threat intelligence

**How It Works**:
- Blocks through SmartScreen (Microsoft browsers)
- Blocks through Network Protection (non-Microsoft browsers, non-browser calls)
- Apply to specific device groups (risk-based)

**Prerequisites**:
- Network Protection enabled in block mode
- Antimalware client 4.18.1906.x or later
- Windows 10 version 1709+ or Windows 11
- "Custom network indicators" enabled in Advanced features

**Limitations**:
- External IPs only (no internal IPs)
- No CIDR notation for IPs
- Single IP addresses only (no CIDR blocks or ranges)
- Encrypted URLs (full path): first party browsers only
- Encrypted URLs (FQDN only): outside first party browsers
- Full URL path blocks: domain level + all unencrypted URLs
- Up to 2-hour latency

**Network Protection Coverage**:
- IP: Supported for TCP, HTTP, HTTPS (TLS)
- Microsoft Edge: Network Protection inspects and allows/blocks
- Other processes: Network Protection for inspection and enforcement

**Create Indicator**:
1. Navigate: Settings → Indicators
2. Select "IP addresses or URLs/Domains" tab
3. Select "+ Add item"
4. Specify:
   - Indicator (entity details, expiration)
   - Action (Allow/Alert only/Alert and block, description)
   - Scope (device group)
5. Review Summary tab
6. Select Save

### 7. Create Certificate Indicators

**Use Cases**:
- Allow behaviors from signed applications (ASR, controlled folder access exceptions)
- Block specific signed applications organization-wide

**Prerequisites**:
- Defender Antivirus with Cloud-based protection enabled
- Antimalware client 4.18.1901.x or later
- Windows 10 version 1703+, Windows Server 2016/2019
- Up-to-date virus and threat protection definitions
- Supports .CER or .PEM extensions
- Valid leaf certificate with valid certification path
- Microsoft signed certificates CANNOT be blocked
- Up to 3-hour creation/removal time

**Certificate Requirements**:
- Valid leaf certificate chained to Microsoft-trusted Root CA OR
- Custom (self-signed) certificate trusted by client (Root CA in Local Machine 'Trusted Root Certification Authorities')
- Only leaf certificates supported (not children or parents)

**Create Indicator**:
1. Navigate: Settings → Endpoints → Indicators → Certificate tab
2. Select "+ Add item"
3. Specify:
   - Indicator (entity details, expiration)
   - Action (Allow/Alert/Block, description)
   - Scope (device group)
4. Review Summary tab
5. Select Save

### 8. Import IoC List

**Purpose**: Bulk upload indicators via CSV file

**Process**:
1. Download sample CSV (shows supported attributes)
2. Navigate: Settings → Endpoints → Indicators
3. Select entity type tab
4. Select Import → Choose file
5. Select Import
6. Repeat for all files
7. Select Done

**Supported CSV Parameters**:

| Parameter | Type | Values/Description | Required |
|-----------|------|-------------------|----------|
| indicatorType | Enum | FileSha1, FileSha256, IpAddress, DomainName, Url | Yes |
| indicatorValue | String | Indicator entity identity | Yes |
| action | Enum | Alert, AlertAndBlock, Allowed | Yes |
| title | String | Indicator alert title | Yes |
| description | String | Indicator description | Yes |
| expirationTime | DateTimeOffset | Format: YYYY-MM-DDTHH:MM:SS.0Z | Optional |
| severity | Enum | Informational, Low, Medium, High | Optional |
| recommendedActions | String | TI indicator alert recommended actions | Optional |
| rbacGroupNames | String | Comma-separated RBAC group names | Optional |
| category | String | Alert category (e.g., Execution, credential access) | Optional |
| MITRE techniques | String | MITRE technique codes (comma-separated) | Optional |

**Note**: Recommended to add category value when using MITRE technique

---

## IX. Utilize Vulnerability Management

### 1. Understand Threat & Vulnerability Management

**Purpose**: Identify, assess, and remediate endpoint weaknesses to reduce organizational risk

**Key Features**:
- Real-time vulnerability and misconfiguration discovery
- No agents or periodic scans needed
- Prioritizes based on threat landscape, detections, sensitive data, business context

**Integration**:
- Built-in, real-time, cloud-powered
- Fully integrated with Microsoft endpoint security stack
- Microsoft Intelligent Security Graph
- Application analytics knowledge base
- Creates security tasks via Intune and Endpoint Configuration Manager

**Bridging Workflow Gaps**:
- First solution to bridge security admin and IT admin gap
- Seamless collaboration during remediation
- Integration with Intune and Endpoint Configuration Manager

### 2. Real-Time Discovery

**Sensor-Based Discovery**:
- Uses agentless built-in Defender sensors
- Reduces network scans and IT overhead

**Discovery Capabilities**:

**Real-Time Device Inventory**:
- Automatic vulnerability and security configuration reporting
- Pushed to dashboard

**Software and Vulnerabilities Visibility**:
- Organization software inventory
- Software changes tracking (installs, uninstalls, patches)
- Newly discovered vulnerabilities reported
- Actionable mitigation recommendations (1st and 3rd party apps)

**Application Runtime Context**:
- Application usage patterns visibility
- Better prioritization and decision-making

**Configuration Posture**:
- Organizational security configuration visibility
- Misconfiguration identification
- Issues reported with actionable security recommendations

### 3. Intelligence-Driven Prioritization

**Prioritization Factors**:
- Dynamic threat context
- Business context
- Most urgent and highest risk focus

**Prioritization Features**:

**Exposing Emerging Attacks**:
- Dynamically aligns security recommendations
- Focuses on wild exploits
- Emerging threats with highest risk

**Pinpointing Active Breaches**:
- Correlates TVM and EDR insights
- Prioritizes vulnerabilities in active breaches

**Protecting High-Value Assets**:
- Identifies exposed devices with:
  - Business-critical applications
  - Confidential data
  - High-value users

### 4. Seamless Remediation

**Security and IT Collaboration**:
- Security admins request remediation
- IT admins execute fixes

**Remediation Features**:

**Remediation Requests**:
- Create remediation task in Intune
- From specific security recommendation
- Expansion to other IT security management platforms planned

**Alternate Mitigations**:
- Configuration changes insights
- Risk reduction without software updates

**Real-Time Remediation Status**:
- Monitor status and progress across organization
- Track remediation activities

### 5. Vulnerability Management Features by License

**Three Licensing Tiers**:

| Feature | Defender for Endpoint P2 (Core) | TVM Add-on for Defender P2 | TVM Standalone |
|---------|--------------------------------|---------------------------|----------------|
| Device discovery | ✓ | ✓ | ✓ |
| Device inventory | ✓ | ✓ | ✓ |
| Vulnerability assessment | ✓ | ✓ | ✓ |
| Configuration assessment | ✓ | ✓ | ✓ |
| Risk-based prioritization | ✓ | ✓ | ✓ |
| Remediation tracking | ✓ | ✓ | ✓ |
| Continuous monitoring | ✓ | ✓ | ✓ |
| Software assessment | ✓ | ✓ | ✓ |
| Security baselines assessment | | ✓ | ✓ |
| Block vulnerable applications | | ✓ | ✓ |
| Browser extensions | | ✓ | ✓ |
| Digital certificate assessment | | ✓ | ✓ |
| Network share analysis | | ✓ | ✓ |

### 6. Vulnerability Management Portal Areas

**Dashboard**:
- Multiple tiles showing overall exposure
- Remediation information

**Recommendations**:
- List of security recommendations
- Prioritized by risk

**Remediation**:
- Track remediation activities
- Request and monitor fixes

**Inventories**:
- Software installed in network
- Vendor name, weaknesses, threats
- Exposed devices, exposure score impact
- Filter by: weaknesses, threats, end-of-support tags

**Weaknesses**:
- Software vulnerabilities (CVE IDs)
- Severity, CVSS rating
- Prevalence in organization
- Breach correlation, threat insights

**Event Timeline**:
- Risk news feed
- How risk introduced to organization
- New vulnerabilities, exploitability changes
- Exposure score and Secure Score for Devices story
- Impact on devices and scores
- Remediation prioritization

**Baseline Assessments**:
- Continuous compliance monitoring
- Real-time security baselines compliance
- Identify changes in real time
- Create customized security baseline profiles
- Assess against industry benchmarks

### 7. Vulnerable Devices Report

**Location**: Reports area in Microsoft Defender portal

**Report Contents**:
- Vulnerable device trends (graphs)
- Current statistics (bar charts)
- Device exposure scope understanding

**Graphs Included**:

**Severity Level Graphs**:
- Each device counted once (by most severe vulnerability)

**Exploit Availability Graphs**:
- Each device counted once (by highest known exploit level)

**Vulnerability Age Graphs**:
- Each device counted once (by oldest vulnerability date)
- Older vulnerabilities = higher exploit chance

**Vulnerable Devices by OS Platform**:
- Number of devices per OS exposed due to software vulnerabilities

**Vulnerable Devices by Windows Version**:
- Number of devices per Windows version exposed

### 8. Manage Remediation

**Remediation Request Workflow**:
- Security admins request remediation
- IT admins execute via Intune

**Request Steps**:
1. Navigate: Vulnerability management → Recommendations
2. Select security recommendation
3. Select "Remediation options"
4. Fill out form:
   - What requesting remediation for
   - Applicable device groups
   - Priority level
   - Due date
   - Optional notes
5. Select "Submit request"

**Note**: "Attention required" option = no due date (no specific action)

**Post-Submission**:
- Creates remediation activity item in TVM
- Monitor remediation progress
- No immediate changes to devices
- Notify IT administrator
- IT admin logs into Intune to approve/reject
- IT admin starts package deployment

**View Remediation Activities**:
1. Navigate: Remediation page
2. Select remediation activity
3. Available actions:
   - Follow remediation steps
   - Track progress
   - View related recommendation
   - Export to CSV
   - Mark as complete

**Activity Tracking**:
- Security task created
- Tracks on Remediation page
- Remediation ticket in Intune
- "Attention required" = no progress bar, ticket status, or due date

---

## Summary

This comprehensive module covers threat mitigation using Microsoft Defender for Endpoint across nine major areas:

**I. Protection Capabilities**: TVM, ASR, Next-gen protection, EDR, Automated remediation, Advanced hunting with KQL

**II. Deployment**: Environment setup, multi-platform OS compatibility, device onboarding methods, RBAC configuration, device groups, advanced features

**III. Security Enhancements**: Attack surface reduction rules with multiple configuration methods (Intune, MDM, Configuration Manager, Group Policy, PowerShell)

**IV. Device Investigation**: Inventory management, detailed device pages, behavioral blocking (client-based, feedback-loop, EDR block mode), device discovery

**V. Device Actions**: Containment (isolate, restrict apps, AV scan), investigation (automated investigation, package collection, live response with 25+ commands)

**VI. Evidence Investigation**: File deep analysis, user account tracking, IP address investigation, domain analysis with comprehensive entity details

**VII. Automation**: Advanced feature configuration, upload/folder settings, automated investigation levels (full/semi/no automation), conditional access for at-risk devices

**VIII. Alerts & Detections**: Advanced features, email notifications, alert suppression, comprehensive indicator management (files, IPs, URLs, certificates) with CSV import

**IX. Vulnerability Management**: Real-time discovery, intelligence-driven prioritization, seamless remediation workflow, licensing tiers, portal areas, vulnerable device reporting

**Key Takeaways**:
- **Multi-layered defense** with integrated protection capabilities
- **RBAC ensures** least privilege access control
- **Automation reduces** manual workload and response time
- **Behavioral blocking** stops threats even after execution begins
- **Live response** provides instant remote access for investigation
- **Deep analysis** uncovers detailed threat behaviors
- **Vulnerability management** bridges security and IT admin gaps
- **Custom indicators** enable proactive threat blocking
- **Conditional access** contains threats at network level
- **Comprehensive reporting** supports risk-based decision making
