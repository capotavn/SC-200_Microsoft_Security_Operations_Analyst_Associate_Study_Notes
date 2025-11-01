# SC-200: Configure your Microsoft Sentinel environment

## I. Introduction to Microsoft Sentinel

### 1. What is SIEM?

**Security Information and Event Management (SIEM)**:
- Tool for collecting, analyzing, and performing security operations on computer systems
- Can be hardware appliances, applications, or both

**Basic SIEM Functions**:
- Collect and query logs
- Correlation or anomaly detection
- Create alerts and incidents based on findings

**SIEM Functionality**:
- **Log Management**: Collect, store, and query log data from environment resources
- **Alerting**: Proactive detection of potential security incidents and anomalies
- **Visualization**: Graphs and dashboards for log data insights
- **Incident Management**: Create, update, assign, and investigate incidents
- **Querying Data**: Rich query language for data understanding

### 2. What is Microsoft Sentinel?

**Definition**: Cloud-native SIEM system for security operations teams

**Core Capabilities**:
- **Get Security Insights**: Collect data from virtually any source across enterprise
- **Detect and Investigate Threats**: Built-in machine learning and Microsoft threat intelligence
- **Automate Threat Responses**: Playbooks and Azure Logic Apps integration

**Key Advantages**:
- No server installation required (on-premises or cloud)
- Service deployed in Azure
- Get up and running in minutes via Azure portal
- Tightly integrated with other cloud services
- Native use of cloud services (authorization, automation)

**Security Operations Coverage**:
- Collection
- Detection
- Investigation
- Response

### 3. How Microsoft Sentinel Works

**Key Features and Components**:

**Data Connectors**:
- Ingest data into Microsoft Sentinel
- Install Content hub solutions first
- Some services require only button selection (e.g., Azure activity logs)
- Others require more configuration (e.g., syslog)

**Connector Types**:
- Syslog
- Common Event Format (CEF)
- TAXII (Trusted Automated eXchange of Indicator Information - threat intelligence)
- Azure Activity
- Microsoft Defender services
- Amazon Web Services (AWS)
- Google Cloud Platform (GCP)

**Log Retention**:
- Data stored in Log Analytics workspace after ingestion
- Benefits: Use Kusto Query Language (KQL) to query data
- Rich query language for diving into data and gaining insights

**Workbooks**:
- Visualize data within Microsoft Sentinel
- Think of workbooks as dashboards
- Each component built using underlying KQL query
- Use built-in workbooks or create custom ones
- Edit existing workbooks to meet needs
- Implementation of Azure Monitor workbooks

**Analytics Alerts**:
- Proactive analytics across data
- Notifications for suspicious occurrences
- Enable built-in analytics alerts in workspace
- Various alert types (some editable, others ML-based proprietary models)
- Create custom scheduled alerts from scratch

**Threat Hunting**:
- Content hub solutions provide built-in hunting queries
- Analysts can create custom queries
- Integration with Azure Notebooks
- Example notebooks for advanced hunters
- Full programming language power for hunting

**Incidents and Investigations**:
- Incident created when alerts triggered
- Standard incident management tasks:
  - Change status
  - Assign incidents to individuals
- Investigation functionality:
  - Visually investigate incidents
  - Map entities across log data along timeline

**Automation Playbooks**:
- Automate security operations workflows
- Create automated workflows in response to events
- Use cases:
  - Incident management
  - Enrichment
  - Investigation
  - Remediation
- Security Orchestration, Automation, and Response (SOAR)

**End-to-End Solution**:
- Ingest data from cloud and on-premises
- Perform analytics on data
- Manage and investigate incidents
- Respond automatically using playbooks

### 4. When to Use Microsoft Sentinel

**Ideal Scenarios**:
- Need for cloud-native SIEM solution
- Multi-cloud and hybrid environment security
- Require scalable security analytics
- Want to leverage AI and machine learning for threat detection
- Need automated incident response
- Require integration with Microsoft security ecosystem

**Benefits**:
- No infrastructure management
- Elastic scalability
- Built-in threat intelligence
- Advanced analytics and ML
- Seamless Azure integration
- Pay-as-you-go pricing model

---

## II. Create and Manage Microsoft Sentinel Workspaces

### 1. Plan for Microsoft Sentinel Workspace

**Critical Planning Decision**: Region selection (where log data resides)

**Three Implementation Options**:

**Option 1: Single-Tenant with Single Workspace**

**Description**: Central repository for logs across all resources within same tenant

**Pros**:
- Central pane of glass
- Consolidates all security logs and information
- Easier to query all information
- Azure Log Analytics RBAC for data access control
- Microsoft Sentinel RBAC for service RBAC

**Cons**:
- May not meet data governance requirements
- Can incur bandwidth cost for cross-region data transfer
- Logs from other regions travel and stored in different region

**Use Case**: Organizations without strict data residency requirements, prefer centralized view

**Option 2: Single-Tenant with Regional Workspaces**

**Description**: Multiple Microsoft Sentinel workspaces (multiple workspace creation and configuration)

**Pros**:
- No cross-region bandwidth costs
- May be required to meet data governance requirements
- Granular data access control
- Granular retention settings
- Split billing

**Cons**:
- No central pane of glass
- Not looking in one place for all data
- Analytics, workbooks, etc. must be deployed multiple times

**Cross-Workspace Queries**:
```kql
TableName
| union workspace("WorkspaceName").TableName
```

**Option 3: Multiple Tenant Workspaces**

**Description**: Manage Microsoft Sentinel workspace not in your tenant

**Implementation**: Use Azure Lighthouse for security configuration
- Grants access to external tenants
- Tenant configuration (regional or multi-regional) same as single-tenant considerations

**Shared Workspace Recommendation**:
- Use same Log Analytics workspace for Microsoft Sentinel and Microsoft Defender for Cloud
- Streamlines security operations
- All Defender for Cloud logs can be used by Sentinel
- Note: Default workspace created by Defender for Cloud won't appear as available workspace for Sentinel

### 2. Create Microsoft Sentinel Workspace

**Prerequisites**:
- Azure subscription
- Appropriate permissions (Contributor or Owner on subscription/resource group)

**Creation Steps**:
1. Sign into Azure portal
2. Search for "Microsoft Sentinel"
3. Select "Create Microsoft Sentinel"
4. Select or create Log Analytics workspace
5. Add Microsoft Sentinel to workspace
6. Configure settings

**Key Configuration Decisions**:
- Region/location
- Pricing tier (Pay-as-you-go or Commitment tiers)
- Data retention period
- Resource group assignment

### 3. Manage Workspaces Across Tenants - Azure Lighthouse

**Purpose**: Manage resources across multiple tenants

**Azure Lighthouse Capabilities**:
- Cross-tenant management at scale
- Service provider scenarios
- Manage multiple customer tenants
- Enhanced visibility across managed tenants

**Benefits for Microsoft Sentinel**:
- Centralized management of multiple customer Sentinel instances
- Perform cross-tenant queries
- Create and manage automation rules across tenants
- View and manage incidents across customer workspaces

**Setup Requirements**:
- Azure Lighthouse onboarding
- Appropriate delegated permissions
- Service provider or MSSP scenarios

### 4. Microsoft Sentinel Permissions and Roles

**Azure RBAC for Sentinel**: Built-in roles for users, groups, and services

**Microsoft Sentinel-Specific Roles** (all grant read access to data):

| Role | Permissions |
|------|-------------|
| **Microsoft Sentinel Reader** | View data, incidents, workbooks, and other Sentinel resources |
| **Microsoft Sentinel Responder** | Above + manage incidents (assign, dismiss, etc.) |
| **Microsoft Sentinel Contributor** | Above + create and edit workbooks, analytics rules, and other Sentinel resources |
| **Microsoft Sentinel Automation Contributor** | Allows Sentinel to add playbooks to automation rules (not for user accounts) |

**Best Practice**: Assign roles to resource group containing Sentinel workspace (applies to all supporting resources)

**Additional Role Requirements**:

**Playbooks and Automation**:
- **Logic App Contributor**: Use Logic Apps for SOAR operations
- Microsoft Sentinel uses special service account to run playbooks
- Account needs explicit permissions to resource group containing playbooks
- User needs Owner permissions on resource group to grant these permissions

**Data Connectors**:
- User needs write permissions on Sentinel workspace
- Note required permissions for each specific connector

**Guest Users**:
- To assign incidents: Need **Directory Reader** role (Microsoft Entra role, not Azure role)
- Regular users have this role by default

**Workbooks**:
- Create/delete: Sentinel Contributor OR lesser Sentinel role + Azure Monitor **Workbook Contributor** role

**Azure Roles** (wider permissions):
- **Owner**: Full access across all Azure resources
- **Contributor**: Create and manage resources
- **Reader**: View resources

**Log Analytics Roles**:
- **Log Analytics Contributor**: Full access to Log Analytics workspaces
- **Log Analytics Reader**: Read-only access

**Role Capabilities Summary**:

| Role | Create/Run Playbooks | Create/Edit Workbooks & Rules | Manage Incidents | View Data & Resources |
|------|---------------------|------------------------------|------------------|---------------------|
| Sentinel Reader | No | No | No | Yes |
| Sentinel Responder | No | No | Yes | Yes |
| Sentinel Contributor | No | Yes | Yes | Yes |
| Sentinel Contributor + Logic App Contributor | Yes | Yes | Yes | Yes |

**Custom Roles**: Can be created if built-in roles don't meet organization needs

### 5. Manage Microsoft Sentinel Settings

**Settings Configuration Areas**:

**Workspace Settings**:
- Daily cap (ingestion limit)
- Data retention period
- Azure region
- Pricing tier

**Data Collection**:
- Configure data connectors
- Enable content hub solutions
- Set up data collection rules

**Analytics Configuration**:
- Enable/disable analytics rules
- Configure scheduled queries
- Set up ML-based detections

**Automation Settings**:
- Configure automation rules
- Set up playbooks
- Configure incident triggers

**Threat Intelligence**:
- Configure TI connectors
- Set up indicator feeds
- Configure indicator matching

### 6. Configure Logs

**Log Analytics Workspace Configuration**:

**Data Retention**:
- Default: 30 days (free for first 31 days)
- Can extend: 30 to 730 days (additional cost)
- Archive data: Up to 7 years (lower cost)

**Data Collection Rules (DCR)**:
- Define which data to collect
- Filter and transform data before ingestion
- Route data to specific destinations
- Reduce ingestion costs

**Table Management**:
- Basic logs: Lower-cost option for high-volume logs
- Analytics logs: Full query capabilities
- Archive logs: Long-term retention at lower cost

**Workspace Access Control**:
- Workspace-level RBAC
- Table-level RBAC
- Resource-context RBAC

**Query Performance**:
- Use time filters
- Limit search scope
- Optimize KQL queries
- Use summarize appropriately

---

## III. Query Logs in Microsoft Sentinel

### 1. Logs Page Overview

**Purpose**: Query and analyze log data in Microsoft Sentinel

**Log Analytics Query Interface**:
- **Table List** (left pane): All available tables
- **Query Editor** (top): Write and edit KQL queries
- **Results Pane** (bottom): View query results
- **Time Range Selector**: Scope data by time

**Key Features**:
- Syntax highlighting
- IntelliSense support
- Query sharing
- Save queries
- Pin to dashboard
- Export results (CSV, Excel)

### 2. Microsoft Sentinel Tables

**Table Organization**:

**Built-in Tables**:
- SecurityEvent
- Syslog
- SecurityAlert
- SecurityIncident
- CommonSecurityLog
- AzureActivity
- AzureDiagnostics

**Custom Tables**:
- Created via data collection
- Ingested through custom logs
- Parsed from unstructured data

**Table Schemas**:
- Each table has defined schema
- Columns with specific data types
- TimeGenerated column (common across tables)
- Use schema explorer to view structure

### 3. Common Tables

**SecurityEvent Table**:
- Windows security events
- Event ID-based filtering
- Account, computer, process information
- Login/logoff events
- Privilege use
- Security policy changes

**Example Query**:
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| summarize count() by Account, Computer
```

**Syslog Table**:
- Linux/Unix system logs
- Facility and severity filtering
- Process information
- System messages

**Example Query**:
```kql
Syslog
| where TimeGenerated > ago(1d)
| where Facility == "auth"
| where SeverityLevel == "err"
```

**SecurityAlert Table**:
- Alerts from various security products
- Microsoft Defender alerts
- Third-party security solutions
- Severity, status, classification

**Example Query**:
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertSeverity == "High"
| summarize count() by ProductName, AlertName
```

**SecurityIncident Table**:
- Microsoft Sentinel incidents
- Aggregated alerts
- Status and severity
- Owner and tags
- Investigation metadata

**Example Query**:
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "New"
| summarize count() by Severity, Classification
```

**CommonSecurityLog Table**:
- CEF (Common Event Format) logs
- Firewall logs
- Proxy logs
- IDS/IPS logs

**Example Query**:
```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor == "Palo Alto Networks"
| summarize count() by DeviceAction, DestinationIP
```

### 4. Microsoft 365 Defender Tables

**Integration Tables**:

**AlertEvidence**:
- Evidence from Defender XDR alerts
- Files, processes, users, devices
- Related to security alerts

**AlertInfo**:
- Alert metadata
- Title, severity, category
- Detection source

**DeviceEvents**:
- Endpoint events
- Process creation
- Network connections
- File modifications

**DeviceFileCertificateInfo**:
- File certificate information
- Signing information
- Certificate validity

**DeviceFileEvents**:
- File operations
- Creation, modification, deletion
- File hash information

**DeviceImageLoadEvents**:
- DLL and driver loading
- Image load operations

**DeviceLogonEvents**:
- Login events from endpoints
- Interactive, network, batch logons
- Success and failure events

**DeviceNetworkEvents**:
- Network connections from endpoints
- Source and destination IPs
- Ports and protocols

**DeviceProcessEvents**:
- Process creation events
- Command line information
- Parent-child relationships

**DeviceRegistryEvents**:
- Registry modifications
- Key and value changes

**EmailEvents**:
- Email metadata
- Sender, recipient, subject
- Delivery status

**EmailAttachmentInfo**:
- Email attachment details
- File names, hashes
- Detection results

**EmailPostDeliveryEvents**:
- Post-delivery actions
- Moved to junk, deleted
- User actions

**EmailUrlInfo**:
- URLs in emails
- URL analysis results
- Threat classifications

**IdentityLogonEvents**:
- Identity-based logon events
- Azure AD sign-ins
- Federated authentication

**Example Multi-Table Query**:
```kql
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe"
| join kind=inner (
    DeviceNetworkEvents
    | where TimeGenerated > ago(1h)
) on DeviceId, InitiatingProcessCreationTime
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, RemoteIP, RemotePort
```

---

## IV. Use Watchlists in Microsoft Sentinel

### 1. Plan for Watchlists

**Definition**: Collections of external data for correlation with Sentinel environment events

**Use Cases**:
- **High-Value Assets**: VIP users, sensitive systems
- **IP Address Lists**: Known good/bad IPs, VPN ranges
- **Service Accounts**: List of service accounts
- **Terminated Employees**: Recently terminated user accounts
- **Geographic Locations**: Office locations, data centers
- **Business Data**: Cost centers, business units

**Benefits**:
- Reduce false positives
- Enrich investigations
- Create custom detections
- Improve alert accuracy
- Simplify rule management

**Data Sources**:
- CSV files
- External systems
- Manual entry
- Automated updates

**Size Limits**:
- File uploads: Up to 3.8 MB
- Supports thousands of rows
- Can create multiple watchlists

### 2. Create Watchlist

**Creation Steps**:
1. Navigate: Microsoft Sentinel → Configuration → Watchlist
2. Select "Add new"
3. **General Page**:
   - Name
   - Description
   - Alias (for KQL queries)
4. Select "Next"
5. **Source Page**:
   - Select dataset type
   - Upload file (CSV format)
   - Preview data
6. Select "Next"
7. Review information
8. Select "Create"
9. Notification appears when watchlist ready

**CSV File Format**:
- First row: Column headers
- Subsequent rows: Data
- Use commas as delimiters
- Quote strings containing commas

**Example CSV**:
```csv
ComputerName,Owner,Department
SERVER01,John Doe,IT
SERVER02,Jane Smith,Finance
```

### 3. Use Watchlist in KQL

**Access Function**:
```kql
_GetWatchlist('watchlist_alias')
```

**Example Queries**:
```kql
// Get all watchlist data
_GetWatchlist('HighValueMachines')

// Join with other tables
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| join kind=inner (
    _GetWatchlist('HighValueMachines')
) on Computer
| project TimeGenerated, Computer, Account, Owner, Department

// Filter based on watchlist
let VIPUsers = _GetWatchlist('VIPUsers') | project UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in (VIPUsers)
| where ResultType != 0
| summarize FailedLogins=count() by UserPrincipalName, IPAddress
```

### 4. Manage Watchlists

**Management Operations**:

**Update Watchlist**:
- Edit watchlist details
- Upload new CSV file
- Add/remove items
- Modify column mappings

**Delete Watchlist**:
- Remove watchlist when no longer needed
- Check dependencies before deletion
- Remove references in analytics rules

**Version Control**:
- Track changes over time
- Maintain history of updates
- Audit watchlist modifications

**Automation**:
- Update via API
- Schedule automated updates
- Integrate with external systems
- Use Logic Apps for updates

**Best Practices**:
- Use descriptive names and aliases
- Document watchlist purpose
- Regular review and updates
- Remove obsolete entries
- Test queries before production use

---

## V. Utilize Threat Intelligence in Microsoft Sentinel

### 1. Define Threat Intelligence

**Cyber Threat Intelligence (CTI)**:

**Sources**:
- Open-source data feeds
- Threat intelligence-sharing communities
- Paid intelligence feeds
- Security investigations within organizations

**Intelligence Types**:
- Written reports (threat actor motivations, infrastructure, techniques)
- Specific observations (IP addresses, domains, file hashes)
- Tactical threat intelligence (most utilized in SIEM)

**Indicators of Compromise (IoCs)**:
- URLs
- File hashes
- IP addresses
- Domains
- Other data associated with known threat activity (phishing, botnets, malware)

**CTI in Microsoft Sentinel**:
- Detect malicious cyber activity
- Respond to threats
- Provide context for security operations

### 2. Integrate Threat Intelligence

**Integration Methods**:

**Data Connectors**:
- Connect to various TI platforms
- Import threat intelligence into Sentinel
- Supported platforms:
  - TAXII servers
  - Threat intelligence platforms (TIPs)
  - Microsoft Defender Threat Intelligence
  - Custom threat feeds

**View and Manage**:
- View in Logs (ThreatIntelligenceIndicator table)
- Threat Intelligence area in Sentinel
- Indicator management interface

**Analytics Rules**:
- Built-in templates for TI
- Generate alerts based on indicators
- Match indicators against logs

**Visualization**:
- Threat Intelligence workbook
- Critical TI information
- Indicator trends and statistics

**Threat Hunting**:
- Use imported TI for hunting
- Correlate indicators with logs
- Identify potential compromises

### 3. Manage Threat Indicators

**Indicator Management**:

**Add Indicators**:
- Manual creation
- Import via data connectors
- API integration
- Bulk upload

**Indicator Properties**:
- Indicator type (IP, domain, URL, file hash)
- Threat type (malware, phishing, C2, etc.)
- Confidence level
- Severity
- Valid from/until dates
- Tags and descriptions
- Source

**Indicator Actions**:
- View indicator details
- Edit indicator properties
- Disable/enable indicators
- Delete indicators
- Export indicators

**Indicator Matching**:
- Automatic matching with logs
- Generate alerts on matches
- Correlation across data sources

### 4. View Threat Indicators with KQL

**ThreatIntelligenceIndicator Table**:
```kql
// View all active indicators
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where Active == true
| summarize count() by ThreatType

// Get IP indicators
ThreatIntelligenceIndicator
| where TimeGenerated > ago(7d)
| where NetworkIP != ""
| project TimeGenerated, NetworkIP, ThreatType, ConfidenceScore, Description

// Match indicators with security events
let TIIPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(7d)
    | where NetworkIP != ""
    | project NetworkIP, ThreatType, ConfidenceScore;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationIP in (TIIPs)
| join kind=inner (TIIPs) on $left.DestinationIP == $right.NetworkIP
| project TimeGenerated, SourceIP, DestinationIP, ThreatType, ConfidenceScore

// Indicator statistics
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| summarize 
    TotalIndicators = count(),
    ActiveIndicators = countif(Active == true),
    HighConfidence = countif(ConfidenceScore >= 80)
    by ThreatType
| order by TotalIndicators desc
```

---

## VI. Integrate Microsoft Defender XDR with Microsoft Sentinel

### 1. Benefits of Integration

**Two Integration Methods**:

**Method 1: Defender XDR Connector Only**:
- Ingest Defender XDR data into Sentinel
- View Sentinel data in Azure portal
- Install Defender XDR connector in Sentinel

**Method 2: Unified Portal**:
- Integrate Sentinel and Defender XDR into single portal
- View Sentinel data in Defender portal
- View all Defender incidents, alerts, vulnerabilities
- Install connector + onboard Sentinel to unified operations platform

**Integration Architecture**:
- Signals from entire organization feed into Defender XDR and Defender for Cloud
- SIEM log data flows through Sentinel connectors
- SecOps teams analyze and respond in unified interface
- Multicloud support with third-party integration

### 2. Streamlined Operations

**Benefits**:
- Reduce complexity of managing multiple tools
- Save time switching between systems
- Reduce errors from context switching
- Single pane of glass for security operations

**Advanced Hunting**:
- Query from single portal across different datasets
- More efficient hunting
- No context switching needed
- Copilot for Security helps generate KQL queries
- View and query all data (Microsoft services + Sentinel)
- Use existing Sentinel workspace content (queries, functions)

### 3. Attack Disruption

**Automatic Attack Disruption**:
- Deploy for SAP with Microsoft Defender and Sentinel solution for SAP
- Contain compromised assets automatically
- Lock suspicious SAP users in financial process manipulation attacks
- Proactive threat containment

### 4. Unified Entities

**Entity Pages**:
- Devices, users, IP addresses, Azure resources
- Display information from both Sentinel and Defender data sources
- Expanded context for investigations
- Single view of entity across all data sources

### 5. Unified Incident Management

**Single Incident Queue**:
- Manage and investigate in one location
- Single queue in Defender portal
- Use Copilot for Security:
  - Summarize incidents
  - Respond to threats
  - Generate reports

**Incident Features**:
- Data from breadth of sources
- AI analytics from SIEM
- Context and mitigation from XDR
- Single workflow for all incidents

### 6. Capability Differences Between Portals

**Azure Portal (Sentinel)**:
- Full Sentinel configuration
- Workspace management
- Data connector configuration
- Custom content creation
- Advanced analytics rule authoring

**Defender Portal (Unified)**:
- Incident management
- Advanced hunting
- Entity investigations
- Automated investigations
- Response actions
- Threat analytics

**Best Practice**: Use Defender portal for day-to-day operations, Azure portal for configuration

### 7. Onboarding Sentinel to Defender XDR

**Prerequisites**:
- Microsoft Sentinel workspace
- Defender XDR license
- Appropriate permissions

**Onboarding Steps**:
1. Navigate to Microsoft Defender portal
2. Go to Settings → Microsoft Sentinel
3. Select "Connect workspace"
4. Choose Sentinel workspace
5. Review and confirm settings
6. Complete onboarding

**Post-Onboarding**:
- Sentinel data appears in Defender portal
- Incidents synchronized
- Unified hunting queries
- Integrated entity pages

### 8. Exploring Sentinel Features in Defender XDR

**Available Features**:

**Incidents**:
- View Sentinel incidents alongside Defender incidents
- Single incident queue
- Unified investigation experience

**Advanced Hunting**:
- Query Sentinel tables
- Use existing Sentinel queries
- Create cross-product queries
- Leverage Copilot assistance

**Threat Intelligence**:
- View indicators from both sources
- Unified indicator management
- Integrated threat analytics

**Entities**:
- Enhanced entity pages
- Consolidated information
- Cross-product context

**Automation**:
- Trigger playbooks from Defender portal
- Unified automation rules
- Integrated response actions

---

## Summary

This comprehensive module covers Microsoft Sentinel environment configuration across six major areas:

**I. Introduction to Microsoft Sentinel**:
- Cloud-native SIEM system with no server installation
- Core capabilities: Collect data, detect threats, investigate, automate responses
- Key components: Data connectors, log retention, workbooks, analytics, hunting, incidents, playbooks
- End-to-end security operations (collection, detection, investigation, response)

**II. Create and Manage Workspaces**:
- Three implementation options: Single-tenant single workspace, regional workspaces, multi-tenant
- Workspace planning considerations: Region, data governance, bandwidth costs
- Azure Lighthouse for cross-tenant management
- Four Sentinel-specific RBAC roles (Reader, Responder, Contributor, Automation Contributor)
- Additional role requirements for playbooks, data connectors, guest users, workbooks

**III. Query Logs**:
- Logs page interface: Table list, query editor, results pane
- Built-in tables: SecurityEvent, Syslog, SecurityAlert, SecurityIncident, CommonSecurityLog
- Microsoft 365 Defender tables: AlertEvidence, DeviceEvents, EmailEvents, IdentityLogonEvents (15+ tables)
- Multi-table correlation capabilities

**IV. Use Watchlists**:
- Collections of external data for correlation (high-value assets, IPs, service accounts)
- Create from CSV files (up to 3.8 MB)
- Access via `_GetWatchlist('alias')` function in KQL
- Management: Update, delete, version control, automation
- Reduce false positives and enrich investigations

**V. Utilize Threat Intelligence**:
- CTI sources: Open-source feeds, communities, paid feeds, internal investigations
- Indicators of Compromise (IoCs): URLs, file hashes, IPs, domains
- Integration via data connectors (TAXII, TIPs, Defender TI)
- ThreatIntelligenceIndicator table for KQL queries
- Analytics rules for automatic indicator matching

**VI. Integrate Defender XDR**:
- Two integration methods: Connector only vs. Unified portal
- Benefits: Streamlined operations, advanced hunting, attack disruption
- Unified entities and incident management
- Copilot for Security integration
- Single pane of glass for security operations

**Key Takeaways**:
- **Cloud-Native**: No infrastructure management, elastic scalability
- **Flexible Deployment**: Single or multi-workspace, multi-tenant support
- **RBAC**: Fine-grained access control with built-in roles
- **Rich Querying**: KQL for powerful log analysis across all tables
- **External Data**: Watchlists for correlation and enrichment
- **Threat Intelligence**: Built-in TI integration and indicator matching
- **Unified Operations**: Seamless integration with Defender XDR
- **Automation**: Playbooks and Logic Apps for automated response
- **Scalability**: Pay-as-you-go pricing, grow with your needs

**Best Practices**:
- Plan workspace architecture based on data governance and costs
- Use appropriate RBAC roles (principle of least privilege)
- Leverage watchlists for high-value asset tracking
- Integrate threat intelligence feeds for enhanced detection
- Use unified Defender XDR portal for day-to-day operations
- Configure retention policies based on compliance requirements
- Implement cross-workspace queries for regional deployments
- Regular review and update of watchlists and threat indicators

**Common Patterns**:
```kql
// Cross-workspace query
SecurityEvent
| union workspace("WorkspaceName").SecurityEvent
| where TimeGenerated > ago(7d)

// Watchlist correlation
_GetWatchlist('HighValueAssets')
| join kind=inner (SecurityEvent) on Computer

// Threat intelligence matching
let ThreatIPs = ThreatIntelligenceIndicator
    | where NetworkIP != ""
    | project NetworkIP;
CommonSecurityLog
| where DestinationIP in (ThreatIPs)
```
