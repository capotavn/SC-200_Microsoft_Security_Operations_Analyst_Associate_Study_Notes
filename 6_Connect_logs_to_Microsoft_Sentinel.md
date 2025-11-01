# SC-200: Connect logs to Microsoft Sentinel

## I. Connect Data Using Data Connectors

### 1. Ingest Log Data with Data Connectors

**Purpose**: Collect log data from various sources into Microsoft Sentinel

**Content Hub Solutions**:
- Data Connectors included with Content Hub Solutions
- Install solutions from Microsoft Sentinel
- Installed connectors appear: Configuration → Data connectors

**Connector Page Layout**:

**Left Half**:
- Connector information
- Connector status
- Last log received timestamp
- **Data Types section**: Lists tables connector writes to

**Right Half**:
- **Instructions tab**: Prerequisites and Configuration steps
- **Next steps tab**: Quick reference to workbooks, query samples, analytical templates

**Important Notes**:
- Follow Configuration steps to connect data source
- Connectors can be disconnected/deactivated, not deleted
- Content Hub solutions may also install: Workbooks, Analytics rules, Hunting queries
- Out-of-box connector templates already available in Sentinel

### 2. Data Connector Providers

**Microsoft Defender XDR**:
- Single connector for all Defender products
- Provides: Alerts, incidents, raw data
- Included products:
  - Microsoft Defender for Endpoint
  - Microsoft Defender for Identity
  - Microsoft Defender for Office 365
  - Microsoft Defender for Cloud Apps

**Microsoft Azure Services**:
- Microsoft Entra ID (Azure AD)
- Azure Activity
- Microsoft Entra ID Protection
- Azure DDoS Protection
- Microsoft Defender for IoT
- Azure Information Protection
- Azure Firewall
- Microsoft Defender for Cloud
- Azure Web Application Firewall (WAF)
- Domain Name Server
- Office 365
- Windows Firewall
- Security Events

**Vendor Connectors**:
- Ever-growing list of vendor-specific connectors
- Primarily use CEF and Syslog as foundation
- Check connector page for Data Type (table) information

**Custom Connectors**:
- **Log Analytics API**: Send log data to Log Analytics workspace
- **Logstash Plugin**: Send any log through Logstash to workspace (writes to custom table)

**Generic Connectors**:

**Common Event Format (CEF)**:
- Industry-standard format on top of Syslog
- Used by many security vendors
- Event interoperability among platforms
- **Advantage**: Parsed into predefined fields in CommonSecurityLog table

**Syslog**:
- Event logging protocol common to Linux
- Applications send messages to local machine or Syslog collector
- **Limitation**: Raw log in SyslogMessage field, requires parser for field extraction

**CEF vs Syslog**:
- **CEF is superior choice**: Pre-parsed into fields
- **Syslog**: Requires custom parser for querying specific fields

### 3. Connector Architecture Options

**Agent Deployment**:
- Deploy on dedicated Azure VM or on-premises system
- Supports appliance communication with Sentinel

**Automatic Deployment** (available when):
- Dedicated machine connected to Azure Arc OR
- Virtual Machine in Azure

**Manual Deployment**:
- Existing Azure VM
- VM in another cloud
- On-premises machine

**Architecture 1 - Azure VM**:
```
On-premises systems → Syslog data → Dedicated Azure VM (Sentinel agent) → Microsoft Sentinel
```

**Architecture 2 - On-premises**:
```
On-premises systems → Syslog data → Dedicated on-premises system (Sentinel agent) → Microsoft Sentinel
```

### 4. View Connected Hosts

**Monitoring Connected Data Sources**:
- View connector status in Data connectors page
- Check last log received timestamp
- Monitor data ingestion volume
- Verify connectivity health

**Data Validation**:
- Query tables to verify data ingestion
- Check Data Types section for table names
- Use KQL to validate data flow

---

## II. Connect Microsoft Services

### 1. Plan for Microsoft Services Connectors

**Planning Considerations**:
- Identify required Microsoft services
- Determine data types needed
- Evaluate licensing requirements
- Plan for data retention
- Consider data volume and costs

**Prerequisites**:
- Appropriate permissions on source services
- Microsoft Sentinel workspace access
- Service-specific configurations

### 2. Office 365 Connector

**Data Collected**:
- Exchange audit logs
- SharePoint audit logs
- Teams audit logs
- User activities
- Admin activities

**Configuration**:
1. Install Office 365 Content Hub solution
2. Navigate to Data connectors → Office 365
3. Select "Open connector page"
4. Check prerequisites
5. Enable logs for desired services (Exchange, SharePoint, Teams)
6. Apply changes

**Tables**:
- OfficeActivity table

**Use Cases**:
- Track user file access
- Monitor admin changes
- Detect suspicious activities
- Compliance auditing

### 3. Microsoft Entra ID (Azure AD) Connector

**Data Collected**:
- Sign-in logs
- Audit logs
- User risk events
- Non-interactive sign-ins
- Service principal sign-ins
- Managed identity sign-ins

**Configuration**:
1. Install Microsoft Entra ID Content Hub solution
2. Navigate to Data connectors → Microsoft Entra ID
3. Select log types to stream:
   - Sign-in logs
   - Audit logs
   - Non-interactive user sign-in logs
   - Service principal sign-in logs
   - Managed Identity sign-in logs
   - Provisioning logs
4. Apply changes

**Tables**:
- SigninLogs
- AuditLogs
- AADNonInteractiveUserSignInLogs
- AADServicePrincipalSignInLogs
- AADManagedIdentitySignInLogs

**Prerequisites**:
- Azure AD Premium P1 or P2 license
- Global Administrator or Security Administrator role

### 4. Microsoft Entra ID Identity Protection Connector

**Data Collected**:
- Risk detections
- Risky users
- Risky sign-ins

**Configuration**:
1. Navigate to Data connectors → Microsoft Entra ID Identity Protection
2. Select "Connect"
3. Choose data types
4. Apply

**Tables**:
- SecurityAlert (alerts from Identity Protection)

**Prerequisites**:
- Azure AD Premium P2 license
- Global Administrator or Security Administrator role

**Use Cases**:
- Monitor identity risks
- Detect compromised accounts
- Track risk events
- Automated response to identity threats

### 5. Azure Activity Connector

**Data Collected**:
- Subscription-level events
- Resource operations
- Service health events
- Azure Resource Manager operations
- Administrative activities

**Configuration**:
1. Navigate to Data connectors → Azure Activity
2. Launch configuration wizard
3. Select subscriptions to connect
4. Apply

**Table**:
- AzureActivity

**Use Cases**:
- Track resource changes
- Monitor administrative actions
- Detect unauthorized operations
- Compliance reporting

---

## III. Connect Microsoft Defender XDR

### 1. Plan for Microsoft Defender XDR Connectors

**Connector Options**:
- Microsoft Defender XDR (unified connector)
- Microsoft Defender for Cloud
- Microsoft Defender for IoT
- Legacy individual connectors (deprecated)

**Planning Considerations**:
- Use unified Defender XDR connector (recommended)
- Avoid duplicate data ingestion
- Consider incident integration
- Plan for bi-directional sync

### 2. Microsoft Defender XDR Connector

**Data Collected**:
- Incidents (synchronized bi-directionally)
- Alerts
- Advanced hunting events (raw data)
- Device, email, identity, app events

**Configuration**:
1. Navigate to Data connectors → Microsoft Defender XDR
2. Prerequisites: Enable Defender XDR
3. Configuration:
   - Connect incidents & alerts
   - Select data tables (Advanced hunting)
   - Enable bi-directional sync
4. Apply

**Tables** (Advanced Hunting):
- DeviceEvents
- DeviceFileEvents
- DeviceImageLoadEvents
- DeviceLogonEvents
- DeviceNetworkEvents
- DeviceProcessEvents
- DeviceRegistryEvents
- DeviceFileCertificateInfo
- DeviceInfo
- EmailEvents
- EmailAttachmentInfo
- EmailUrlInfo
- EmailPostDeliveryEvents
- IdentityLogonEvents
- IdentityQueryEvents
- IdentityDirectoryEvents
- CloudAppEvents
- AlertEvidence
- AlertInfo

**Bi-directional Sync**:
- Incidents created in Sentinel sync to Defender XDR
- Incidents created in Defender XDR sync to Sentinel
- Updates synchronized in both directions

### 3. Microsoft Defender for Cloud Connector

**Data Collected**:
- Security alerts from Defender for Cloud
- Azure Security Center alerts
- Recommendations (optional)
- Secure score data

**Configuration**:
1. Navigate to Data connectors → Microsoft Defender for Cloud
2. Select subscriptions to connect
3. Choose: Bi-directional sync (recommended)
4. Apply

**Table**:
- SecurityAlert

**Integration Benefits**:
- Unified alert management
- Correlation with other data sources
- Automated response capabilities

### 4. Microsoft Defender for IoT Connector

**Data Collected**:
- IoT device alerts
- OT (Operational Technology) alerts
- Device inventory
- Vulnerability information

**Configuration**:
1. Navigate to Data connectors → Microsoft Defender for IoT
2. Prerequisites: Defender for IoT deployed
3. Connect subscriptions
4. Apply

**Table**:
- SecurityAlert (IoT alerts)

**Use Cases**:
- Monitor IoT/OT environments
- Detect IoT threats
- Track device vulnerabilities

### 5. Legacy Connectors (Deprecated)

**Note**: Microsoft recommends using unified Microsoft Defender XDR connector

**Legacy Connectors** (being phased out):
- Microsoft Defender for Endpoint (standalone)
- Microsoft Defender for Identity (standalone)
- Microsoft Defender for Office 365 (standalone)
- Microsoft Defender for Cloud Apps (standalone)

**Migration Path**:
- Disconnect legacy connectors
- Enable unified Microsoft Defender XDR connector
- Verify data flow

---

## IV. Connect Windows Hosts

### 1. Plan for Windows Hosts Security Events

**Windows Security Events Connector**:
- Collects Windows security events
- Uses Azure Monitor Agent (AMA)
- Replaces legacy Log Analytics agent

**Event Sets**:
- **All events**: All Windows security and AppLocker events
- **Common**: Standard set of events for auditing
- **Minimal**: Small set of events (may not provide complete audit trail)
- **None**: No security or AppLocker events
- **Custom**: Define specific event IDs

**Planning Considerations**:
- Balance between data volume and visibility
- Compliance requirements
- Cost vs. benefit analysis
- Use Data Collection Rules (DCR) for filtering

### 2. Configure Data Collection Rules (DCR)

**Purpose**: Define what data to collect and how to transform it

**DCR Components**:
- **Data sources**: What to collect (Windows Event Logs)
- **Destinations**: Where to send data (Log Analytics workspace)
- **Transformations**: Filter and transform data before ingestion

**Create DCR**:
1. Navigate to Azure Monitor → Data Collection Rules
2. Create new DCR
3. Configure:
   - Name and resource group
   - Data source: Windows Event Logs
   - Event filters (XPath queries)
   - Destination: Log Analytics workspace
4. Create

**Event Filtering (XPath)**:
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4625)]]</Select>
  </Query>
</QueryList>
```

**Benefits**:
- Reduce ingestion costs
- Filter irrelevant events
- Transform data before storage
- Reusable across multiple machines

### 3. Connect Windows Hosts

**Connection Methods**:

**Azure VMs**:
- Automatic via Azure Policy
- Manual via VM extensions
- Bulk deployment via Arc

**Non-Azure Machines**:
- Azure Arc-enabled servers
- Manual agent installation

**Steps**:
1. Navigate to Data connectors → Windows Security Events via AMA
2. Create Data Collection Rule
3. Select event set or custom XPath
4. Add resources (VMs or Azure Arc machines)
5. Review and create

**Verification**:
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count() by Computer
```

### 4. Collect Sysmon Event Logs

**Sysmon Overview**:
- System Monitor (Sysmon) - Windows system service
- Monitors and logs system activity
- Detailed process, network, file activity information

**Sysmon Events**:
- Process creation (Event ID 1)
- File creation time (Event ID 2)
- Network connections (Event ID 3)
- Sysmon service state (Event ID 4)
- Process termination (Event ID 5)
- Driver loaded (Event ID 6)
- And many more...

**Prerequisites**:
1. Install Sysmon on Windows hosts
2. Configure Sysmon with XML config file
3. Sysmon logs to: Microsoft-Windows-Sysmon/Operational

**Configure DCR for Sysmon**:
1. Create/edit Data Collection Rule
2. Add data source: Windows Event Logs
3. Specify: Microsoft-Windows-Sysmon/Operational
4. Configure XPath (or select all)
5. Save

**XPath Example**:
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
  </Query>
</QueryList>
```

**Query Sysmon Data**:
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where TimeGenerated > ago(1d)
| project TimeGenerated, Computer, EventID, EventData
```

**Use Cases**:
- Advanced threat hunting
- Process execution tracking
- Network connection monitoring
- Malware analysis

---

## V. Connect Common Event Format (CEF) Logs

### 1. Plan for CEF Connector

**Common Event Format**:
- Industry-standard format
- Built on top of Syslog
- Used by many security vendors
- Structured log format

**CEF Advantages**:
- Pre-parsed fields
- Standardized format
- Easy querying
- Better performance than raw Syslog

**Supported Appliances**:
- Firewalls (Check Point, Palo Alto, Fortinet, Cisco ASA)
- IDS/IPS systems
- Proxies
- Security appliances
- Network devices

**Architecture Requirements**:
- Linux-based log forwarder
- Azure Monitor Agent
- Network connectivity to appliances
- Network connectivity to Sentinel

### 2. Connect External Solution Using CEF

**Deployment Options**:

**Option 1: Azure VM**:
- Deploy Linux VM in Azure
- Install Azure Monitor Agent
- Configure rsyslog/syslog-ng

**Option 2: On-premises**:
- Use existing Linux server
- Install Azure Monitor Agent
- Configure rsyslog/syslog-ng

**Configuration Steps**:

**Step 1: Deploy Log Forwarder**
```bash
# Update system
sudo apt-get update

# Install rsyslog
sudo apt-get install rsyslog
```

**Step 2: Configure Syslog Daemon**

Edit `/etc/rsyslog.conf`:
```
# Provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

# CEF forwarding
*.* @@127.0.0.1:25226
```

**Step 3: Install Azure Monitor Agent**
- Via Azure portal (VM extensions)
- Via Arc for non-Azure machines
- Via deployment script

**Step 4: Create Data Collection Rule**
1. Navigate to Data Collection Rules
2. Create new DCR
3. Data source: Linux Syslog
4. Select facilities and log levels
5. Destination: Log Analytics workspace

**Step 5: Configure Appliance**
- Point appliance to send CEF logs to Linux forwarder IP:514
- Use TCP (recommended) or UDP
- Test connectivity

**Verification**:
```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| summarize count() by DeviceVendor, DeviceProduct
```

**Troubleshooting**:
```bash
# Check rsyslog status
sudo systemctl status rsyslog

# Check rsyslog logs
sudo tail -f /var/log/syslog

# Test TCP listener
sudo netstat -an | grep 514

# Verify AMA agent
sudo systemctl status azuremonitoragent
```

---

## VI. Connect Syslog Data Sources

### 1. Plan for Syslog Connector

**Syslog Overview**:
- Event logging protocol
- Common to Linux/Unix systems
- Applications send messages to collector

**Syslog vs CEF**:
- Syslog: Raw format, requires parsing
- CEF: Structured format, pre-parsed

**When to Use Syslog Connector**:
- Linux/Unix system logs
- Network devices without CEF support
- Custom applications
- Legacy systems

**Facilities**:
- auth, authpriv (authentication)
- cron (scheduled tasks)
- daemon (system daemons)
- kern (kernel messages)
- syslog (syslog daemon)
- user (user-level messages)
- local0-local7 (custom)

**Severity Levels**:
- emerg (0) - Emergency
- alert (1) - Alert
- crit (2) - Critical
- err (3) - Error
- warning (4) - Warning
- notice (5) - Notice
- info (6) - Informational
- debug (7) - Debug

### 2. Collect Data from Linux-Based Sources

**Architecture**:
```
Linux sources → Syslog → Log forwarder (AMA) → Microsoft Sentinel
```

**Configuration Steps**:

**Step 1: Configure Source Systems**
Edit `/etc/rsyslog.conf` on source:
```
*.* @@<forwarder-IP>:514
```

**Step 2: Configure Log Forwarder**
Edit `/etc/rsyslog.conf` on forwarder:
```
# Enable reception
module(load="imtcp")
input(type="imtcp" port="514")

# Forward to AMA
*.* @@127.0.0.1:28330
```

**Step 3: Restart Rsyslog**
```bash
sudo systemctl restart rsyslog
```

### 3. Configure Log Analytics Agent (Legacy)

**Note**: Log Analytics agent is deprecated. Use Azure Monitor Agent (AMA).

**Migration Path**:
- Plan migration to AMA
- Create Data Collection Rules
- Deploy AMA to machines
- Remove Log Analytics agent

### 4. Parse Syslog Data

**Why Parse**:
- Extract specific fields
- Make data queryable
- Improve analytics
- Reduce query complexity

**Parsing Methods**:

**Method 1: KQL Parse**
```kql
Syslog
| where Facility == "auth"
| parse SyslogMessage with * "user=" User " " *
| project TimeGenerated, Computer, User, SyslogMessage
```

**Method 2: Extract**
```kql
Syslog
| extend User = extract("user=([^\\s]+)", 1, SyslogMessage)
| project TimeGenerated, Computer, User
```

**Method 3: Custom Parser Function**
```kql
let ParseSyslog = (T:(SyslogMessage:string)) {
    T
    | parse SyslogMessage with * "user=" User " " "pid=" PID " " *
    | project-away SyslogMessage
};
Syslog
| invoke ParseSyslog()
```

**Save as Function**:
1. Write parser query
2. Select "Save" → "Save as function"
3. Name function (e.g., "ParseAuthLog")
4. Use in queries: `Syslog | invoke ParseAuthLog()`

**Best Practices**:
- Test parsers thoroughly
- Handle variations in log format
- Document parser logic
- Version control parser functions

---

## VII. Connect Threat Indicators

### 1. Plan for Threat Intelligence Connectors

**Threat Intelligence Types**:
- **STIX/TAXII**: Structured Threat Information eXpression
- **CSV Import**: Manual indicator upload
- **API Import**: Programmatic indicator import
- **Platform Integration**: Third-party TI platforms

**Connector Options**:
- Microsoft Defender Threat Intelligence
- Threat Intelligence - TAXII
- Threat Intelligence Upload Indicators API
- Third-party TI platform connectors

**Planning Considerations**:
- Source reliability
- Update frequency
- Data volume
- Cost implications
- Indicator lifespan

### 2. Microsoft Defender Threat Intelligence Connector

**Data Provided**:
- Microsoft-generated indicators
- High-confidence threats
- Malicious IPs, domains, URLs
- File hashes
- Automatic updates

**Configuration**:
1. Navigate to Data connectors → Microsoft Defender Threat Intelligence
2. Prerequisites: Defender Threat Intelligence license
3. Select "Connect"
4. Choose indicator types
5. Apply

**Tables**:
- ThreatIntelligenceIndicator

**Benefits**:
- Microsoft's global threat intelligence
- Automatic updates
- High-quality indicators
- No manual maintenance

### 3. Threat Intelligence - TAXII Connector

**TAXII Protocol**:
- Trusted Automated eXchange of Indicator Information
- Standard protocol for CTI sharing
- Server-client model

**Configuration**:
1. Navigate to Data connectors → Threat Intelligence - TAXII
2. Configuration:
   - **Friendly name**: Connector name
   - **API root URL**: TAXII server URL
   - **Collection ID**: TAXII collection identifier
   - **Username**: Authentication username
   - **Password**: Authentication password
   - **Import Indicators**: Look-back period (hours)
   - **Polling frequency**: How often to check (minutes)
3. Add
4. Test connection

**Example TAXII Servers**:
- AlienVault OTX
- MISP
- Anomali ThreatStream
- Custom TAXII servers

**Table**:
- ThreatIntelligenceIndicator

**Supported TAXII Versions**:
- TAXII 2.0
- TAXII 2.1

### 4. Threat Intelligence Upload Indicators API

**Purpose**: Programmatically upload custom threat indicators

**Use Cases**:
- Internal threat intelligence
- Custom indicator sources
- Automated indicator management
- Integration with SIEM/SOAR

**API Configuration**:
1. Register application in Azure AD
2. Grant permissions: ThreatIndicators.ReadWrite.OwnedBy
3. Generate client secret
4. Note: Tenant ID, Application ID, Client secret

**Upload Indicators via API**:

**Authentication**:
```python
import requests

tenant_id = "your-tenant-id"
client_id = "your-client-id"
client_secret = "your-client-secret"

token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
token_data = {
    'grant_type': 'client_credentials',
    'client_id': client_id,
    'client_secret': client_secret,
    'scope': 'https://graph.microsoft.com/.default'
}

token_response = requests.post(token_url, data=token_data)
access_token = token_response.json()['access_token']
```

**Upload Indicator**:
```python
import json

indicator_url = "https://graph.microsoft.com/beta/security/tiIndicators"
headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

indicator_data = {
    "action": "alert",
    "confidence": 80,
    "description": "Malicious IP from internal investigation",
    "expirationDateTime": "2024-12-31T00:00:00Z",
    "networkIPv4": "192.0.2.1",
    "threatType": "MaliciousIp",
    "tlpLevel": "amber"
}

response = requests.post(indicator_url, headers=headers, json=indicator_data)
print(response.json())
```

**Indicator Properties**:
- action (alert, allow, block)
- confidence (0-100)
- description
- expirationDateTime
- Indicator value (IP, domain, URL, file hash)
- threatType
- tlpLevel (white, green, amber, red)

**Bulk Upload**:
```python
indicators = [
    {
        "action": "alert",
        "confidence": 90,
        "networkIPv4": "192.0.2.1",
        "threatType": "MaliciousIp"
    },
    {
        "action": "alert",
        "confidence": 85,
        "domainName": "evil.com",
        "threatType": "Phishing"
    }
]

for indicator in indicators:
    response = requests.post(indicator_url, headers=headers, json=indicator)
    print(f"Uploaded: {indicator}")
```

### 5. View Threat Indicators

**Query Indicators**:
```kql
// View all indicators
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| summarize count() by ThreatType, ConfidenceScore

// View active indicators by source
ThreatIntelligenceIndicator
| where TimeGenerated > ago(7d)
| where Active == true
| summarize count() by SourceSystem

// Get specific indicator types
ThreatIntelligenceIndicator
| where ThreatType == "MaliciousIp"
| where ConfidenceScore > 80
| project TimeGenerated, NetworkIP, Description, ConfidenceScore

// Match indicators with security events
let MaliciousIPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(7d)
    | where ThreatType == "MaliciousIp"
    | project NetworkIP;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationIP in (MaliciousIPs)
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction
```

**Workbook Visualization**:
- Navigate to Workbooks → Threat Intelligence
- View indicator statistics
- Monitor indicator sources
- Track indicator lifecycle

**Analytics Rules**:
- Create rules to alert on indicator matches
- Automatic correlation with logs
- Generate incidents for matches

---

## Summary

This comprehensive module covers connecting logs to Microsoft Sentinel across seven major areas:

**I. Data Connectors Overview**:
- Content Hub Solutions for connector installation
- Connector page layout (status, data types, instructions)
- Provider types (Defender XDR, Azure services, vendor, custom)
- CEF vs Syslog (CEF superior - pre-parsed fields)
- Architecture options (Azure VM or on-premises forwarder)

**II. Microsoft Services Connectors**:
- Office 365 (Exchange, SharePoint, Teams audit logs)
- Microsoft Entra ID (sign-in, audit, risk logs)
- Entra ID Identity Protection (risk detections)
- Azure Activity (subscription-level events)
- Prerequisites and configuration steps for each

**III. Microsoft Defender XDR Connectors**:
- Unified Defender XDR connector (recommended)
- 20+ advanced hunting tables
- Bi-directional incident sync
- Defender for Cloud, IoT connectors
- Legacy connector migration

**IV. Windows Hosts**:
- Security Events via Azure Monitor Agent
- Data Collection Rules (DCR) for filtering
- Event sets (All, Common, Minimal, Custom)
- Sysmon configuration and collection
- XPath filtering for cost optimization

**V. Common Event Format (CEF)**:
- Linux log forwarder architecture
- Rsyslog/syslog-ng configuration
- Azure Monitor Agent deployment
- DCR creation for CEF logs
- Appliance configuration and troubleshooting

**VI. Syslog Connectors**:
- Facilities and severity levels
- Linux source configuration
- Log forwarder setup
- Syslog data parsing (parse, extract, functions)
- Migration from Log Analytics agent to AMA

**VII. Threat Intelligence**:
- Four connector types (Defender TI, TAXII, Upload API, platforms)
- TAXII 2.0/2.1 configuration
- API-based indicator upload with Python examples
- Bulk upload scenarios
- Query and correlate indicators with logs

**Key Takeaways**:
- **Multiple Connector Types**: Choose appropriate connector for data source
- **Azure Monitor Agent**: Modern agent replacing Log Analytics agent
- **Data Collection Rules**: Essential for filtering and cost optimization
- **CEF Preferred**: Better than Syslog for structured data
- **Bi-directional Sync**: Defender XDR integration supports two-way sync
- **Threat Intelligence**: Multiple ingestion methods for maximum flexibility
- **Pre-parsing**: Use CEF/structured formats when possible to avoid custom parsing
- **Architecture Planning**: Consider Azure VM vs on-premises for forwarders

**Best Practices**:
- Use Azure Monitor Agent instead of legacy Log Analytics agent
- Implement Data Collection Rules for cost optimization
- Choose CEF over Syslog when available
- Use unified Defender XDR connector (not legacy connectors)
- Filter events at source using XPath or DCR
- Parse Syslog data into reusable functions
- Regularly update threat intelligence feeds
- Monitor connector health and data ingestion
- Test connectivity before production deployment
- Document custom parsers and configurations

**Cost Optimization**:
- Use DCRs to filter unnecessary events
- Select appropriate event sets (not "All" unless needed)
- Implement XPath filtering for Windows events
- Parse only required Syslog facilities
- Set appropriate TI indicator expiration
- Monitor ingestion volume regularly

**Common Patterns**:
```kql
// Verify connector data flow
SecurityEvent | where TimeGenerated > ago(1h) | count
CommonSecurityLog | where TimeGenerated > ago(1h) | summarize by DeviceVendor
Syslog | where TimeGenerated > ago(1h) | summarize by Facility

// Parse custom Syslog
Syslog
| parse SyslogMessage with * "user=" User " " "src=" SourceIP " " *
| project TimeGenerated, Computer, User, SourceIP

// Match threat indicators
let ThreatIPs = ThreatIntelligenceIndicator | where NetworkIP != "" | project NetworkIP;
CommonSecurityLog | where DestinationIP in (ThreatIPs)
```
