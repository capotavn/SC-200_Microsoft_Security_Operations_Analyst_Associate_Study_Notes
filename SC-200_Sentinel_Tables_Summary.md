# Microsoft Sentinel Tables - SC-200 Quick Reference

> **Bảng tra cứu nhanh các Tables trong Microsoft Sentinel cho khóa SC-200**

---

## 📊 Bảng tổng hợp đầy đủ

| Product | Tên Table | Data Connector | Nguồn Log / Mô tả | Billable | License Required | Use Case |
|---------|-----------|----------------|-------------------|----------|------------------|----------|
| **MDE** | DeviceLogonEvents | Microsoft Defender XDR | Device logon/authentication events | Yes | M365 E5 / Defender for Endpoint | Authentication monitoring, lateral movement detection |
| **MDE** | DeviceProcessEvents | Microsoft Defender XDR | Process creation và related events | Yes | M365 E5 / Defender for Endpoint | Process monitoring, malware execution detection |
| **MDE** | DeviceNetworkEvents | Microsoft Defender XDR | Network connections từ endpoints | Yes | M365 E5 / Defender for Endpoint | Network traffic analysis, C2 detection |
| **MDE** | DeviceNetworkInfo | Microsoft Defender XDR | Network properties của devices | Yes | M365 E5 / Defender for Endpoint | Network inventory, device profiling |
| **MDE** | DeviceFileEvents | Microsoft Defender XDR | File creation, modification, deletion events | Yes | M365 E5 / Defender for Endpoint | File activity monitoring, ransomware detection |
| **MDE** | DeviceRegistryEvents | Microsoft Defender XDR | Registry modifications | Yes | M365 E5 / Defender for Endpoint | Persistence detection, malware analysis |
| **MDE** | DeviceEvents | Microsoft Defender XDR | Multiple event types, Windows Defender Antivirus | Yes | M365 E5 / Defender for Endpoint | General endpoint events, AV detections |
| **MDE** | DeviceInfo | Microsoft Defender XDR | Device information (OS, hardware, config) | Yes | M365 E5 / Defender for Endpoint | Asset inventory, compliance checking |
| **MDE** | DeviceImageLoadEvents | Microsoft Defender XDR | DLL loading events | Yes | M365 E5 / Defender for Endpoint | DLL injection detection, code execution analysis |
| **MDE** | DeviceFileCertificateInfo | Microsoft Defender XDR | Certificate information của signed files | Yes | M365 E5 / Defender for Endpoint | Trust verification, malware identification |
| **MDE** | DeviceTvmSoftwareInventory | Microsoft Defender XDR | Software inventory trên devices | Yes | M365 E5 / Defender for Endpoint | Vulnerability management, software tracking |
| **MDE** | DeviceTvmSoftwareVulnerabilities | Microsoft Defender XDR | Software vulnerabilities discovered | Yes | M365 E5 / Defender for Endpoint | Risk assessment, patch prioritization |
| **MDO** | EmailEvents | Microsoft Defender XDR | Email delivery và blocking events | Yes | **Defender for Office 365 P2** | Email security monitoring, phishing detection |
| **MDO** | EmailAttachmentInfo | Microsoft Defender XDR | Information về email attachments | Yes | **Defender for Office 365 P2** | Malware analysis, attachment tracking |
| **MDO** | EmailUrlInfo | Microsoft Defender XDR | URL information trong emails | Yes | **Defender for Office 365 P2** | URL reputation, phishing link detection |
| **MDO** | EmailPostDeliveryEvents | Microsoft Defender XDR | Security events sau delivery (ZAP, user reported) | Yes | **Defender for Office 365 P2** | Post-delivery protection, remediation tracking |
| **MDO** | UrlClickEvents | Microsoft Defender XDR | URL clicks, selections trong Office 365 | Yes | **Defender for Office 365 P2** | User behavior, Safe Links monitoring |
| **MDI** | IdentityLogonEvents | Microsoft Defender XDR | Authentication activities (On-prem AD + Azure AD) | Yes | **M365 E5 Security / MDI** | Identity compromise detection, logon monitoring |
| **MDI** | IdentityDirectoryEvents | Microsoft Defender XDR | Directory events (password resets, group changes) | Yes | **M365 E5 Security / MDI** | AD change monitoring, privilege escalation |
| **MDI** | IdentityQueryEvents | Microsoft Defender XDR | Query events (SAMR, DNS, LDAP queries) | Yes | **M365 E5 Security / MDI** | Reconnaissance detection, enumeration activities |
| **MDI** | IdentityInfo | Microsoft Defender XDR | Account information (AD + Azure AD) | Yes | **M365 E5 Security / MDI** | Identity correlation, account tracking |
| **MCAS** | CloudAppEvents | Microsoft Defender XDR | Cloud app activities (Office 365, SaaS apps) | Yes | Defender for Cloud Apps | Cloud app monitoring, DLP events |
| **MCAS** | McasShadowItReporting | Defender for Cloud Apps | Shadow IT discovery reports | Yes | Defender for Cloud Apps | Unsanctioned app discovery |
| **Alerts** | SecurityAlert | Multiple (unified) | Alerts từ tất cả Microsoft security products | **No** | N/A | Unified alert management, threat detection |
| **Alerts** | SecurityIncident | Multiple (unified) | Incidents từ Sentinel và M365 Defender | **No** | N/A | Incident management, SOC operations |
| **Alerts** | SecurityRecommendation | Defender for Cloud | Security recommendations cho Azure resources | **No** | N/A | Security posture, remediation guidance |
| **Azure AD** | SigninLogs | Azure Active Directory | Interactive và non-interactive sign-ins | **No** | **Azure AD P1/P2 required** | Authentication monitoring, Conditional Access |
| **Azure AD** | AuditLogs | Azure Active Directory | Azure AD changes (users, groups, PIM) | **No** | Any Azure AD license | Change tracking, compliance auditing |
| **Azure AD** | AADNonInteractiveUserSignInLogs | Azure Active Directory | Token refreshes, background authentication | **No** | Azure AD P1/P2 | Silent authentication tracking |
| **Azure AD** | AADServicePrincipalSignInLogs | Azure Active Directory | Service principal sign-ins | **No** | Any Azure AD license | App authentication monitoring |
| **Azure AD** | AADManagedIdentitySignInLogs | Azure Active Directory | Managed identity authentications | **No** | Any Azure AD license | Managed identity tracking |
| **Azure AD** | AADProvisioningLogs | Azure Active Directory | User provisioning activities | **No** | Azure AD P1/P2 | Provisioning monitoring |
| **Azure AD** | AADRiskyUsers | Azure Active Directory | Risky user detections | **No** | Azure AD P2 | Identity Protection, risk monitoring |
| **Azure AD** | AADUserRiskEvents | Azure Active Directory | User risk events (leaked credentials, etc.) | **No** | Azure AD P2 | Risk event analysis |
| **Office 365** | OfficeActivity | Office 365 | Activities từ Exchange, SharePoint, Teams, OneDrive | Yes | Office 365 E3/E5 | User activity monitoring, data governance |
| **Azure** | AzureActivity | Azure Activity Logs | Azure subscription operations (ARM) | **No** | Any Azure subscription | Resource management, compliance |
| **Azure** | AzureDiagnostics | Azure Diagnostics | Diagnostic logs từ Azure services (legacy) | Yes | Varies by service | Service-specific monitoring |
| **Azure** | AzureMetrics | Azure Metrics | Performance metrics từ Azure resources | Yes | Varies by service | Performance monitoring |
| **Windows** | SecurityEvent | Windows Security Events | Windows Security Event Logs (Event IDs) | Yes | N/A | Windows security monitoring, logon tracking |
| **Windows** | WindowsEvent | Windows Events (AMA) | Windows events via Azure Monitor Agent | Yes | N/A | Modern Windows event collection |
| **Windows** | Event | Log Analytics Agent | Windows operational events (non-security) | Yes | N/A | System monitoring, troubleshooting |
| **Windows** | SysmonEvent | Windows Security Events | Sysmon detailed events | Yes | N/A | Advanced threat hunting, process monitoring |
| **Linux** | Syslog | Syslog | Linux syslog events, network device logs | Yes | N/A | Linux monitoring, network device tracking |
| **Network** | CommonSecurityLog | CEF / Syslog | Firewall, IDS/IPS logs (CEF format) | Yes | N/A | Network security monitoring, firewall analysis |
| **Network** | DnsEvents | DNS Analytics | Windows DNS queries và responses | Yes | N/A | DNS monitoring, malicious domain detection |
| **Network** | DnsInventory | DNS Analytics | DNS server inventory | Yes | N/A | DNS infrastructure tracking |
| **Network** | W3CIISLog | IIS Logs | IIS web server access logs | Yes | N/A | Web application monitoring, attack detection |
| **Network** | WindowsFirewall | Windows Firewall | Windows Firewall events | Yes | N/A | Host-based firewall monitoring |
| **Network** | WireData | Wire Data | Network dependency and connection data | Yes | N/A (deprecated) | Network mapping, dependency tracking |
| **Threat Intel** | ThreatIntelligenceIndicator | Threat Intelligence / TAXII | IOCs từ threat feeds | Yes | N/A | Threat matching, IOC correlation |
| **Threat Intel** | ThreatIntelIndicators | Threat Intelligence (Preview) | New STIX indicator schema | Yes | N/A | Modern threat intelligence (replacing TI Indicator) |
| **Threat Intel** | ThreatIntelObjects | Threat Intelligence (Preview) | STIX objects | Yes | N/A | Advanced threat intelligence |
| **ASIM** | ASimDnsActivityLogs | Multiple (normalized) | Normalized DNS queries | Yes | N/A | Cross-source DNS analysis |
| **ASIM** | ASimNetworkSessionLogs | Multiple (normalized) | Normalized network sessions | Yes | N/A | Unified network monitoring |
| **ASIM** | ASimWebSessionLogs | Multiple (normalized) | Normalized web/HTTP sessions | Yes | N/A | Web traffic analysis |
| **ASIM** | ASimProcessEventLogs | Multiple (normalized) | Normalized process events | Yes | N/A | Cross-platform process monitoring |
| **ASIM** | ASimFileEventLogs | Multiple (normalized) | Normalized file operations | Yes | N/A | Unified file activity tracking |
| **ASIM** | ASimAuthenticationEventLogs | Multiple (normalized) | Normalized authentication events | Yes | N/A | Cross-platform authentication analysis |
| **ASIM** | ASimRegistryEventLogs | Multiple (normalized) | Normalized registry events | Yes | N/A | Registry change tracking |
| **ASIM** | ASimAuditEventLogs | Multiple (normalized) | Normalized audit events | Yes | N/A | Unified audit log analysis |
| **ASIM** | ASimDhcpEventLogs | Multiple (normalized) | Normalized DHCP events | Yes | N/A | IP address assignment tracking |
| **ASIM** | ASimUserManagementActivityLogs | Multiple (normalized) | Normalized user management events | Yes | N/A | User lifecycle monitoring |
| **Other** | Heartbeat | Azure Monitor Agent | Agent health và connectivity | Yes | N/A | Agent monitoring, infrastructure health |
| **Other** | Update | Update Management | Update assessment và installation | Yes | N/A | Patch management, compliance |
| **Other** | UpdateSummary | Update Management | Update status summary | Yes | N/A | Update compliance reporting |
| **Other** | ProtectionStatus | Endpoint Protection | Antivirus và protection status | Yes | N/A | Endpoint protection monitoring |
| **Other** | SecurityBaseline | Security Center | Security baseline compliance | Yes | Defender for Cloud | Configuration compliance |
| **Other** | SecurityBaselineSummary | Security Center | Baseline compliance summary | Yes | Defender for Cloud | Compliance reporting |
| **Other** | ComputerGroup | Log Analytics | Computer group membership | Yes | N/A | Group management |
| **Other** | Operation | Log Analytics | Workspace operational events | **No** | N/A | Workspace monitoring |
| **Other** | Watchlist | Sentinel Watchlists | Custom imported data (via `_GetWatchlist()`) | **No** | N/A | Custom threat lists, allow lists |
| **AWS** | AWSCloudTrail | Amazon Web Services | AWS API calls và account activity | Yes | AWS account | Multi-cloud monitoring |
| **GCP** | GCPAuditLogs | Google Cloud Platform | GCP resource operations | Yes | GCP account | Multi-cloud monitoring |

---

## 📌 Legend (Chú thích)

### Product Abbreviations
- **MDE**: Microsoft Defender for Endpoint
- **MDO**: Microsoft Defender for Office 365
- **MDI**: Microsoft Defender for Identity
- **MCAS**: Microsoft Defender for Cloud Apps (formerly MCAS)
- **ASIM**: Advanced Security Information Model (Normalized)

### Billable Status
- **No**: FREE (không tính phí ingestion)
- **Yes**: BILLABLE (tính phí theo GB ingested)

### Key Points
- 🟢 **FREE Tables**: SigninLogs, AuditLogs, AAD*, SecurityAlert, SecurityIncident, AzureActivity, Operation, Watchlist
- 🔴 **Billable Tables**: Hầu hết các tables khác
- ⚠️ **License Requirements**: 
  - EmailEvents: Cần **Defender for Office 365 P2**
  - IdentityLogonEvents: Cần **M365 E5 Security** hoặc standalone **Defender for Identity**
  - SigninLogs: Cần **Azure AD P1** hoặc **P2**

---

## 🎯 Use Cases theo Product

### Microsoft Defender for Endpoint (MDE)
**Tables**: 12 Device* tables  
**Dùng cho**: 
- Endpoint threat detection
- Process và file monitoring
- Network traffic analysis
- Vulnerability management

**Key Tables**:
- `DeviceLogonEvents` - Theo dõi authentications
- `DeviceProcessEvents` - Detect malicious processes
- `DeviceNetworkEvents` - Monitor network connections
- `DeviceFileEvents` - Track file operations

### Microsoft Defender for Office 365 (MDO)
**Tables**: 5 Email* và UrlClickEvents  
**Dùng cho**:
- Email security
- Phishing detection
- Malware protection
- Safe Links monitoring

**Key Tables**:
- `EmailEvents` - Email flow analysis
- `EmailAttachmentInfo` - Malicious attachment detection
- `UrlClickEvents` - Track Safe Links clicks

### Microsoft Defender for Identity (MDI)
**Tables**: 4 Identity* tables  
**Dùng cho**:
- Active Directory monitoring
- Identity threat detection
- Lateral movement detection
- Privilege escalation

**Key Tables**:
- `IdentityLogonEvents` - Authentication monitoring
- `IdentityDirectoryEvents` - AD changes tracking

### Azure Active Directory
**Tables**: 8 AAD* tables + SigninLogs + AuditLogs  
**Dùng cho**:
- Cloud identity monitoring
- Conditional Access
- Sign-in analysis
- User provisioning

**Key Tables**:
- `SigninLogs` - User sign-in analysis
- `AuditLogs` - Azure AD change tracking

---

## 💡 Query Examples

### Cross-Product Correlation
```kql
// Correlate Azure AD sign-in with endpoint logon
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| join kind=inner (
    DeviceLogonEvents
    | where ActionType == "LogonSuccess"
    | project TimeGenerated, AccountName, DeviceName, LogonType
) on $left.UserPrincipalName == $right.AccountName
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) <= 5
```

### Threat Intelligence Matching
```kql
// Match threat indicators với network traffic
let ThreatIPs = ThreatIntelligenceIndicator
    | where ExpirationDateTime > now()
    | where Active == true
    | distinct NetworkIP;
CommonSecurityLog
| where DestinationIP in (ThreatIPs)
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction, DeviceVendor
```

### Multi-Source Authentication Analysis
```kql
// Combine authentication events từ multiple sources
union 
    (SecurityEvent | where EventID == 4624 | project TimeGenerated, Account, Computer, LogonType),
    (DeviceLogonEvents | project TimeGenerated, AccountName, DeviceName, LogonType),
    (SigninLogs | project TimeGenerated, UserPrincipalName, Location, AppDisplayName),
    (IdentityLogonEvents | project TimeGenerated, AccountName, DestinationDeviceName, Protocol)
| summarize Count=count() by bin(TimeGenerated, 1h)
```

### Email Phishing Investigation
```kql
// Investigate phishing campaign
EmailEvents
| where ThreatTypes has "Phish"
| join kind=inner (
    EmailAttachmentInfo
    | where FileType in ("exe", "dll", "ps1", "vbs")
) on NetworkMessageId
| join kind=inner (
    EmailUrlInfo
    | where UrlLocation == "Body"
) on NetworkMessageId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, FileName, Url, ThreatTypes
```

---

## 📚 Best Practices

### 1. **Data Connector Setup**
- Enable **Microsoft Defender XDR** connector để collect tất cả Device*, Email*, Identity* tables
- Enable **Azure Active Directory** connector cho SigninLogs và AuditLogs
- Enable **Office 365** connector cho OfficeActivity

### 2. **Query Optimization**
- Sử dụng ASIM parsers (`_Im_Dns`, `_Im_NetworkSession`) cho cross-source queries
- Limit time range với `| where TimeGenerated > ago(24h)`
- Use `summarize` thay vì `distinct` khi có thể

### 3. **Cost Management**
- FREE tables: Azure AD logs, SecurityAlert, SecurityIncident
- Monitor ingestion với `Usage` table
- Configure data retention theo table

### 4. **Security Monitoring**
- Combine multiple tables cho comprehensive view
- Use ASIM normalized tables cho vendor-agnostic detections
- Leverage Watchlists cho known-good/known-bad lists

---

## 🔍 Quick Reference cho SC-200 Exam

| Scenario | Tables to Use |
|----------|---------------|
| **Windows Logon Investigation** | SecurityEvent (4624, 4625), DeviceLogonEvents |
| **Process Execution Analysis** | DeviceProcessEvents, SecurityEvent (4688), SysmonEvent |
| **Email Phishing Detection** | EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents |
| **Network Traffic Analysis** | DeviceNetworkEvents, CommonSecurityLog, ASimNetworkSessionLogs |
| **Azure AD Sign-in Issues** | SigninLogs, AADNonInteractiveUserSignInLogs |
| **File Operations Tracking** | DeviceFileEvents, ASimFileEventLogs |
| **Active Directory Changes** | IdentityDirectoryEvents, SecurityEvent (4720, 4726, 4728) |
| **Threat Intel Matching** | ThreatIntelligenceIndicator + any network/email tables |
| **Cloud App Monitoring** | CloudAppEvents, OfficeActivity |
| **Incident Investigation** | SecurityIncident, SecurityAlert, all relevant source tables |

---

## ⚠️ Important Notes

1. **SecurityEvent vs DeviceLogonEvents**:
   - SecurityEvent: Windows Event IDs (4624 = logon)
   - DeviceLogonEvents: ActionType ("LogonSuccess")

2. **License Requirements Matter**:
   - Không có Defender for Office 365 P2 → Không có EmailEvents
   - Không có M365 E5 Security → Không có IdentityLogonEvents
   - Không có Azure AD P1/P2 → Không có SigninLogs

3. **Data Retention**:
   - Default: 90 days
   - Can extend lên đến 2 years (with cost)
   - Configure per-table retention

4. **Connector Dependencies**:
   - Microsoft Defender XDR connector → Tất cả Device*, Email*, Identity* tables
   - Individual connectors → Specific tables only

---

**Version**: 2.0  
**Last Updated**: October 2025  
**Source**: SC-200 Certification Materials + Microsoft Learn
