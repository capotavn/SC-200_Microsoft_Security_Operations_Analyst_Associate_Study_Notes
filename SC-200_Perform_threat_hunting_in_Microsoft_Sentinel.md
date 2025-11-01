# SC-200: Perform threat hunting in Microsoft Sentinel

## I. Explain Threat Hunting Concepts

### 1. Understand Cybersecurity Threat Hunts

**Threat Hunting Definition**:
- Proactively hunting through environment for threats or activities not previously detected
- "Not previously detected" differentiates hunting from incident response or alert triage
- Uses KQL queries to find threats

**Types of Hunting**:

**1. Proactive Hunting**:
- Hunt for "not previously detected" threats
- Based on hypothesis, not known indicators
- Focus on attacker tactics and techniques
- Goal: Discover attackers early in attack process before data exfiltration

**2. Indicator-Based Hunting**:
- Search for threats with newly obtained indicators
- Example: New malicious IP from Threat Intelligence Feed
- Search logs to find if indicator seen in past
- Technically not "threat hunting" (using known bad indicators)

**3. Evidence-Based Hunting**:
- Hunt for more evidence from current incident/alert
- Part of incident analysis process
- Explore data based on evidence found in current incident
- Both Sentinel and Defender XDR provide this capability

**Common Element**: All approaches use KQL queries to find threats

**Tool Focus**:
- **Microsoft Defender/Defender for Endpoint**: More focused on indicator and analysis hunting
- **Microsoft Sentinel**: More features to manage threat hunting process

### 2. Proactive Hunts

**Why Proactive Hunting?**:
- Don't wait for threat detection
- Waiting could result in more significant compromise impact
- Discover attackers earlier in attack process
- Prevent data exfiltration

**What to Hunt Without Known Indicators?**:
- Hunt based on **Hypothesis**
- Hypothesis starts with Operational Threat Intelligence
- List attacker tactics and techniques
- Search for specific technique (not indicators like IP addresses)

### 3. Process to Hunt Threats

**Continual Process**:
1. Start with Hypothesis
2. Plan what to hunt for
3. Understand where to hunt and how
4. Know available data, tools, and expertise
5. Execute hunt
6. Respond to anomalies
7. Document everything
8. Perform routine tasks (even if no active threat found)

**Routine Tasks**:
- Set up new monitoring
- Improve detection capabilities

**Documentation Requirements**:
- What, How, and Why
- Input and Output
- How to replicate the hunt
- Next Steps

### 4. Develop a Hypothesis

**Hypothesis Definition**: The idea of what to hunt

**Key Factors for Good Hypothesis**:

**1. Keep It Achievable**:
- Don't hunt where you have no hope of finding results
- Ensure you have available data
- Have sufficient knowledge about threat

**2. Keep Scope Narrow**:
- Avoid broad hypothesis (e.g., "hunt for strange log-ons")
- Define what results could mean
- Be specific

**3. Keep It Time-Bound**:
- Define time period (last day, last week, since log beginning)
- Used in documentation
- Prevents repeating same hunt on same dataset
- Document: "I did this hunt, at this time, covering this period"
- Team members know what period was hunted

**4. Keep It Useful and Efficient**:
- Target threats without adequate detection coverage
- Focus on previously missed threats
- SOC team knows where coverage is good/weak
- Relate to realistic threats
- Don't hunt for threats not applicable to your environment

**5. Keep It Related to Threat Model**:
- Hunt for threats relevant to your organization
- Don't spend time on threats you'll never find
- Align with what you're defending against

**6. Start Simple**:
- Don't start with most advanced threats
- Begin with basics
- Incrementally mature hunting capabilities

**Example Hypotheses**:

**Example 1**:
- Threat Intel: Threat Actor uses automated attacks with cmd.exe process
- Hunt: Find unusual cmd.exe executions

**Example 2**:
- Check for accounts that ran cmd.exe in last day
- BUT did NOT run cmd.exe during past week
- Identifies anomalous behavior

### 5. Explore MITRE ATT&CK

**MITRE ATT&CK Framework**:
- Knowledge base of tactics and techniques
- Observed in global threat landscape
- Used to develop and inform threat-hunting models

**Microsoft Sentinel Integration**:
- Categorize and order queries by tactics
- ATT&CK tactics timeline on Hunting page
- Filter queries by selected tactic

**ATT&CK Tactics** (Enterprise and ICS matrices):

| Tactic | Description |
|--------|-------------|
| **Reconnaissance** | Find information to plan future operations |
| **Resource Development** | Establish resources (infrastructure, accounts, capabilities) |
| **Initial Access** | Gain entry to network (exploit vulnerabilities, spear-phishing) |
| **Execution** | Run code on target system (PowerShell scripts, download tools) |
| **Persistence** | Maintain access after restarts/credential changes (scheduled tasks) |
| **Privilege Escalation** | Gain higher-level privileges (local admin, root) |
| **Defense Evasion** | Avoid detection (hide code, encrypt, disable security software) |
| **Credential Access** | Steal usernames and credentials for reuse |
| **Discovery** | Obtain information about systems and networks |
| **Lateral Movement** | Move from one system to another (pass-the-hash, RDP abuse) |
| **Collection** | Gather and consolidate targeted information |
| **Command and Control** | Communicate with controlled systems (uncommon ports) |
| **Exfiltration** | Move data from compromised network to attacker network |
| **Impact** | Affect availability (DoS, disk-wiping, data-wiping) |
| **Impair Process Control** | Manipulate, disable, damage physical control processes (ICS) |
| **Inhibit Response Function** | Prevent safety/protection functions from responding (ICS) |
| **None** | Uncategorized |

---

## II. Threat Hunting with Microsoft Sentinel

### 1. Hunt Using Built-in Queries

**Hunting Page Features**:
- Built-in queries guide hunting process
- Help pursue appropriate hunting paths
- Expose issues not significant enough for alerts
- Track issues that happen often enough to warrant investigation

**Query List Features**:
- Filter and sort by: Name, provider, data source, results, tactics
- Save queries as Favorites (star icon)
- Favorites run automatically when opening Hunting page

**Query Execution**:
1. Select query from list
2. Query details appear in pane
3. View: Description, code, related entities, tactics
4. Select "Run Query" to execute

### 2. Query Management and Creation

**Manage Hunting Queries**:

**Query Details Pane Contains**:
- Description
- KQL code
- Related entities
- Identified tactics
- Run Query button

**Filter by MITRE ATT&CK**:
- Select tactic from timeline on Hunting page
- Filters available queries by selected tactic
- Categorize queries using ATT&CK framework

**Create Custom Queries**:

**Custom Query Parameters**:

| Parameter | Description |
|-----------|-------------|
| **Name** | Name for custom query |
| **Description** | Query functionality description |
| **Custom Query** | Your KQL hunting query code |
| **Entity Mapping** | Map entity types to columns from query results (populate with actionable information) |
| **Tactics & Techniques** | Specify tactics query designed to expose |

**Custom Query Listing**:
- Listed alongside built-in queries
- Same management capabilities

**KQL Syntax**:
- All hunting queries use Kusto Query Language
- Same syntax as Log Analytics
- Modify queries in details pane
- Save as new reusable query
- Create from scratch

### 3. Microsoft Sentinel GitHub Repository

**Repository Contents**:
- Out-of-the-box detections
- Exploration queries
- Hunting queries
- Workbooks
- Playbooks
- More security content

**Community Contributions**:
- Microsoft contributions
- Community contributions
- Folders for different functionality areas

**Using GitHub Content**:
- Browse hunting queries folder
- Use code to create custom queries
- Contribute back to community
- Stay updated with latest queries

---

## III. Bookmarks

### 1. Bookmark Overview

**Purpose**: Save important query results for later investigation

**Use Cases**:
- Mark interesting findings during hunt
- Preserve evidence
- Create reference for investigation
- Share findings with team
- Build incident from multiple bookmarks

### 2. Create Bookmarks

**Creation Methods**:

**Method 1: From Query Results**:
1. Run hunting query
2. Select interesting rows
3. Click "Add bookmark"
4. Enter:
   - Bookmark name
   - Tags
   - Notes
5. Save

**Method 2: From Logs**:
1. Query in Logs page
2. Select results
3. Create bookmark

**Bookmark Properties**:
- Name and description
- Tags for categorization
- Query used to create bookmark
- Query results preserved
- Timestamp of creation
- Notes and observations

### 3. Manage Bookmarks

**View Bookmarks**:
- Navigate to Hunting → Bookmarks tab
- See all saved bookmarks
- Filter by tags, time, query

**Bookmark Actions**:
- **View**: See bookmark details
- **Investigate**: Open investigation graph
- **Delete**: Remove bookmark
- **Edit**: Update name, tags, notes
- **Create Incident**: Convert to incident

### 4. Create Incidents from Bookmarks

**Process**:
1. Select one or more bookmarks
2. Click "Create incident"
3. Choose:
   - Create new incident
   - Add to existing incident
4. Set incident properties:
   - Title
   - Severity
   - Status
   - Owner
5. Submit

**Benefits**:
- Promote findings to incidents
- Trigger investigation workflow
- Assign to analysts
- Track through resolution

---

## IV. Livestream

### 1. Livestream Overview

**Purpose**: Real-time hunting with automatic query execution

**Capabilities**:
- Monitor for threats in real-time
- Automatically run queries on interval
- Get immediate notifications
- Track evolving threats
- Proactive threat detection

### 2. Create Livestream Session

**Setup**:
1. Navigate to Hunting page
2. Select query
3. Click "Livestream"
4. Configure:
   - Query to run
   - Execution interval (minutes)
   - Notification settings
5. Start livestream

**Livestream Settings**:
- **Query**: KQL query to execute
- **Interval**: How often to run (e.g., every 5 minutes)
- **Results Threshold**: Minimum results to trigger notification
- **Duration**: How long to run livestream

### 3. Monitor Livestream

**Real-time Monitoring**:
- View results as they appear
- See result count over time
- Visual timeline of findings
- Pause/resume livestream
- Stop when investigation complete

**Notifications**:
- Alert when threshold exceeded
- Email or portal notifications
- Immediate awareness of threats

### 4. Use Cases

**Scenario 1: IOC Monitoring**:
- New threat indicator received
- Create query for indicator
- Run livestream to find matches
- Get alerted immediately

**Scenario 2: Active Incident**:
- Incident under investigation
- Hunt for related activity
- Livestream for new occurrences
- Track attacker activity in real-time

**Scenario 3: Hypothesis Testing**:
- Testing new hypothesis
- Run livestream during business hours
- Gather evidence over time
- Validate or refute hypothesis

---

## V. Use Search Jobs

### 1. Hunt with Search Jobs

**Search Jobs Overview**:
- Run long-running queries on large data sets
- Search across extended time periods
- Access archived data
- Optimize costs (search tier pricing)

**When to Use Search Jobs**:
- Hunt over months of historical data
- Large-scale investigations
- Compliance searches
- Historical pattern analysis
- Archive data analysis

### 2. Create Search Job

**Steps**:
1. Navigate to Search page
2. Write KQL query
3. Select time range (up to 7 years)
4. Estimated cost displayed
5. Run search job

**Search Job Properties**:
- Query text
- Time range
- Target tables
- Job status
- Results preview
- Cost estimate

**Execution**:
- Runs in background
- No timeout limits
- Can take hours for large datasets
- Results saved to search table

### 3. View Search Results

**Access Results**:
1. Navigate to completed search job
2. View results in grid
3. Export to CSV
4. Create visualizations
5. Further analysis with KQL

**Results Table**:
- Temporary table created
- Named: search_job_<guid>
- Available for 7 days
- Can query like any table

**Example**:
```kql
search_job_12345678
| where Computer contains "SERVER"
| summarize count() by Computer
```

### 4. Restore Historical Data

**Purpose**: Make archived data available for analysis

**Restore Process**:
1. Navigate to Tables
2. Select archived table
3. Choose "Restore"
4. Specify:
   - Time range to restore
   - Destination table name
   - Retention period
5. Start restoration

**Restored Data Characteristics**:
- Available in Analytics logs tier
- Full query capabilities
- Retained for specified period
- Then automatically deleted or re-archived

**Use Cases**:
- Deep investigation requiring archived data
- Compliance audits
- Historical threat analysis
- Long-term pattern analysis

**Cost Considerations**:
- Restoration costs apply
- Analytics tier pricing while restored
- Plan restoration scope carefully
- Use search jobs first when possible

---

## VI. Hunt for Threats Using Notebooks

### 1. Access Sentinel Data with External Tools

**Notebooks Overview**:
- Jupyter notebooks for advanced hunting
- Python-based analysis
- Machine learning integration
- Data science workflows

**Benefits**:
- Full programming language capabilities
- Advanced statistical analysis
- Machine learning models
- Data visualization libraries
- Repeatable investigations

**Access Methods**:
- Azure Machine Learning workspace
- Azure Notebooks
- Local Jupyter environment

### 2. Hunt with Notebooks

**Hunting Capabilities**:
- **Data Access**: Query Sentinel workspace via API
- **Data Processing**: Clean, transform, enrich data
- **Analysis**: Statistical analysis, pattern detection
- **Visualization**: Create charts, graphs, timelines
- **ML Models**: Anomaly detection, classification
- **Automation**: Automated hunting workflows

**Python Libraries**:
- **msticpy**: Microsoft Sentinel-specific toolkit
- **pandas**: Data manipulation
- **matplotlib/seaborn**: Visualization
- **scikit-learn**: Machine learning
- **networkx**: Network analysis

### 3. Create Notebook

**Setup**:
1. Navigate to Microsoft Sentinel → Notebooks
2. Select "Templates"
3. Choose template or create new
4. Clone to Azure ML workspace
5. Launch notebook

**Notebook Structure**:
- **Markdown cells**: Documentation, notes
- **Code cells**: Python code execution
- **Output cells**: Results, visualizations

**Authentication**:
```python
from msticpy.auth.azure_auth import az_connect
ws = az_connect(auth_methods=['cli', 'msi', 'interactive'])
```

**Query Data**:
```python
from msticpy.data import QueryProvider

qry_prov = QueryProvider("MSSentinel")
qry_prov.connect(workspace_id="<workspace_id>")

# Run query
df = qry_prov.exec_query("""
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| summarize count() by Computer
""")
```

### 4. Explore Notebook Code

**Data Analysis Example**:
```python
import pandas as pd
import matplotlib.pyplot as plt

# Load data
df = qry_prov.exec_query("SecurityEvent | where EventID == 4624")

# Analyze
login_counts = df.groupby('Account').size().sort_values(ascending=False)

# Visualize
login_counts.head(10).plot(kind='bar')
plt.title('Top 10 Accounts by Login Count')
plt.xlabel('Account')
plt.ylabel('Login Count')
plt.show()
```

**Anomaly Detection Example**:
```python
from sklearn.ensemble import IsolationForest

# Prepare data
features = df[['LoginCount', 'UniqueIPs', 'FailedLogins']]

# Train model
model = IsolationForest(contamination=0.1)
df['anomaly'] = model.fit_predict(features)

# Find anomalies
anomalies = df[df['anomaly'] == -1]
print(f"Found {len(anomalies)} anomalies")
```

**Timeline Visualization**:
```python
from msticpy.vis.timeline import display_timeline

# Create timeline
display_timeline(
    data=df,
    title="Login Events Timeline",
    source_columns=['Account', 'Computer'],
    height=400
)
```

**Network Graph**:
```python
import networkx as nx

# Create graph
G = nx.from_pandas_edgelist(
    df, 
    source='SourceIP', 
    target='DestinationIP'
)

# Plot
nx.draw(G, with_labels=True)
plt.title("Network Connections")
plt.show()
```

**Threat Intelligence Enrichment**:
```python
from msticpy.context.tiproviders import TILookup

ti = TILookup()

# Lookup IP reputation
result = ti.lookup_ioc(
    observable='192.168.1.1',
    ioc_type='ipv4'
)

print(result)
```

**Geolocation Analysis**:
```python
from msticpy.context.geoip import GeoLiteLookup

geo_ip = GeoLiteLookup()

# Get location
location = geo_ip.lookup_ip('8.8.8.8')
print(f"Country: {location.CountryName}")
print(f"City: {location.City}")
```

**Complete Hunting Workflow**:
```python
# 1. Define hypothesis
hypothesis = "Detect unusual PowerShell executions"

# 2. Collect data
query = """
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where Process contains "powershell"
"""
df = qry_prov.exec_query(query)

# 3. Analyze patterns
ps_stats = df.groupby('Account').agg({
    'Computer': 'nunique',
    'CommandLine': 'count'
}).rename(columns={
    'Computer': 'UniqueComputers',
    'CommandLine': 'ExecutionCount'
})

# 4. Identify anomalies
threshold = ps_stats['ExecutionCount'].mean() + 2 * ps_stats['ExecutionCount'].std()
suspicious = ps_stats[ps_stats['ExecutionCount'] > threshold]

# 5. Visualize findings
suspicious.plot(kind='bar', y='ExecutionCount')
plt.title('Suspicious PowerShell Activity')
plt.show()

# 6. Create bookmarks for investigation
for account in suspicious.index:
    print(f"Investigate account: {account}")
```

**Export Results**:
```python
# Save to CSV
suspicious.to_csv('suspicious_accounts.csv')

# Create incident
from msticpy.common.azure_sentinel import MicrosoftSentinel

sentinel = MicrosoftSentinel(workspace_id="<workspace_id>")

incident = sentinel.create_incident(
    title="Suspicious PowerShell Activity Detected",
    description=f"Found {len(suspicious)} accounts with unusual activity",
    severity="High"
)
```

**Notebook Best Practices**:
- Document hypothesis clearly
- Show methodology step-by-step
- Include visualizations
- Add comments in code
- Save results/findings
- Version control notebooks
- Share with team via templates

---

## Summary

This comprehensive module covers threat hunting in Microsoft Sentinel across six major areas:

**I. Threat Hunting Concepts**:
- Three types: Proactive, indicator-based, evidence-based
- Proactive hunting based on hypothesis (not known indicators)
- Continual process with documentation requirements
- Good hypothesis: Achievable, narrow scope, time-bound, useful, related to threat model, start simple
- MITRE ATT&CK framework: 17 tactics for categorizing threats

**II. Threat Hunting with Sentinel**:
- Built-in hunting queries guide process
- Filter/sort by name, provider, data source, tactics
- Favorites run automatically
- Custom query creation with entity mapping
- GitHub repository for community queries

**III. Bookmarks**:
- Save important query results
- Preserve evidence for later
- Create incidents from bookmarks
- Tag and categorize findings
- Share with team

**IV. Livestream**:
- Real-time hunting with automatic execution
- Configure interval and thresholds
- Immediate notifications
- Monitor evolving threats
- Track active incidents

**V. Search Jobs**:
- Long-running queries on large datasets
- Search up to 7 years of data
- Access archived data
- Results saved for 7 days
- Restore historical data to Analytics tier

**VI. Notebooks**:
- Advanced hunting with Python
- Machine learning integration
- Data visualization libraries
- msticpy toolkit for Sentinel
- Complete hunting workflows with code examples

**Key Takeaways**:
- **Hypothesis-Driven**: Start with clear, achievable hypothesis
- **MITRE ATT&CK**: Framework guides hunting focus
- **Built-in + Custom**: Use provided queries and create custom
- **Real-time Monitoring**: Livestream for immediate awareness
- **Historical Analysis**: Search jobs for long-term patterns
- **Advanced Analytics**: Notebooks for ML and data science
- **Documentation**: Critical for repeatability and knowledge sharing
- **Continuous Process**: Hunting never stops, always improve

**Best Practices**:
- Start simple, incrementally increase complexity
- Document all hunts (what, how, why, results, next steps)
- Use MITRE ATT&CK for categorization
- Time-bound hunts to avoid duplication
- Save interesting findings as bookmarks
- Create incidents from confirmed threats
- Use livestream for active monitoring
- Leverage notebooks for complex analysis
- Share findings and queries with team
- Regularly update hunting queries

**Hunting Workflow**:
1. Develop hypothesis based on threat intelligence
2. Create or select hunting query
3. Execute hunt (interactive, livestream, or search job)
4. Analyze results
5. Bookmark interesting findings
6. Create incidents for confirmed threats
7. Document hunt and results
8. Update detections based on findings
9. Share knowledge with team
10. Repeat with refined hypothesis

**Common Patterns**:
```kql
// Hypothesis: Unusual process execution
SecurityEvent
| where EventID == 4688
| where Process !in ("explorer.exe", "svchost.exe")
| summarize count() by Account, Process
| where count_ > 10

// Hypothesis: Suspicious network connections
DeviceNetworkEvents
| where RemotePort in (4444, 5555, 8080)
| where RemoteIP !startswith "10."
| summarize UniqueDestinations=dcount(RemoteIP) by DeviceName
| where UniqueDestinations > 5

// Hypothesis: Anomalous authentication
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress
| where FailedAttempts > 10
```

**Notebook Template Structure**:
```
1. Hypothesis & Objectives
2. Data Collection
3. Data Cleaning & Preprocessing
4. Exploratory Analysis
5. Pattern Detection
6. Anomaly Detection
7. Visualization
8. Conclusions & Recommendations
9. Next Steps & Automation
```
