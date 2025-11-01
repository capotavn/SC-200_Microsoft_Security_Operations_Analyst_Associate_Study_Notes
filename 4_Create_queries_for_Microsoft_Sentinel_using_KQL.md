# SC-200: Create queries for Microsoft Sentinel using Kusto Query Language (KQL)

## I. Construct KQL Statements for Microsoft Sentinel

### 1. KQL Statement Structure

**Overview**:
- Read-only request to process data and return results
- Plain text format with data-flow model
- Easy to read, write, and automate
- Schema hierarchy: Databases → Tables → Columns

**Query Structure**:
- Sequence of query statements
- At least one tabular expression statement required
- Produces data in table-like mesh (columns and rows)
- Tabular data flows from one operator to another using pipe delimiter `|`

**Basic Query Flow**:
```kql
SecurityEvent                    // Data source (table)
| where EventID == 4688          // Filter rows
| summarize count() by Account   // Aggregate and create new column
| take 10                         // Limit results to 10 rows
```

**Important**: Results flow through pipe `|` - everything left of pipe is processed, then passed to right

**Log Analytics Demo Environment**:
- Access: https://aka.ms/lademo
- No Azure charges
- Practice KQL statements
- Dynamic environment (continuously updating)
- May need to adjust time range (>30 days) if no results

**Query Window Sections**:
1. **Left**: Reference list of tables
2. **Middle Top**: Query editor
3. **Bottom**: Query results

**Before Running**:
- Adjust time range to scope data
- Select Columns box to choose displayed columns

### 2. Search Operator

**Purpose**: Multi-table/multi-column search experience

**Characteristics**:
- Easy to use
- Inefficient compared to `where` operator
- Use when unsure which table or column to filter

**Syntax Examples**:
```kql
// Search across all tables
search "err"

// Search specific tables
search in (SecurityEvent, SecurityAlert, A*) "err"
```

**Note**: May need to adjust Time range to "Last hour" to avoid errors

### 3. Where Operator

**Purpose**: Filter table to subset of rows satisfying a predicate

**Examples**:
```kql
// Filter by time
SecurityEvent
| where TimeGenerated > ago(1d)

// Multiple conditions with AND
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"

// Multiple where statements (equivalent to AND)
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where AccountType =~ "user"    // =~ is case-insensitive

// Filter with IN operator
SecurityEvent 
| where EventID in (4624, 4625)
```

**Comparison Operators**:
- `==`: Equals (case-sensitive)
- `=~`: Equals (case-insensitive)
- `!=`: Not equals
- `>`, `>=`, `<`, `<=`: Comparison operators
- `in`: Value in list
- `contains`, `has`: String contains/has substring

### 4. Let Statement

**Purpose**: Bind names to expressions for reuse and modularity

**Use Cases**:
- Create variables
- Create user-defined functions
- Create views
- Break complex expressions into parts

**Declare Variables**:
```kql
let timeOffset = 7d;
let discardEventId = 4688;
SecurityEvent
| where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
| where EventID != discardEventId
```

**Create Dynamic Tables**:
```kql
// Create table with specific values
let suspiciousAccounts = datatable(account: string) [
    @"\administrator",
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent 
| where Account in (suspiciousAccounts)

// Create table from query results
let LowActivityAccounts =
    SecurityEvent
    | summarize cnt = count() by Account
    | where cnt < 1000;
LowActivityAccounts 
| where Account contains "SQL"
```

**Note**: `ago()` function takes current Date/Time and subtracts provided value

### 5. Extend Operator

**Purpose**: Create calculated columns and append to result set

**Syntax**:
```kql
SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir = substring(ProcessName, 0, string_size(ProcessName) - string_size(Process))
```

**Characteristics**:
- Adds new columns without removing existing ones
- Calculated columns appear alongside original columns
- Can use functions (substring, string_size, etc.)
- Multiple extend operations can be chained

### 6. Order By Operator

**Purpose**: Sort rows by one or more columns

**Syntax**:
```kql
SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir = substring(ProcessName, 0, string_size(ProcessName) - string_size(Process))
| order by StartDir desc, Process asc
```

**Characteristics**:
- Multiple columns separated by comma
- Each column can be `asc` (ascending) or `desc` (descending)
- Default order: Descending
- Alias: `sort by` (same as `order by`)

### 7. Project Operators

**Overview**: Control which columns to include, add, remove, or rename

**Project Operator Variations**:

| Operator | Description |
|----------|-------------|
| **project** | Select columns to include, rename, drop, or insert new computed columns |
| **project-away** | Select columns to exclude from output |
| **project-keep** | Select columns to keep in output |
| **project-rename** | Rename columns in output |
| **project-reorder** | Set column order in output |

**Project** - Select Specific Columns:
```kql
// Include only specific columns
SecurityEvent
| project Computer, Account

// Include calculated columns
SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir = substring(ProcessName, 0, string_size(ProcessName) - string_size(Process))
| order by StartDir desc, Process asc
| project Process, StartDir
```

**Project-Away** - Exclude Columns:
```kql
SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir = substring(ProcessName, 0, string_size(ProcessName) - string_size(Process))
| order by StartDir desc, Process asc
| project-away ProcessName    // Remove ProcessName column
```

**Benefits**:
- Limits result set size
- Increases query performance
- Improves readability

---

## II. Analyze Query Results Using KQL

### 1. Summarize Operator

**Purpose**: Aggregate data and create summary statistics

**Basic Syntax**:
```kql
// Return unique list of Activity values
SecurityEvent 
| summarize by Activity

// Count rows grouped by columns
SecurityEvent
| where EventID == "4688"
| summarize count() by Process, Computer
```

**Common Aggregate Functions**:

| Function | Description |
|----------|-------------|
| **count(), countif()** | Count of records per group |
| **dcount(), dcountif()** | Estimate of distinct values in group |
| **avg(), avgif()** | Average of expression across group |
| **max(), maxif()** | Maximum value across group |
| **min(), minif()** | Minimum value across group |
| **percentile()** | Nearest-rank percentile estimate |
| **stdev(), stdevif()** | Standard deviation across group |
| **sum(), sumif()** | Sum of expression across group |
| **variance(), varianceif()** | Variance across group |

**Count Function Example**:
```kql
// Explicitly name aggregate column
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| summarize cnt=count() by AccountType, Computer
```

**DCount Function Example**:
```kql
// Count unique IP addresses
SecurityEvent
| summarize dcount(IpAddress)
```

**Real-World Example** - Detect Invalid Password Failures:
```kql
let timeframe = 30d;
let threshold = 1;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "Invalid password"
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```

### 2. Summarize to Filter Results

**Use Case**: Filter results based on aggregate calculations

**Examples**:
```kql
// Filter by count
SecurityEvent
| summarize Count=count() by Account
| where Count > 100

// Filter by distinct count
SecurityEvent
| summarize UniqueComputers=dcount(Computer) by Account
| where UniqueComputers > 5
```

### 3. Summarize to Prepare Data

**Use Case**: Transform and prepare data for visualization or further analysis

**Examples**:
```kql
// Prepare time-series data
SecurityEvent
| summarize EventCount=count() by bin(TimeGenerated, 1h), EventID
| order by TimeGenerated asc

// Calculate percentages
SecurityEvent
| summarize Total=count(), Failed=countif(ResultType != 0) by Account
| extend FailureRate = (Failed * 100.0) / Total
```

### 4. Render Operator - Create Visualizations

**Purpose**: Generate visualizations from query results

**Supported Visualizations**:
- `areachart`
- `barchart`
- `columnchart`
- `piechart`
- `scatterchart`
- `timechart`

**Bar Chart Example**:
```kql
SecurityEvent
| summarize count() by Account
| render barchart
```

**Time Series with bin() Function**:

**bin() Function**:
- Rounds values down to integer multiple of given bin size
- Groups scattered values into smaller set of specific values
- Used frequently with `summarize by`

**Time Chart Example**:
```kql
SecurityEvent
| summarize count() by bin(TimeGenerated, 1d)
| render timechart
```

**Time-Series Visualization Flow**:
1. Use `bin()` to group timestamps (e.g., 1 day, 1 hour)
2. Use `summarize` to aggregate data per time bucket
3. Use `render timechart` to create visualization

---

## III. Build Multi-Table Statements Using KQL

### 1. Union Operator

**Purpose**: Combine rows from two or more tables

**Basic Examples**:
```kql
// Query 1: Return all rows from both tables
SecurityEvent
| union SigninLogs

// Query 2: Count total rows from both tables
SecurityEvent
| union SigninLogs
| summarize count()
| project count_

// Query 3: All SecurityEvent rows + one row from SigninLogs
SecurityEvent
| union (SigninLogs | summarize count() | project count_)
```

**Important**: Understanding how results pass through pipe `|` is essential

**Wildcard Support**:
```kql
// Union all tables starting with "Security"
union Security*
| summarize count() by Type
```

**Characteristics**:
- Returns all rows from all specified tables
- Column schemas must be compatible
- Useful for combining similar data from different sources

### 2. Join Operator

**Purpose**: Merge rows of two tables by matching specified column values

**Syntax**:
```kql
LeftTable 
| join [JoinParameters] ( RightTable ) on Attributes
```

**Example**:
```kql
SecurityEvent
| where EventID == "4624"
| summarize LogOnCount=count() by EventID, Account
| project LogOnCount, Account
| join kind=inner (
    SecurityEvent
    | where EventID == "4634"
    | summarize LogOffCount=count() by EventID, Account
    | project LogOffCount, Account
) on Account
```

**Table References**:
- First table = Left table
- Table after `join` keyword = Right table
- Column designation: `$left.Column` and `$right.Column`

**Join Flavors** (kinds):

| Join Flavor | Output Records |
|-------------|----------------|
| **kind=leftanti, kind=leftantisemi** | All records from left WITHOUT matches from right |
| **kind=rightanti, kind=rightantisemi** | All records from right WITHOUT matches from left |
| **kind unspecified, kind=innerunique** | One row from left matched for each `on` key value, output row for each match with right |
| **kind=leftsemi** | All records from left WITH matches from right |
| **kind=rightsemi** | All records from right WITH matches from left |
| **kind=inner** | Row for every combination of matching rows from left and right |
| **kind=leftouter** (or **rightouter**, **fullouter**) | Row for every row on left and right, even without match (nulls for unmatched) |

**Visual Guide**:
- **Inner join**: Only matching records from both sides
- **Left outer**: All left + matching right (nulls if no match)
- **Right outer**: All right + matching left (nulls if no match)
- **Full outer**: All records from both sides (nulls where no match)
- **Left anti**: Left records WITHOUT right matches
- **Right anti**: Right records WITHOUT left matches

---

## IV. Work with Data in Microsoft Sentinel Using KQL

### 1. Extract Data from Unstructured String Fields

**Overview**: Security log data often contained in unstructured string fields requiring parsing

**Two Primary Operators**: `extract` and `parse`

**Extract Operator**:

**Purpose**: Get regex match from text string, optionally convert to specified type

**Syntax**:
```kql
extract(regex, captureGroup, text [, typeLiteral])
```

**Arguments**:
- **regex**: Regular expression
- **captureGroup**: Positive int (0=entire match, 1=first parenthesis, 2=second, etc.)
- **text**: String to search
- **typeLiteral**: Optional type (e.g., typeof(long))

**Returns**: Matched substring, optionally converted to type (null if no match or conversion fails)

**Example**:
```kql
// Simple extract
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"

// Extract account name from SecurityEvent
SecurityEvent
| where EventID == 4672 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| summarize LoginCount = count() by Account_Name
| where Account_Name != ""
| where LoginCount < 10
```

**Parse Operator**:

**Purpose**: Parse string expression into one or more calculated columns

**Syntax**:
```kql
T | parse [kind=regex [flags=regex_flags] | simple | relaxed] Expression with * (StringConstant ColumnName [: ColumnType]) *
```

**Arguments**:
- **T**: Input table
- **kind**:
  - `simple` (default): Regular string value, strict match
  - `regex`: StringConstant can be regex, strict match
  - `relaxed`: Regular string value, relaxed match (partial type matches allowed)
- **flags**: Regex flags (U=ungreedy, m=multi-line, s=match newline, i=case-insensitive)
- **Expression**: Expression evaluating to string
- **ColumnName**: Column name for extracted value
- **ColumnType**: Optional scalar type (default: string)

**Example**:
```kql
let Traces = datatable(EventText:string)
[
    "Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=23, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)",
    "Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=15, lockTime=02/17/2016 08:40:00, releaseTime=02/17/2016 08:40:00, previousLockTime=02/17/2016 08:39:00)"
];
Traces
| parse EventText with * "resourceName=" resourceName ", totalSlices=" totalSlices:long * "sliceNumber=" sliceNumber:long * "lockTime=" lockTime ", releaseTime=" releaseTime:date "," * "previousLockTime=" previousLockTime:date ")" *
| project resourceName, totalSlices, sliceNumber, lockTime, releaseTime, previousLockTime
```

### 2. Extract Data from Structured String Data

**Dynamic Fields**:

**Definition**: Fields containing key-value pairs (JSON-like structure)

**Example Dynamic Field**:
```json
{
    "eventCategory": "Autoscale",
    "eventName": "GetOperationStatusResult",
    "operationId": "xxxxxxxx-6a53-4aed-bab4-575642a10226",
    "eventProperties": "{\"OldInstancesCount\":6,\"NewInstancesCount\":5}"
}
```

**Access with Dot Notation**:
```kql
SigninLogs
| extend OS = DeviceDetail.operatingSystem
```

**Dynamic Fields Example**:
```kql
SigninLogs
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend Date = startofday(TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails
| sort by Date
```

**JSON Functions and Operators**:

| Function | Description |
|----------|-------------|
| **parse-json()** or **todynamic()** | Interprets string as JSON, returns dynamic value. Access: `JsonField.Key` or `JsonField["Key"]` |
| **mv-expand** | Expands dynamic array/property bag so each value gets separate row. Duplicates other columns. Easiest way to process JSON arrays |
| **mv-apply** | Applies subquery to each record, returns union of all subquery results. Query each array value |

**JSON Examples**:
```kql
// Parse JSON and extract fields
SigninLogs
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend AuthMethod = AuthDetails[0].authenticationMethod
| extend AuthResult = AuthDetails[0].["authenticationStepResultDetail"]
| project AuthMethod, AuthResult, AuthDetails

// Expand JSON array (each value gets separate row)
SigninLogs
| mv-expand AuthDetails = parse_json(AuthenticationDetails)
| project AuthDetails

// Apply query to JSON array elements
SigninLogs
| mv-apply AuthDetails = parse_json(AuthenticationDetails) on
    (where AuthDetails.authenticationMethod == "Password")
```

### 3. Integrate External Data

**externaldata Operator**:

**Purpose**: Return table with data from external storage (Azure Blob Storage, Azure Data Lake)

**Syntax**:
```kql
externaldata ( ColumnName : ColumnType [, ...] )
[ StorageConnectionString [, ...] ]
[with ( PropertyName = PropertyValue [, ...] )]
```

**Arguments**:
- **ColumnName, ColumnType**: Define table schema (same syntax as `create table`)
- **StorageConnectionString**: Storage artifacts holding data
- **PropertyName, PropertyValue**: Additional properties

**Supported Properties**:

| Property | Type | Description |
|----------|------|-------------|
| **format** | string | Data format (CSV default if not specified, supports all ingestion formats) |
| **ignoreFirstRecord** | bool | If true, ignore first record (useful for CSV headers) |
| **ingestionMapping** | string | How to map source data to result columns |

**Example**:
```kql
Users
| where UserID in (
    (externaldata (UserID:string) [
        @"https://storageaccount.blob.core.windows.net/storagecontainer/users.txt"
        h@"?...SAS..."  // Secret token for blob access
    ])
)
| ...
```

**Note**: Not available in demo environment

### 4. Create Parsers with Functions

**Purpose**: Create reusable functions for parsing unstructured string fields (e.g., Syslog data)

**Parsers**: Functions defining virtual tables with pre-parsed unstructured data

**Create Function**:
1. Write query in Logs window
2. Select **Save** button
3. Enter **Name**
4. Select **Save As Function** from dropdown

**Example**:
```kql
// Original query
SecurityEvent
| where EventID == 4672 and AccountType == 'User'

// Save as function named "PrivLogins"

// Use function
PrivLogins
```

**Benefits**:
- Reusability across multiple queries
- Consistent parsing logic
- Simplified complex queries
- Easy to maintain and update

**Use Cases**:
- Parse Syslog messages
- Extract data from custom logs
- Standardize data access patterns
- Create virtual tables for common queries

---

## Summary

This comprehensive module covers Kusto Query Language (KQL) for Microsoft Sentinel across four major areas:

**I. Construct KQL Statements**:
- **Statement Structure**: Read-only requests, tabular data flow with pipe `|`, schema hierarchy
- **Search Operator**: Multi-table/multi-column search (easy but inefficient)
- **Where Operator**: Filter rows with predicates (efficient, recommended)
- **Let Statement**: Bind variables, create functions, dynamic tables, improve modularity
- **Extend Operator**: Add calculated columns without removing existing ones
- **Order By Operator**: Sort by multiple columns (asc/desc)
- **Project Operators**: Control column inclusion/exclusion (project, project-away, project-keep, project-rename, project-reorder)

**II. Analyze Query Results**:
- **Summarize Operator**: Aggregate data with 10+ functions (count, dcount, avg, max, min, percentile, stdev, sum, variance)
- **Filter Results**: Use summarize with where to filter aggregated data
- **Prepare Data**: Transform and prepare for visualization
- **Render Operator**: Create visualizations (areachart, barchart, columnchart, piechart, scatterchart, timechart)
- **bin() Function**: Group time-series data for visualization

**III. Build Multi-Table Statements**:
- **Union Operator**: Combine rows from multiple tables, supports wildcards
- **Join Operator**: Merge tables by matching columns
- **Join Flavors**: 8 types (inner, leftouter, rightouter, fullouter, leftanti, rightanti, leftsemi, rightsemi)
- **Table References**: Left/right table designation, column qualification

**IV. Work with Data**:
- **Extract from Unstructured**: extract (regex-based), parse (pattern-based) operators
- **Extract from Structured**: Dynamic fields with dot notation, JSON functions (parse-json, mv-expand, mv-apply)
- **External Data**: externaldata operator for Azure Blob/Data Lake integration
- **Parsers**: Save queries as functions for reusable parsing logic

**Key Takeaways**:
- **Pipeline Model**: Data flows left to right through pipe `|` operator
- **Performance**: Use where over search, project to limit columns
- **Modularity**: Let statements improve code reusability
- **Aggregation**: Summarize with rich function library
- **Visualization**: Built-in rendering for quick insights
- **Multi-Table**: Union for combining, join for merging with various flavors
- **Data Extraction**: Powerful regex and pattern-based parsing
- **JSON Support**: Native handling of dynamic fields and JSON structures
- **External Data**: Integration with Azure storage for enrichment
- **Reusability**: Function-based parsers for consistent data access

**Best Practices**:
- Start with where clauses to filter early
- Use project to limit result set size
- Chain operators for complex transformations
- Use let for variables and reusable logic
- Choose appropriate join flavor for use case
- Use bin() for time-series aggregation
- Create functions for common parsing patterns
- Leverage dynamic fields for JSON data
- Use extract for simple regex patterns
- Use parse for complex structured data

**Common Patterns**:
```kql
// Time-series analysis
Table
| where TimeGenerated > ago(7d)
| summarize Count=count() by bin(TimeGenerated, 1h)
| render timechart

// Multi-table correlation
Table1
| where Condition
| join kind=inner (
    Table2
    | where Condition
) on CommonField

// Parse unstructured data
Table
| extend ParsedField = extract(@"Pattern", 1, RawField)
| where ParsedField != ""

// JSON handling
Table
| extend JsonData = parse_json(DynamicField)
| mv-expand JsonArray = JsonData.ArrayField
| project Field1, Field2, JsonArray
```
