# Microsoft Sentinel SIEM — Cloud Security Monitoring Lab

![Azure](https://img.shields.io/badge/Microsoft_Azure-0089D6?style=flat&logo=microsoft-azure&logoColor=white)
![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)
![Status](https://img.shields.io/badge/Status-Complete-success)

## Overview

A production-grade Microsoft Sentinel SIEM deployment demonstrating real-world cloud security monitoring, custom threat detection, automated incident response, and proactive threat hunting. This lab connects multiple data sources, implements custom KQL detection rules mapped to the MITRE ATT&CK framework, simulates real attacks, and walks through a complete incident response workflow.

## Technologies Used

- Microsoft Sentinel (SIEM)
- Azure Log Analytics
- KQL (Kusto Query Language)
- MITRE ATT&CK Framework
- Azure Activity Logs
- Azure Key Vault
- Microsoft Defender Suite
- Azure CLI
- REST API

## Architecture

```
Microsoft Sentinel Deployment
│
├── Log Analytics Workspace (sentinel-workspace)
│     └── Data Retention: 30 days
│
├── Data Connectors (9 connected)
│     ├── Azure Activity — subscription level events
│     ├── Azure Key Vault — secret access and vault operations
│     ├── Microsoft Defender for Cloud Apps
│     ├── Microsoft Defender for Endpoint
│     ├── Microsoft Defender for Identity
│     ├── Microsoft Defender for Office 365
│     ├── Microsoft Defender XDR
│     ├── Microsoft Entra ID Protection
│     └── Microsoft 365 Insider Risk Management
│
├── Custom Detection Rules (KQL)
│     ├── Key Vault Secret Access Detected
│     │     ├── Severity: Medium
│     │     ├── Tactic: CredentialAccess (MITRE ATT&CK)
│     │     └── Frequency: Every 5 minutes
│     ├── SSH Brute Force Attack Detected
│     │     ├── Severity: High
│     │     ├── Tactic: InitialAccess (MITRE ATT&CK)
│     │     └── Frequency: Every 5 minutes
│     └── Azure Policy Modified or Deleted
│           ├── Severity: High
│           ├── Tactic: DefenseEvasion (MITRE ATT&CK)
│           └── Frequency: Every 5 minutes
│
├── Built-in Rules
│     └── Advanced Multistage Attack Detection (Fusion ML)
│
├── Watchlist
│     └── Authorized Admins
│
└── Automation Rules
      └── Auto Assign New Incidents — assigns and activates on creation
```

## Implementation Details

### Step 1 — Sentinel Deployment
Deployed Microsoft Sentinel on a dedicated Log Analytics workspace using the Azure REST API. Registered the Microsoft.SecurityInsights resource provider and enabled Sentinel via the onboarding endpoint. Connected Azure Activity logs through Azure Monitor diagnostic settings to capture all subscription-level events.

**Key decision:** Created a dedicated workspace for Sentinel rather than reusing the existing Project 1 workspace — separation of concerns ensures security monitoring data is isolated from general infrastructure logs.

### Step 2 — Data Connector Configuration
Connected 9 data sources to Sentinel providing comprehensive visibility across identity, endpoint, cloud apps, and infrastructure. The Microsoft Defender suite connected automatically due to existing subscription configuration, providing immediate coverage across multiple attack surfaces without additional configuration.

**Key decision:** Prioritized breadth of data sources over depth — connecting multiple connectors gives Sentinel the correlation capability to detect multi-stage attacks that span multiple systems.

### Step 3 — Custom KQL Detection Rules
Wrote three custom detection rules from scratch using KQL, each mapped to a specific MITRE ATT&CK tactic:

- **Key Vault Secret Access** — queries AzureDiagnostics for SecretGet operations, mapped to CredentialAccess. Detects potential credential theft or unauthorized secret retrieval.
- **SSH Brute Force** — queries Syslog auth logs for failed password attempts, summarizes by host and 5 minute window, triggers when count exceeds 5. Mapped to InitialAccess.
- **Azure Policy Modification** — queries AzureActivity for policy assignment write and delete operations. Mapped to DefenseEvasion — attackers often remove security controls before executing their main objective.

**Key decision:** Wrote custom rules rather than relying solely on built-in templates — custom rules demonstrate understanding of the specific threat landscape and data sources in the environment.

### Step 4 — Attack Simulation and Incident Response
Simulated two real attacks to generate Sentinel incidents:

- **Credential access simulation** — retrieved a Key Vault secret from inside the VM using managed identity, triggering the Key Vault detection rule
- **Brute force simulation** — generated 10 failed SSH login attempts against localhost using sshpass, triggering the SSH brute force rule

Completed a full incident response workflow: detection → triage → investigation → classification → closure. Closed incident as Benign Positive with classification reason SuspiciousButExpected — documenting that the activity was authorized testing.

### Step 5 — Threat Hunting and Automation
Created a watchlist of authorized admin accounts for use in detection rule enrichment. Built an automation rule that automatically assigns new incidents and sets status to Active — reducing mean time to acknowledge. Executed a proactive threat hunting query against Azure Activity logs identifying the top operations performed in the subscription and confirming all activity was expected and explainable.

**Key decision:** Combined reactive detection rules with proactive threat hunting — rules catch known patterns automatically while hunting finds anomalies that rules haven't been written for yet.

## KQL Detection Rules

### Key Vault Secret Access
```kql
AzureDiagnostics
| where ResourceType == 'VAULTS'
| where OperationName == 'SecretGet'
```
**MITRE ATT&CK:** CredentialAccess | **Severity:** Medium | **Frequency:** 5 minutes

---

### SSH Brute Force Attack
```kql
Syslog
| where Facility == 'auth'
| where SyslogMessage contains 'Failed password'
| summarize FailedAttempts = count() by HostIP, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
```
**MITRE ATT&CK:** InitialAccess | **Severity:** High | **Frequency:** 5 minutes

---

### Azure Policy Modified or Deleted
```kql
AzureActivity
| where OperationNameValue contains 'MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS'
| where ActivityStatusValue == 'Success'
| where OperationNameValue contains 'DELETE' or OperationNameValue contains 'WRITE'
```
**MITRE ATT&CK:** DefenseEvasion | **Severity:** High | **Frequency:** 5 minutes

---

### Threat Hunting — Top Operations
```kql
AzureActivity
| summarize count() by OperationNameValue
| top 10 by count_
```
**Purpose:** Proactive hunting to identify unusual operation volumes or unexpected activity patterns

## CLI Command Reference

### Create Log Analytics Workspace
```bash
az monitor log-analytics workspace create --resource-group secure-infra-rg --workspace-name sentinel-workspace --location eastus
```

### Enable Microsoft Sentinel
```bash
az rest --method put --url "https://management.azure.com/subscriptions/<your-subscription-id>/resourceGroups/secure-infra-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" --body '{"properties":{}}'
```

### Connect Key Vault Diagnostics
```bash
az monitor diagnostic-settings create --name "sentinel-keyvault" --resource /subscriptions/<your-subscription-id>/resourceGroups/secure-infra-rg/providers/Microsoft.KeyVault/vaults/secure-kv-brayden --workspace /subscriptions/<your-subscription-id>/resourceGroups/secure-infra-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace --logs '[{"category":"AuditEvent","enabled":true}]' --metrics '[{"category":"AllMetrics","enabled":true}]'
```

### Create Detection Rule — Key Vault Secret Access
```bash
az rest --method put --url "https://management.azure.com/subscriptions/<your-subscription-id>/resourceGroups/secure-infra-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace/providers/Microsoft.SecurityInsights/alertRules/keyvault-secret-access?api-version=2023-02-01" --body '{"kind":"Scheduled","properties":{"displayName":"Key Vault Secret Access Detected","description":"Detects when secrets are accessed from Key Vault","severity":"Medium","enabled":true,"query":"AzureDiagnostics | where ResourceType == \"VAULTS\" | where OperationName == \"SecretGet\"","queryFrequency":"PT5M","queryPeriod":"PT5M","triggerOperator":"GreaterThan","triggerThreshold":0,"suppressionEnabled":false,"suppressionDuration":"PT1H","tactics":["CredentialAccess"]}}'
```

### Create Detection Rule — SSH Brute Force
```bash
az rest --method put --url "https://management.azure.com/subscriptions/<your-subscription-id>/resourceGroups/secure-infra-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace/providers/Microsoft.SecurityInsights/alertRules/ssh-brute-force?api-version=2023-02-01" --body '{"kind":"Scheduled","properties":{"displayName":"SSH Brute Force Attack Detected","description":"Detects multiple failed SSH login attempts indicating a brute force attack","severity":"High","enabled":true,"query":"Syslog | where Facility == \"auth\" | where SyslogMessage contains \"Failed password\" | summarize FailedAttempts = count() by HostIP, bin(TimeGenerated, 5m) | where FailedAttempts > 5","queryFrequency":"PT5M","queryPeriod":"PT5M","triggerOperator":"GreaterThan","triggerThreshold":0,"suppressionEnabled":false,"suppressionDuration":"PT1H","tactics":["InitialAccess"]}}'
```

### Create Detection Rule — Azure Policy Modified
```bash
az rest --method put --url "https://management.azure.com/subscriptions/<your-subscription-id>/resourceGroups/secure-infra-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace/providers/Microsoft.SecurityInsights/alertRules/policy-modified?api-version=2023-02-01" --body '{"kind":"Scheduled","properties":{"displayName":"Azure Policy Modified or Deleted","description":"Detects when Azure Policy assignments are created, modified, or deleted","severity":"High","enabled":true,"query":"AzureActivity | where OperationNameValue contains \"MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS\" | where ActivityStatusValue == \"Success\" | where OperationNameValue contains \"DELETE\" or OperationNameValue contains \"WRITE\"","queryFrequency":"PT5M","queryPeriod":"PT5M","triggerOperator":"GreaterThan","triggerThreshold":0,"suppressionEnabled":false,"suppressionDuration":"PT1H","tactics":["DefenseEvasion"]}}'
```

### Create Automation Rule
```bash
az rest --method put --url "https://management.azure.com/subscriptions/<your-subscription-id>/resourceGroups/secure-infra-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace/providers/Microsoft.SecurityInsights/automationRules/auto-assign-incidents?api-version=2023-02-01" --body '{"properties":{"displayName":"Auto Assign New Incidents","order":1,"triggeringLogic":{"isEnabled":true,"triggersOn":"Incidents","triggersWhen":"Created","conditions":[]},"actions":[{"order":1,"actionType":"ModifyProperties","actionConfiguration":{"status":"Active","owner":{"objectId":"<your-object-id>"}}}]}}'
```

### List Detection Rules
```bash
az sentinel alert-rule list --resource-group secure-infra-rg --workspace-name sentinel-workspace --output table
```

### List Incidents
```bash
az sentinel incident list --resource-group secure-infra-rg --workspace-name sentinel-workspace --output table
```

### Threat Hunting Query
```bash
$body = '{"query":"AzureActivity | summarize count() by OperationNameValue | top 10 by count_"}'
az rest --method post --url "https://api.loganalytics.io/v1/workspaces/<your-workspace-id>/query" --body $body
```

## Security Decisions

| Decision | What Was Used | Production Alternative | Reason Not Used |
|---|---|---|---|
| SIEM deployment | Microsoft Sentinel free tier | Sentinel with paid data ingestion | Lab scale data volume stays within free tier |
| Data connectors | Diagnostic settings + built-in connectors | Sentinel data collection rules | Connectors sufficient for lab scope |
| Detection rules | Custom KQL scheduled rules | Built-in rule templates | Custom rules demonstrate deeper understanding |
| Incident response | CLI based workflow | Defender portal | Personal account licensing restriction |
| Threat hunting | Manual KQL queries | Sentinel hunting notebooks | Notebooks require Defender portal access |
| Automation | Basic property modification rule | Logic App playbooks | Logic Apps add cost and complexity for lab scope |

## What I Would Add in Production

- **Logic App playbooks** — automated response actions like blocking IPs, disabling accounts, or notifying teams via Teams or email when high severity incidents fire
- **Entity behavior analytics (UEBA)** — detects anomalous user and entity behavior using machine learning baselines
- **Threat intelligence feeds** — connect threat intel providers to automatically flag known malicious IPs and domains
- **Hunting notebooks** — Jupyter notebooks for complex multi-step threat hunting investigations
- **Workbooks** — custom dashboards showing security posture, incident trends, and detection coverage over time
- **SOC playbooks** — documented response procedures for each detection rule so analysts follow consistent investigation steps
- **Data collection rules** — more granular control over exactly which logs are collected to optimize cost
- **Cross workspace queries** — query across multiple Sentinel workspaces for enterprise-wide visibility

## Incident Response Workflow

1. **Detection** — Custom KQL rule identifies suspicious activity and creates incident
2. **Triage** — Automation rule assigns incident and sets status to Active
3. **Investigation** — Analyst reviews incident timeline, affected entities, and related alerts
4. **Classification** — Incident classified as True Positive, Benign Positive, or False Positive
5. **Closure** — Incident closed with documented classification reason
6. **Lessons Learned** — Detection rules tuned based on findings

## Lessons Learned

- Microsoft Sentinel CLI support is experimental — REST API calls are more reliable for complex operations
- PowerShell pipe characters conflict with KQL queries — storing queries in variables resolves the issue
- Spot VM eviction is visible in Azure Activity logs — useful for distinguishing expected vs unexpected VM shutdowns
- MITRE ATT&CK tactic mapping transforms a detection rule from a technical alert into a threat intelligence artifact
- Threat hunting and detection rules serve different purposes — rules catch known patterns, hunting finds unknown ones
- Personal Microsoft account tenants have licensing restrictions that affect Sentinel portal access — organizational accounts are required for full Defender portal functionality

## Author

**Brayden Miller**
[LinkedIn](https://www.linkedin.com/in/brayden-miller13/) | [GitHub](https://github.com/BraydenMiller-CloudSec)

---
*Built as part of a hands-on Azure cloud security portfolio. See my other projects on GitHub.*
