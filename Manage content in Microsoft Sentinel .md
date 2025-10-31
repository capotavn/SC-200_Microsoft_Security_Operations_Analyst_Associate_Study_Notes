# Microsoft Sentinel Summary

## Content Hub
- Central hub for discovering and deploying out-of-the-box solutions and content
- Provides filtering and powerful text search capabilities
- Enables one-step installation of complete content packages
- Content includes:
  - Data connectors
  - Workbooks
  - Analytics rules
  - Playbooks
  - Hunting queries
  - Parsers
  - Watchlists
  - And more
- Solutions maintained by Microsoft, partners, or the community
- Updates can be managed directly from the Content hub
- Powered by Azure Marketplace for discoverability and deployment

## Repositories
- Connects Microsoft Sentinel with external source control repositories
- Supported platforms: GitHub and Azure DevOps only
- Enables automatic deployment of custom content to workspaces
- **Prerequisites:**
  - Owner role in resource group (or User Access Administrator + Sentinel Contributor combination)
  - Content must be in ARM template format
- **Limitations:**
  - Maximum 5 connections per workspace
  - Maximum 800 deployments per resource group
- **Supported content types:**
  - Analytics rules
  - Automation rules
  - Hunting queries
  - Parsers
  - Playbooks
  - Workbooks
- **Connection process:**
  - Authorize with GitHub/Azure DevOps credentials
  - Select repository and branch
  - Choose content types to deploy
  - Workflow/pipeline automatically generated after connection
  - Content automatically deployed from repository to workspace
