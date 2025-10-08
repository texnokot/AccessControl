# Entra + Azure RBAC App-only Audit

## Overview
App-only audit of Microsoft Entra directory roles and Azure resource RBAC across Management Group and Subscription scopes.

## Purpose
Produce a unified report of permanent and PIM-eligible assignments for Users, Groups, and Service Principals (including Managed Identities).

## Description
- Enumerates Entra directory permanent assignments (unifiedRoleAssignments) and PIM eligibilities, plus Azure resource RBAC permanent assignments and PIM eligibilities at management group and subscription scopes.
- Resolves principals in batches, enriches users with UPN, and tags managed identities when detectable; preserves rows even when principals are deleted or cannot be resolved by falling back to assignment payload names.
- Normalizes role names and IDs across providers, renders friendly scope names for management groups and subscriptions, and deduplicates Azure permanent results across overlapping scopes.

## Features
- Permanent RBAC: Users, Groups, Service Principals (incl. Managed Identities).
- PIM eligibilities: Entra directory roles and Azure resource RBAC.
- Principal resolution with display name and UPN enrichment; resilient fallbacks for orphaned principals.
- Role name/ID normalization and friendly scope labels; de-duplication across scopes.

## Output Columns
Scope, RoleName, RoleNameId, ObjectType, DisplayName, ObjectId, UPN, AssignmentType (Eligible|Permanent), Provider (Entra|Azure).

## Prerequisites
PowerShell modules:
- Microsoft.Graph
- Az.Accounts
- Az.Resources

Microsoft Graph application permissions (admin-consented):
- Directory.Read.All
- Group.Read.All
- RoleManagement.Read.Directory
- RoleManagement.Read.All (or the granular Azure RBAC read application permission, as permitted by tenant policy) for Azure Resource PIM

Azure RBAC for the app’s service principal:
- Reader (or higher) at the tenant root management group and/or at each management group/subscription to be enumerated.

## Authentication
- Microsoft Graph: App-only (certificate or client secret), no delegated scopes.
- Azure: Sign in with the same service principal used for Graph.

## Scope Coverage and Limits
- Management group and subscription scopes are covered by default; add resource group or resource scopes if deeper coverage is required.
- Azure permanent assignments are de-duplicated by (PrincipalId, Scope, RoleDefinition) to avoid repeated rows due to inheritance across queried scopes.

## Performance Notes
- Principal lookups are batched to reduce Graph round trips; selective Get-MgUser calls backfill UPNs only for user objects missing that value.
- Role definition names are cached per provider to minimize repeated role lookups.

## Author
Victoria Almazova (texnokot)

## Date
2025-10-03

## Version
1.0
