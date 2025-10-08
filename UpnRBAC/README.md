# Unified Role Audit Script

## Overview

Unified role audit for **Entra ID directory roles**, **Azure RBAC** across tenant/management group/subscription scopes (including **PIM** eligibility and activations), and **Exchange Online RBAC** effective assignments — with **HTML reporting** and **CSV exports**.

---

## Description

This script:

- Collects **Entra ID directory role assignments and eligibility** via Microsoft Graph, including **PIM for Groups** schedules where the user is active or eligible.  
- Enumerates **Azure RBAC role eligibility and assignment schedules** across all scopes.  
- Resolves **effective Exchange Online RBAC** granted via role groups and direct assignments.  
- Renders a styled **HTML report** and writes structured **CSV files**.

The Exchange section connects interactively using modern authentication (with device code fallback), while Graph and Az modules use delegated user context to read role and PIM schedules for the target principal.

---

## Features

- **Entra ID:**  
  Reads unified directory role assignments for the target principal and enumerates role eligibility schedules, including PIM-for-Groups membership and role exposure.  

- **Azure RBAC:**  
  Lists role eligibility schedules and active assignment schedules at tenant, management group, subscription, resource group, and resource scopes, including PIM-based activations.  

- **Exchange Online:**  
  Discovers effective RBAC by aggregating `ManagementRoleAssignment` results from role groups containing the user and any direct assignments after an authenticated EXO session.  

- **Reporting:**  
  Builds a multi-section HTML report using `ConvertTo-Html` with table fragments and simple CSS for readability.  

- **Export:**  
  Writes per-section CSVs for:
  - Exchange RBAC  
  - Entra roles (assigned/eligible)  
  - PIM groups (detailed/compact)  
  - Azure RBAC/PIM  

---

## Outputs

- **HTML Report:**  
  Contains sections for:
  - Exchange Online RBAC  
  - Entra ID directory roles  
  - PIM Groups (detailed and compact)  
  - Azure RBAC/PIM schedules  
  Suitable for browser viewing.

- **CSV Files:**  
  Saved alongside the script or in the current directory:
  - `Exchange_RBAC.csv`  
  - `Entra_Roles_Assigned.csv`  
  - `Entra_Roles_Eligible.csv`  
  - `PIM_Groups_Detailed.csv`  
  - `PIM_Groups_Compact.csv`  
  - `Azure_RBAC.csv`

---

## Prerequisites

- **Modules Required:**
  - `ExchangeOnlineManagement`
  - `Microsoft.Graph.Identity.Governance`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Groups`
  - `Microsoft.Graph.Authentication`
  - `Az.Accounts`
  - `Az.Resources`

- **PowerShell:**  
  PowerShell 7+ recommended (especially for device code authentication with EXO module).

- **Permissions:**  
  Sufficient access to read:
  - Exchange RBAC  
  - Graph role management and PIM objects  
  - Azure RBAC schedules  

---

## Authentication

- **Exchange Online:**  
  Interactive user sign-in; attempts `DisableWAM`, falls back to device code, then standard interactive.

- **Microsoft Graph (Delegated):**  
  Required permissions:
  - `RoleManagement.Read.Directory`  
  - `Directory.Read.All`  
  - `Group.Read.All`  
  - `PrivilegedEligibilitySchedule.Read.AzureADGroup`  
  - `PrivilegedAssignmentSchedule.Read.AzureADGroup`  
  - `PrivilegedAccess.Read.AzureADGroup`  
  *(Admin consent typically required.)*

- **Azure (Az):**  
  Signed-in user via `Connect-AzAccount`; enumerates RBAC/PIM using the caller’s effective permissions.

---

## Limitations

- **Exchange section** is user-interactive — no app-only authentication (unattended EXO enumeration is out of scope).  
- **Visibility** limited by the signed-in principal’s permissions.  
- **PIM for Groups** data depends on Graph delegated permissions for group-based assignment and eligibility schedules.  
- Focuses on **Exchange RBAC** — does not enumerate per-mailbox permissions beyond `ManagementRoleAssignment`.

---

## Author

**Victoria Almazova (texnokot)**

---

## Date

**2025-10-08**

---

## Version

**1.0**
