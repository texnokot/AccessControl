<#
SYNOPSIS
  Unified role audit for Entra ID directory roles, Azure RBAC across tenant/management group/subscription scopes including PIM eligibility and activations, and Exchange Online RBAC effective assignments, with HTML reporting and CSV exports. 

DESCRIPTION
  Collects Entra ID directory role assignments and eligibility via Microsoft Graph, includes PIM for Groups schedules where the user is active or eligible, enumerates Azure RBAC role eligibility and assignment schedules across scopes, 
  and resolves effective Exchange Online RBAC granted via role groups and direct assignments, 
  then renders a styled HTML report and writes structured CSV files. 
  The Exchange section connects interactively using modern authentication and supports device code fallback, while Graph and Az modules use delegated user context to read role and PIM schedules for the target principal. 

.FEATURES
  - Entra ID: reads unified directory role assignments for the target principal and enumerates role eligibility schedules, including PIM-for-Groups membership and role exposure. 
  - Azure RBAC: lists role eligibility schedules and active assignment schedules at tenant, management group, subscription, resource group, and resource scopes, including PIM-based activations. 
  - Exchange Online: discovers effective RBAC by aggregating ManagementRoleAssignment results from role groups containing the user and any direct assignments after an authenticated EXO session. 
  - Reporting: builds a multi-section HTML report from objects using ConvertTo-Html with table fragments and simple CSS for readability. 
  - Export: writes per-section CSVs using Export-Csv for Exchange RBAC, Entra roles (assigned/eligible), PIM groups (detailed/compact), and Azure RBAC/PIM. 

OUTPUTS
  - HTML report containing sections for Exchange Online RBAC, Entra ID directory roles, PIM Groups (detailed and compact), and Azure RBAC/PIM schedules, suitable for browser viewing. 
  - CSV files saved alongside the script or current directory for Exchange_RBAC, Entra_Roles_Assigned, Entra_Roles_Eligible, PIM_Groups_Detailed, PIM_Groups_Compact, and Azure_RBAC datasets. 

PREREQUISITES
  - Modules: ExchangeOnlineManagement, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Authentication, Az.Accounts, Az.Resources. 
  - PowerShell 7+ recommended for device code authentication scenarios with the EXO module when no browser is available. 
  - Sufficient permissions to read Exchange RBAC, Graph role management and PIM objects, and Azure RBAC schedules as documented by their respective cmdlets. 

AUTHENTICATION
  - Exchange Online: Interactive user sign-in; attempts DisableWAM, falls back to device code, then standard interactive.
  - Microsoft Graph (delegated): RoleManagement.Read.Directory; Directory.Read.All; Group.Read.All; PrivilegedEligibilitySchedule.Read.AzureADGroup; PrivilegedAssignmentSchedule.Read.AzureADGroup; PrivilegedAccess.Read.AzureADGroup (admin consent typically required).
  - Azure (Az): Signed-in user via Connect-AzAccount; enumerates RBAC/PIM using the caller’s effective permissions.

LIMITATIONS
  - Exchange section is user-interactive and does not implement app-only authentication, so unattended EXO enumeration is out of scope here. 
  - Visibility is constrained by the signed-in principal’s effective permissions; cmdlets return only data authorized for the caller. 
  - PIM for Groups data availability depends on Graph delegated permissions sufficient to read group-based assignment and eligibility schedules. 
  - The report focuses on Exchange RBAC and does not enumerate per-mailbox permissions beyond what ManagementRoleAssignment exposes. 
#>


param()

# -------------------- Input with guard --------------------
$upn = Read-Host "Enter User Principal Name (UPN)"
if ([string]::IsNullOrWhiteSpace($upn)) {
  Write-Host "No UPN provided; exiting." -ForegroundColor Yellow  
  return
}

# -------------------- Exchange Online RBAC (user-permissions, no child, no app-only) --------------------
Write-Host ">> Exchange Online RBAC (user-permissions interactive)" -ForegroundColor Magenta

# Light cleanup to avoid MSAL/WAM and assembly collisions 
try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}  
try { Remove-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue } catch {}
[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()

# Ensure EXO module
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
  try {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction Stop
  } catch {
    Write-Host ("Failed to install ExchangeOnlineManagement: {0}" -f $_.Exception.Message) -ForegroundColor Red  
  }
}
$workloadRbac = @()

if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
  Import-Module ExchangeOnlineManagement -ErrorAction Stop  

  # Interactive connection sequence: DisableWAM -> Device -> plain 
  function Connect-EXO-Interactive {
    try {
      Connect-ExchangeOnline -DisableWAM -ShowBanner:$false -ErrorAction Stop
      return
    } catch {
      try {
        Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
        return
      } catch {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        return
      }
    }
  }

  try {
    Connect-EXO-Interactive

    # Helper: robust member match for UPN in role group members 
    function Test-MemberMatch {
      param(
        [Parameter(Mandatory=$true)]$Member,
        [Parameter(Mandatory=$true)][string]$Upn
      )
      $candidates = @()
      foreach ($p in 'PrimarySmtpAddress','ExternalDirectoryObjectId','WindowsLiveID','Name','DisplayName','Alias','Identity','UserPrincipalName','SamAccountName') {
        if ($Member.PSObject.Properties[$p]) {
          $val = [string]$Member.$p
          if (-not [string]::IsNullOrWhiteSpace($val)) { $candidates += $val }
        }
      }
      return ($candidates | Where-Object { $_ -and ($_ -ieq $Upn) }) -ne $null
    }

    # Resolve all role groups containing the user
    Write-Host "Resolving Exchange role groups for $upn ..." -ForegroundColor Cyan
    $allRoleGroups = @(); try { $allRoleGroups = Get-RoleGroup -ResultSize Unlimited } catch {}
    $userRoleGroups = @()
    foreach ($rg in $allRoleGroups) {
      try {
        $members = Get-RoleGroupMember -Identity $rg.Identity -ResultSize Unlimited  # enumerate members 
        if ($members | Where-Object { Test-MemberMatch -Member $_ -Upn $upn }) {
          $userRoleGroups += $rg.Identity
        }
      } catch {}
    }
    $userRoleGroups = $userRoleGroups | Select-Object -Unique

    # Aggregate all ManagementRoleAssignments granted to those groups 
    foreach ($rg in $userRoleGroups) {
      try {
        $rgAssigns = Get-ManagementRoleAssignment -RoleAssignee $rg -ErrorAction Stop  # assignments for role group 
      } catch { $rgAssigns = @() }
      foreach ($ar in $rgAssigns) {
        $scopeText = if ($ar.Scope) { $ar.Scope } elseif ($ar.RecipientWriteScope) { $ar.RecipientWriteScope } else { $ar.ScopeType }
        $workloadRbac += [PSCustomObject]@{
          Workload          = 'Exchange'
          Role              = $ar.Role
          AssignmentSource  = "Group: $rg"
          Scope             = $scopeText
          RoleAssigneeType  = 'RoleGroup'
          RoleAssigneeName  = $rg
        }
      }
    }

    # Include direct user assignments (if any) 
    try { $directAssigns = Get-ManagementRoleAssignment -RoleAssignee $upn -ErrorAction Stop } catch { $directAssigns = @() }
    foreach ($ar in $directAssigns) {
      $scopeText = if ($ar.Scope) { $ar.Scope } elseif ($ar.RecipientWriteScope) { $ar.RecipientWriteScope } else { $ar.ScopeType }
      $workloadRbac += [PSCustomObject]@{
        Workload          = 'Exchange'
        Role              = $ar.Role
        AssignmentSource  = 'Direct'
        Scope             = $scopeText
        RoleAssigneeType  = $ar.RoleAssigneeType
        RoleAssigneeName  = $ar.RoleAssigneeName
      }
    }
  } catch {
    Write-Host ("Exchange Online interactive RBAC query failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow  
  } finally {
    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
  }
} else {
  Write-Host "ExchangeOnlineManagement is not available; Exchange RBAC section skipped." -ForegroundColor Yellow  
}

# -------------------- Ensure modules (Graph/Az) --------------------
# Microsoft Graph targeted submodules (avoid broad Microsoft.Graph) 
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
  Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.Governance)) {
  Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Groups)) {
  Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
  Install-Module Az.Accounts -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
  Install-Module Az.Resources -Scope CurrentUser -Force
}

# Import required submodules
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.Governance
Import-Module Microsoft.Graph.Groups
Import-Module Az.Accounts
Import-Module Az.Resources  

# -------------------- Connect Graph & Azure --------------------
# Include PIM-for-Groups read scopes to ensure schedules are retrievable 
Connect-MgGraph -Scopes `
  "RoleManagement.Read.Directory",
  "Directory.Read.All",
  "Group.Read.All",
  "PrivilegedEligibilitySchedule.Read.AzureADGroup",
  "PrivilegedAssignmentSchedule.Read.AzureADGroup",
  "PrivilegedAccess.Read.AzureADGroup"   

Connect-AzAccount | Out-Null  # no context switching; use -Scope everywhere 

# Resolve user
$user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ConsistencyLevel eventual -CountVariable c | Select-Object -First 1  # robust lookup 
if ($null -eq $user) {
  Write-Host "User not found in Entra ID; exiting." -ForegroundColor Yellow  # guard
  Disconnect-MgGraph
  return
}
$userId = $user.Id 

Write-Host "`n=== Roles for $($user.DisplayName) <$upn> ===`n" -ForegroundColor Cyan

# -------------------- Entra ID (directory) roles --------------------
Write-Host ">> Entra ID (Directory) Roles" -ForegroundColor Magenta

$entraAssigned = @()
$assignedRoles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$userId'"  
foreach ($r in ($assignedRoles | ForEach-Object { $_ })) {
  $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $r.RoleDefinitionId  # includes custom roles 
  $entraAssigned += [PSCustomObject]@{ Type='Permanent'; Role=$rd.DisplayName }
}
if (-not $entraAssigned) { Write-Host "No permanent Entra ID roles." -ForegroundColor Yellow }  

$entraEligible = @()
$eligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$userId'"  
foreach ($r in ($eligibleRoles | ForEach-Object { $_ })) {
  $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $r.RoleDefinitionId  
  $entraEligible += [PSCustomObject]@{ Type='Eligible'; Role=$rd.DisplayName }
}
if (-not $entraEligible) { Write-Host "No eligible Entra ID roles." -ForegroundColor Yellow }  

# -------------------- Entra PIM groups (PIM for Groups) --------------------
Write-Host "`n>> PIM Groups & Roles" -ForegroundColor Magenta

$allGroupEntries = @()

# Eligible schedules for the user (PIM eligible) 
try {
  $eligAll = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "principalId eq '$userId'" -All
} catch { $eligAll = @() }
foreach ($e in $eligAll) {
  $allGroupEntries += [PSCustomObject]@{
    GroupId         = $e.GroupId
    MembershipState = "Eligible"
  }
}

# Assignment schedules for the user (PIM active/assigned)
try {
  $assignAll = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedule -Filter "principalId eq '$userId'" -All
} catch { $assignAll = @() }
foreach ($a in $assignAll) {
  $allGroupEntries += [PSCustomObject]@{
    GroupId         = $a.GroupId
    MembershipState = "Active"
  }
}

# Include static group membership (non-PIM) for completeness 
try {
  $directGroups = Get-MgUserMemberOf -UserId $userId -All | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" }
} catch { $directGroups = @() }
foreach ($g in $directGroups) {
  $allGroupEntries += [PSCustomObject]@{
    GroupId         = $g.Id
    MembershipState = "PermanentMember"
  }
}

# Group name lookup
$allUserGroupIds = ($allGroupEntries | Select-Object -ExpandProperty GroupId -Unique)
$groupNameById = @{}
foreach ($gid in $allUserGroupIds) {
  try {
    $grp = Get-MgGroup -GroupId $gid -ErrorAction Stop
    $groupNameById[$gid] = $grp.DisplayName
  } catch { }
}

$allGroupEntries = $allGroupEntries | Sort-Object GroupId, MembershipState -Unique
if (-not $allGroupEntries) {
  Write-Host "No PIM group memberships or group memberships found." -ForegroundColor Yellow
} else {
  foreach ($entry in $allGroupEntries) {
    $gname = $groupNameById[$entry.GroupId]; if (-not $gname) { $gname = $entry.GroupId }
    Write-Host "`nGroup: $gname — MembershipState: $($entry.MembershipState)" -ForegroundColor Cyan

    # Show Entra directory roles assigned to the group (if any) 
    $grpAssigned = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($entry.GroupId)'"
    $grpEligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($entry.GroupId)'"

    if ($grpAssigned) {
      foreach ($r in $grpAssigned) {
        $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $r.RoleDefinitionId
        Write-Output (" GroupPermanentRole: {0}" -f $rd.DisplayName)
      }
    }
    if ($grpEligible) {
      foreach ($r in $grpEligible) {
        $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $r.RoleDefinitionId
        Write-Output (" GroupEligibleRole: {0}" -f $rd.DisplayName)
      }
    }
    if (-not ($grpAssigned -or $grpEligible)) {
      Write-Host "  (No Entra ID role assignments on this group)" -ForegroundColor Yellow
    }
  }
}

# Build structured rows for HTML from the PIM groups discovered above
$pimGroupRows = New-Object System.Collections.Generic.List[object]
foreach ($entry in $allGroupEntries) {
  $gname = if ($groupNameById.ContainsKey($entry.GroupId)) { $groupNameById[$entry.GroupId] } else { $entry.GroupId }
  $grpAssigned = @(); try { $grpAssigned = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($entry.GroupId)'" } catch {}
  $grpEligible = @(); try { $grpEligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($entry.GroupId)'" } catch {}

  if ($grpAssigned -and $grpAssigned.Count -gt 0) {
    foreach ($r in $grpAssigned) {
      try { $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $r.RoleDefinitionId; $roleName=$rd.DisplayName } catch { $roleName=$r.RoleDefinitionId }
      $pimGroupRows.Add([pscustomobject]@{
        GroupName       = $gname
        GroupId         = $entry.GroupId
        MembershipState = $entry.MembershipState
        EntraRoleType   = 'GroupPermanentRole'
        EntraRole       = $roleName
      })
    }
  }
  if ($grpEligible -and $grpEligible.Count -gt 0) {
    foreach ($r in $grpEligible) {
      try { $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $r.RoleDefinitionId; $roleName=$rd.DisplayName } catch { $roleName=$r.RoleDefinitionId }
      $pimGroupRows.Add([pscustomobject]@{
        GroupName       = $gname
        GroupId         = $entry.GroupId
        MembershipState = $entry.MembershipState
        EntraRoleType   = 'GroupEligibleRole'
        EntraRole       = $roleName
      })
    }
  }
  if ((-not $grpAssigned -or $grpAssigned.Count -eq 0) -and (-not $grpEligible -or $grpEligible.Count -eq 0)) {
    $pimGroupRows.Add([pscustomobject]@{
      GroupName       = $gname
      GroupId         = $entry.GroupId
      MembershipState = $entry.MembershipState
      EntraRoleType   = '(none)'
      EntraRole       = ''
    })
  }
}

# Enrichment: de-duplicate PIM group rows and add a compact grouped view 
$pimGroupUnique = @()
if ($pimGroupRows.Count -gt 0) {
  $seen = @{}
  foreach ($row in $pimGroupRows) {
    $k = "$($row.GroupId)|$($row.MembershipState)|$($row.EntraRoleType)|$($row.EntraRole)"
    if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $pimGroupUnique += $row }
  }
}

# Compact grouped summary per group: join distinct roles by type to shorten report 
$pimGroupCompact = @()
if ($pimGroupUnique.Count -gt 0) {
  $groups = $pimGroupUnique | Group-Object GroupId, GroupName, MembershipState
  foreach ($g in $groups) {
    $rows = $g.Group
    $perm = $rows | Where-Object { $_.EntraRoleType -eq 'GroupPermanentRole' -and $_.EntraRole } | Select-Object -ExpandProperty EntraRole -Unique
    $elig = $rows | Where-Object { $_.EntraRoleType -eq 'GroupEligibleRole' -and $_.EntraRole } | Select-Object -ExpandProperty EntraRole -Unique
    $pimGroupCompact += [pscustomobject]@{
      GroupName       = $rows[0].GroupName
      GroupId         = $rows[0].GroupId
      MembershipState = $rows[0].MembershipState
      PermanentRoles  = ($perm -join ", ")
      EligibleRoles   = ($elig -join ", ")
    }
  }
}

# -------------------- Azure RBAC + Azure PIM --------------------
Write-Host "`n>> Azure RBAC Roles (all scopes with PIM group detection)" -ForegroundColor Magenta  

$subscriptions = Get-AzSubscription  # enumerate without selecting context 
$subNameById = @{}; foreach ($s in $subscriptions) { $subNameById[$s.Id.ToString().ToLower()] = $s.Name }

$roleDefNameById = @{}
function Resolve-RoleDefName([string]$roleDefId) {
  if ([string]::IsNullOrWhiteSpace($roleDefId)) { return $null }
  $guid = $roleDefId
  $m = [regex]::Match($roleDefId, "/providers/Microsoft.Authorization/roleDefinitions/([0-9a-fA-F-]{36})$")
  if ($m.Success) { $guid = $m.Groups[1].Value }
  $key = $guid.ToLower()
  if ($roleDefNameById.ContainsKey($key)) { return $roleDefNameById[$key] }
  try { $rd = Get-AzRoleDefinition -Id $guid -ErrorAction Stop; if ($rd -and $rd.Name) { $roleDefNameById[$key] = $rd.Name; return $rd.Name } } catch {}
  return $null
}

function Get-SubscriptionIdFromScope ([string]$scope) {
  if ([string]::IsNullOrWhiteSpace($scope)) { return $null }
  $m = [regex]::Match($scope, "/subscriptions/([0-9a-fA-F-]{36})")
  if ($m.Success) { return $m.Groups[1].Value }
  return $null
}
function Get-AppliedAt ([string]$scope) {
  if (-not $scope) { return "Unknown" }
  if ($scope -eq "/") { return "Tenant" }
  if ($scope -like "/providers/Microsoft.Management/managementGroups/*") { return "ManagementGroup" }
  if ($scope -like "/subscriptions/*/resourceGroups/*/providers/*/*") { return "Resource" }
  if ($scope -like "/subscriptions/*/resourceGroups/*") { return "ResourceGroup" }
  if ($scope -like "/subscriptions/*") { return "Subscription" }
  return "Unknown"
}

$rbacOutput = New-Object System.Collections.Generic.List[object]

# Tenant root (direct only)
try { $tenantAssignments = Get-AzRoleAssignment -ObjectId $userId -Scope "/" -ErrorAction Stop } catch { $tenantAssignments = @() }
foreach ($ar in $tenantAssignments) {
  $rbacOutput.Add([PSCustomObject]@{
    AppliedAt="Tenant"; ManagementGroupId=$null; SubscriptionId=$null; SubscriptionName=$null;
    RoleDefinitionId=$null; RoleDefinitionName=$ar.RoleDefinitionName; Scope=$ar.Scope;
    AssignmentState="ActivePermanent"; AssignmentSource="Direct"
  })
}

# Management groups (direct)
try { $mgList = Get-AzManagementGroup -ErrorAction Stop } catch { $mgList = @() }
foreach ($mg in $mgList) {
  $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
  try { $mgAssignments = Get-AzRoleAssignment -ObjectId $userId -Scope $mgScope -ErrorAction Stop } catch { $mgAssignments = @() }
  foreach ($ar in $mgAssignments) {
    $rbacOutput.Add([PSCustomObject]@{
      AppliedAt="ManagementGroup"; ManagementGroupId=$mg.Name; SubscriptionId=$null; SubscriptionName=$null;
      RoleDefinitionId=$null; RoleDefinitionName=$ar.RoleDefinitionName; Scope=$ar.Scope;
      AssignmentState="ActivePermanent"; AssignmentSource="Direct"
    })
  }
}

# Subscriptions & below: classic + PIM schedules
foreach ($sub in $subscriptions) {
  $subScope = "/subscriptions/$($sub.Id)"

  # Classic direct
  try { $assignmentsAtSubScope = Get-AzRoleAssignment -ObjectId $userId -Scope $subScope -ErrorAction Stop } catch { $assignmentsAtSubScope = @() }
  foreach ($ar in $assignmentsAtSubScope) {
    $sid = Get-SubscriptionIdFromScope -scope $ar.Scope
    $sname = $null; if ($sid) { $sname = $subNameById[$sid.ToLower()] }
    $rbacOutput.Add([PSCustomObject]@{
      AppliedAt=Get-AppliedAt $ar.Scope; ManagementGroupId=$null; SubscriptionId=$sid; SubscriptionName=$sname;
      RoleDefinitionId=$null; RoleDefinitionName=$ar.RoleDefinitionName; Scope=$ar.Scope;
      AssignmentState="ActivePermanent"; AssignmentSource="Direct"
    })
  }

  # PIM eligible 
  try { $eligSchedules = Get-AzRoleEligibilitySchedule -Scope $subScope -ErrorAction Stop } catch { $eligSchedules = @() }
  foreach ($es in $eligSchedules) {
    $isGroup=$false; $grpName=$null
    if ($allUserGroupIds -and $es.PrincipalId) {
      if ($allUserGroupIds -contains $es.PrincipalId) { $isGroup=$true; $grpName=$groupNameById[$es.PrincipalId]; if (-not $grpName) { $grpName=$es.PrincipalId } }
    }
    if ($es.PrincipalId -eq $userId -or $isGroup) {
      $sid = Get-SubscriptionIdFromScope -scope $es.Scope
      $sname = $null; if ($sid) { $sname = $subNameById[$sid.ToLower()] }
      $roleName = if ($es.PSObject.Properties.Match('RoleDefinitionName').Count -gt 0 -and $es.RoleDefinitionName) { $es.RoleDefinitionName } else { Resolve-RoleDefName $es.RoleDefinitionId }
      $rbacOutput.Add([PSCustomObject]@{
        AppliedAt=Get-AppliedAt $es.Scope; ManagementGroupId=$null; SubscriptionId=$sid; SubscriptionName=$sname;
        RoleDefinitionId=$es.RoleDefinitionId; RoleDefinitionName=$roleName; Scope=$es.Scope;
        AssignmentState="Eligible"; AssignmentSource=($isGroup ? "PIM-Group: $grpName" : "Direct")
      })
    }
  }

  # PIM active (activations) 
  try { $actSchedules = Get-AzRoleAssignmentSchedule -Scope $subScope -ErrorAction Stop } catch { $actSchedules = @() }
  foreach ($as in $actSchedules) {
    $isGroup=$false; $grpName=$null
    if ($allUserGroupIds -and $as.PrincipalId) {
      if ($allUserGroupIds -contains $as.PrincipalId) { $isGroup=$true; $grpName=$groupNameById[$as.PrincipalId]; if (-not $grpName) { $grpName=$as.PrincipalId } }
    }
    if ($as.PrincipalId -eq $userId -or $isGroup) {
      $sid = Get-SubscriptionIdFromScope -scope $as.Scope
      $sname = $null; if ($sid) { $sname = $subNameById[$sid.ToLower()] }
      $roleName = if ($as.PSObject.Properties.Match('RoleDefinitionName').Count -gt 0 -and $as.RoleDefinitionName) { $as.RoleDefinitionName } else { Resolve-RoleDefName $as.RoleDefinitionId }
      $state = ($as.EndDateTime) ? "ActiveTimeBound" : "ActivePermanent"
      $rbacOutput.Add([PSCustomObject]@{
        AppliedAt=Get-AppliedAt $as.Scope; ManagementGroupId=$null; SubscriptionId=$sid; SubscriptionName=$sname;
        RoleDefinitionId=$as.RoleDefinitionId; RoleDefinitionName=$roleName; Scope=$as.Scope;
        AssignmentState=$state; AssignmentSource=($isGroup ? "PIM-Group: $grpName" : "Direct")
      })
    }
  }
}

# Deduplicate Azure RBAC
$unique = @{}
$rbacDedup = foreach ($e in $rbacOutput) {
  $ridKey = if ($e.RoleDefinitionId) { $e.RoleDefinitionId } else { $e.RoleDefinitionName }
  $key = ($ridKey + "|" + $e.Scope + "|" + $e.AssignmentState + "|" + $e.AssignmentSource)
  if (-not $unique.ContainsKey($key)) { $unique[$key] = $true; $e }
}

# -------------------- HTML report --------------------
$style = @"
<style>
body { font-family: Segoe UI, Arial, Helvetica, sans-serif; margin: 20px; }
h1 { font-size: 20px; margin-bottom: 8px; }
h2 { font-size: 16px; margin-top: 20px; margin-bottom: 6px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px 8px; font-size: 12px; }
th { background-color: #f3f4f6; text-align: left; }
.section { margin-bottom: 24px; }
.note { color: #555; font-size: 12px; }
</style>
"@  # Simple CSS 

$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$pageTitle = "Unified Role Report for $upn — $now"
$header = "<h1>$pageTitle</h1><div class='note'>Generated by PowerShell</div>"

# Build fragments as strings (normalize to non-null) 
$exoTable = if ($workloadRbac -and $workloadRbac.Count -gt 0) {
  $workloadRbac |
    Sort-Object Workload, Role, AssignmentSource, Scope |
    Select-Object Workload, Role, AssignmentSource, Scope, RoleAssigneeType, RoleAssigneeName |
    ConvertTo-Html -As Table -PreContent "<h2>Exchange Online RBAC</h2>" -Fragment  
} else {
  "<div class='note'><h2>Exchange Online RBAC</h2>No Exchange Online RBAC entries found for $upn.</div>"
}

$entraCombined = @()
if ($entraAssigned) { $entraCombined += $entraAssigned }
if ($entraEligible) { $entraCombined += $entraEligible }
$entraTable = if ($entraCombined -and $entraCombined.Count -gt 0) {
  $entraCombined |
    Sort-Object Type, Role |
    Select-Object Type, Role |
    ConvertTo-Html -As Table -PreContent "<h2>Entra ID Directory Roles</h2>" -Fragment 
} else {
  "<div class='note'><h2>Entra ID Directory Roles</h2>No Entra ID directory roles.</div>"
}

# Detailed PIM Groups & Roles table 
$pimGroupsTable = if ($pimGroupUnique -and $pimGroupUnique.Count -gt 0) {
  $pimGroupUnique |
    Sort-Object GroupName, MembershipState, EntraRoleType, EntraRole |
    Select-Object GroupName, GroupId, MembershipState, EntraRoleType, EntraRole |
    ConvertTo-Html -As Table -PreContent "<h2>PIM Groups & Roles (Detailed)</h2>" -Fragment
} else {
  "<div class='note'><h2>PIM Groups & Roles (Detailed)</h2>No PIM group memberships or assigned roles.</div>"
}

# Compact grouped PIM summary (enrichment) 
$pimGroupsCompactTable = if ($pimGroupCompact -and $pimGroupCompact.Count -gt 0) {
  $pimGroupCompact |
    Sort-Object GroupName, MembershipState |
    Select-Object GroupName, GroupId, MembershipState, PermanentRoles, EligibleRoles |
    ConvertTo-Html -As Table -PreContent "<h2>PIM Groups & Roles (Compact Summary)</h2>" -Fragment
} else {
  "<div class='note'><h2>PIM Groups & Roles (Compact Summary)</h2>No PIM group memberships or roles.</div>"
}

$azureTable = if ($rbacDedup -and $rbacDedup.Count -gt 0) {
  $rbacDedup |
    Sort-Object AppliedAt, SubscriptionName, AssignmentSource, AssignmentState, RoleDefinitionName, Scope |
    Select-Object AppliedAt, SubscriptionId, SubscriptionName, RoleDefinitionName, RoleDefinitionId, AssignmentState, AssignmentSource, Scope |
    ConvertTo-Html -As Table -PreContent "<h2>Azure RBAC and PIM</h2>" -Fragment  
} else {
  "<div class='note'><h2>Azure RBAC and PIM</h2>No Azure RBAC roles found.</div>"
}

# Assemble the page
$html = ConvertTo-Html -Head $style -Title $pageTitle -PreContent $header -Body @"
<div class='section'>
$exoTable
</div>
<div class='section'>
$entraTable
</div>
<div class='section'>
$pimGroupsTable
</div>
<div class='section'>
$pimGroupsCompactTable
</div>
<div class='section'>
$azureTable
</div>
"@  

# Cross-platform temp directory and opener
if ($IsWindows) {
  $tempDir = $env:TEMP
  $openCmd = { param($p) Invoke-Item $p }
} elseif ($IsMacOS) {
  $tempDir = $env:TMPDIR; if ([string]::IsNullOrWhiteSpace($tempDir)) { $tempDir = "/tmp" }
  $openCmd = { param($p) & open $p }
} else {
  $tempDir = $env:TMPDIR; if ([string]::IsNullOrWhiteSpace($tempDir)) { $tempDir = "/tmp" }
  $openCmd = { param($p) & xdg-open $p }
}
if ([string]::IsNullOrWhiteSpace($tempDir)) { $tempDir = [System.IO.Path]::GetTempPath() }

$outFile = Join-Path $tempDir ("Unified-Roles-Report_{0}.html" -f ([Guid]::NewGuid().ToString("N")))
$html | Out-File -FilePath $outFile -Encoding UTF8  # write report 
Write-Host ("Report written to: {0}" -f $outFile) -ForegroundColor Green

try {
  & $openCmd.InvokeReturnAsIs($outFile)
} catch {
  Write-Host "Could not auto-open the report; open this path manually: $outFile" -ForegroundColor Yellow
}

# -------------------- CSV export to script folder --------------------
# Determine export folder: script directory if available, else current location 
$exportFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
try {
  if (-not (Test-Path -LiteralPath $exportFolder)) { New-Item -ItemType Directory -Path $exportFolder -Force | Out-Null }
} catch {}

$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
function Safe-ExportCsv($obj, [string]$path) {
  try {
    if ($obj -and $obj.Count -gt 0) {
      $obj | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
      Write-Host ("CSV written: {0}" -f $path) -ForegroundColor Green
    } else {
      # Write empty CSV with headers if possible
      $obj | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
      Write-Host ("CSV created (empty): {0}" -f $path) -ForegroundColor Yellow
    }
  } catch {
    Write-Host ("Failed to write CSV {0}: {1}" -f $path, $_.Exception.Message) -ForegroundColor Yellow
  }
}

# Build shaped arrays for consistent CSV headers
$csv_EXO   = $workloadRbac | Sort-Object Workload, Role, AssignmentSource, Scope | Select-Object Workload, Role, AssignmentSource, Scope, RoleAssigneeType, RoleAssigneeName  
$csv_ER_As = $entraAssigned | Sort-Object Role | Select-Object Type, Role  
$csv_ER_El = $entraEligible | Sort-Object Role | Select-Object Type, Role  
$csv_PIM_D = $pimGroupUnique | Sort-Object GroupName, MembershipState, EntraRoleType, EntraRole | Select-Object GroupName, GroupId, MembershipState, EntraRoleType, EntraRole  
$csv_PIM_C = $pimGroupCompact | Sort-Object GroupName, MembershipState | Select-Object GroupName, GroupId, MembershipState, PermanentRoles, EligibleRoles  
$csv_AZRB  = $rbacDedup | Sort-Object AppliedAt, SubscriptionName, AssignmentSource, AssignmentState, RoleDefinitionName, Scope |
            Select-Object AppliedAt, SubscriptionId, SubscriptionName, RoleDefinitionName, RoleDefinitionId, AssignmentState, AssignmentSource, Scope  

Safe-ExportCsv $csv_EXO   (Join-Path $exportFolder ("Exchange_RBAC_{0}.csv" -f $ts))
Safe-ExportCsv $csv_ER_As (Join-Path $exportFolder ("Entra_Roles_Assigned_{0}.csv" -f $ts))
Safe-ExportCsv $csv_ER_El (Join-Path $exportFolder ("Entra_Roles_Eligible_{0}.csv" -f $ts))
Safe-ExportCsv $csv_PIM_D (Join-Path $exportFolder ("PIM_Groups_Detailed_{0}.csv" -f $ts))
Safe-ExportCsv $csv_PIM_C (Join-Path $exportFolder ("PIM_Groups_Compact_{0}.csv" -f $ts))
Safe-ExportCsv $csv_AZRB  (Join-Path $exportFolder ("Azure_RBAC_{0}.csv" -f $ts))

Write-Host ("All CSVs saved under: {0}" -f $exportFolder) -ForegroundColor Cyan

# -------------------- Disconnect Graph --------------------
Disconnect-MgGraph  # clean up Graph session 
