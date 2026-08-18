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
  - PowerShell 7.0 or later is required (the script uses ternary operators and other PS7-only syntax; it will not parse on Windows PowerShell 5.1).
  - Modules: ExchangeOnlineManagement, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Authentication, Az.Accounts, Az.Resources. 
  - Sufficient permissions to read Exchange RBAC, Graph role management and PIM objects, and Azure RBAC schedules as documented by their respective cmdlets. 

AUTHENTICATION
  - Exchange Online: Interactive user sign-in; tries standard interactive first, falls back to device code, then DisableWAM (a documented Microsoft workaround for WAM/MSAL compatibility issues, not a first choice).
  - Microsoft Graph (delegated): RoleManagement.Read.Directory; Directory.Read.All; Group.Read.All; PrivilegedEligibilitySchedule.Read.AzureADGroup; PrivilegedAssignmentSchedule.Read.AzureADGroup; PrivilegedAccess.Read.AzureADGroup (admin consent typically required).
  - Azure (Az): Signed-in user via Connect-AzAccount; enumerates RBAC/PIM using the caller’s effective permissions. The script verifies the Graph and Az sessions are in the same tenant and warns if not.

LIMITATIONS
  - Exchange section is user-interactive and does not implement app-only authentication, so unattended EXO enumeration is out of scope here. 
  - Visibility is constrained by the signed-in principal’s effective permissions; cmdlets return only data authorized for the caller. 
  - PIM for Groups data availability depends on Graph delegated permissions sufficient to read group-based assignment and eligibility schedules. 
  - The report focuses on Exchange RBAC and does not enumerate per-mailbox permissions beyond what ManagementRoleAssignment exposes. 
  - Non-fatal errors (failed lookups, throttled calls, etc.) are collected and surfaced in a dedicated "Collection Warnings/Errors" section of the report instead of being silently swallowed.
#>

#Requires -Version 7.0

param()

# Collects non-fatal errors/warnings from throughout the run so they are surfaced in the report
# instead of being silently discarded by empty catch blocks.
$script:auditIssues = New-Object System.Collections.Generic.List[object]
function Add-AuditIssue {
  param(
    [Parameter(Mandatory=$true)][string]$Area,
    [Parameter(Mandatory=$true)][string]$Message
  )
  $script:auditIssues.Add([PSCustomObject]@{ Area = $Area; Message = $Message; Timestamp = (Get-Date) })
  Write-Host ("[{0}] {1}" -f $Area, $Message) -ForegroundColor DarkYellow
}

# Wraps known, script-controlled cell values (assignment source/state, membership
# state) in colored <span> "chip" markup after ConvertTo-Html has already HTML-encoded
# the fragment. This only rewrites literal, well-known tokens the script itself emits
# (e.g. "Direct", "Active", "Group: <name>") — it never touches free-form user input,
# so it can't be used to inject markup via a crafted UPN or display name.
function Format-Badges {
  param([Parameter(Mandatory=$true)][string]$Html)
  $map = @(
    @{ Pattern = '<td>Direct</td>';               Class = 'chip chip-direct';  Text = 'Direct' }
    @{ Pattern = '<td>(Group: [^<]+)</td>';        Class = 'chip chip-group' }
    @{ Pattern = '<td>(PIM-Group: [^<]+)</td>';    Class = 'chip chip-pim' }
    @{ Pattern = '<td>Active</td>';                Class = 'chip chip-active'; Text = 'Active' }
    @{ Pattern = '<td>Eligible</td>';              Class = 'chip chip-eligible'; Text = 'Eligible' }
    @{ Pattern = '<td>Assigned</td>';              Class = 'chip chip-active'; Text = 'Assigned' }
  )
  foreach ($m in $map) {
    if ($m.Text) {
      $Html = $Html -replace [regex]::Escape("<td>$($m.Text)</td>"), "<td><span class=`"$($m.Class)`">$($m.Text)</span></td>"
    } else {
      $Html = $Html -replace $m.Pattern, "<td><span class=`"$($m.Class)`">`$1</span></td>"
    }
  }
  return $Html
}

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
    Add-AuditIssue -Area 'Exchange' -Message ("Failed to install ExchangeOnlineManagement: {0}" -f $_.Exception.Message)
  }
}
$workloadRbac = @()

if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
  Import-Module ExchangeOnlineManagement -ErrorAction Stop  

  # Interactive connection sequence: plain interactive -> Device -> DisableWAM.
  # DisableWAM is a documented Microsoft workaround for WAM/MSAL compatibility issues
  # (see "Resolve issues in Exchange Online PowerShell after WAM integration") and
  # should be attempted last, not first.
  function Connect-EXO-Interactive {
    try {
      Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
      return
    } catch {
      try {
        Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
        return
      } catch {
        Connect-ExchangeOnline -DisableWAM -ShowBanner:$false -ErrorAction Stop
        return
      }
    }
  }

  try {
    Connect-EXO-Interactive

    # Resolve effective Exchange RBAC for the user in a single call. -GetEffectiveUsers
    # expands role-group and USG membership (including nested groups) server-side,
    # which is far more reliable than manually enumerating Get-RoleGroupMember results
    # and string-matching identity properties.
    Write-Host "Resolving effective Exchange RBAC for $upn ..." -ForegroundColor Cyan
    $effectiveAssigns = @()
    try {
      $effectiveAssigns = Get-ManagementRoleAssignment -GetEffectiveUsers -ErrorAction Stop |
        Where-Object {
          $_.EffectiveUserName -and ($_.EffectiveUserName -ieq $upn)
        }
    } catch {
      Add-AuditIssue -Area 'Exchange' -Message ("Get-ManagementRoleAssignment -GetEffectiveUsers failed: {0}" -f $_.Exception.Message)
    }

    foreach ($ar in $effectiveAssigns) {
      $scopeText = if ($ar.Scope) { $ar.Scope } elseif ($ar.RecipientWriteScope) { $ar.RecipientWriteScope } else { $ar.ScopeType }
      $source = if ($ar.RoleAssigneeType -match 'RoleGroup|USG|SecurityGroup') { "Group: $($ar.RoleAssigneeName)" } else { 'Direct' }
      $workloadRbac += [PSCustomObject]@{
        Workload          = 'Exchange'
        Role              = $ar.Role
        AssignmentSource  = $source
        Scope             = $scopeText
        RoleAssigneeType  = $ar.RoleAssigneeType
        RoleAssigneeName  = $ar.RoleAssigneeName
      }
    }

    # Fallback: if -GetEffectiveUsers returned nothing (e.g. insufficient permission for
    # that parameter), still surface any direct assignment to the user so the section
    # isn't silently empty.
    if ($workloadRbac.Count -eq 0) {
      try {
        $directAssigns = Get-ManagementRoleAssignment -RoleAssignee $upn -ErrorAction Stop
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
        Add-AuditIssue -Area 'Exchange' -Message ("Fallback direct RBAC query failed: {0}" -f $_.Exception.Message)
      }
    }
  } catch {
    Add-AuditIssue -Area 'Exchange' -Message ("Exchange Online interactive RBAC query failed: {0}" -f $_.Exception.Message)
  } finally {
    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
  }
} else {
  Add-AuditIssue -Area 'Exchange' -Message 'ExchangeOnlineManagement is not available; Exchange RBAC section skipped.'
}

# -------------------- Ensure modules (Graph/Az) --------------------
# Microsoft Graph targeted submodules (avoid broad Microsoft.Graph). These modules are
# required (unlike ExchangeOnlineManagement above); if installation fails, stop rather
# than continue into a session that will error on every subsequent cmdlet.
function Install-RequiredModule([string]$Name) {
  if (Get-Module -ListAvailable -Name $Name) { return }
  try {
    Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
  } catch {
    throw "Failed to install required module '$Name': $($_.Exception.Message)"
  }
}

foreach ($moduleName in 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Identity.Governance','Microsoft.Graph.Groups','Az.Accounts','Az.Resources') {
  Install-RequiredModule -Name $moduleName
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

# Verify Graph and Az sessions are in the same tenant; otherwise the report would silently
# mix directory/PIM data from one tenant with Azure RBAC data from another.
try {
  $graphTenantId = (Get-MgContext).TenantId
  $azTenantId = (Get-AzContext).Tenant.Id
  if ($graphTenantId -and $azTenantId -and ($graphTenantId -ne $azTenantId)) {
    Add-AuditIssue -Area 'Auth' -Message ("Graph tenant ({0}) and Az tenant ({1}) do not match; results may be inconsistent." -f $graphTenantId, $azTenantId)
  }
} catch {
  Add-AuditIssue -Area 'Auth' -Message ("Could not verify Graph/Az tenant consistency: {0}" -f $_.Exception.Message)
}

# Resolve user. -UserId accepts a UPN directly, avoiding manual OData filter escaping.
$user = $null
try {
  $user = Get-MgUser -UserId $upn -ErrorAction Stop
} catch {
  Add-AuditIssue -Area 'Entra' -Message ("Get-MgUser failed for {0}: {1}" -f $upn, $_.Exception.Message)
}
if ($null -eq $user) {
  Write-Host "User not found in Entra ID; exiting." -ForegroundColor Yellow  # guard
  Disconnect-MgGraph
  return
}
$userId = $user.Id 

Write-Host "`n=== Roles for $($user.DisplayName) <$upn> ===`n" -ForegroundColor Cyan

# -------------------- Entra ID (directory) roles --------------------
Write-Host ">> Entra ID (Directory) Roles" -ForegroundColor Magenta

# Cache directory role definitions across sections (Entra roles + group-assigned roles)
# to avoid repeated Get-MgRoleManagementDirectoryRoleDefinition calls for the same role.
$directoryRoleDefCache = @{}
function Resolve-DirectoryRoleDefName([string]$roleDefinitionId) {
  if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) { return $null }
  if ($directoryRoleDefCache.ContainsKey($roleDefinitionId)) { return $directoryRoleDefCache[$roleDefinitionId] }
  try {
    $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $roleDefinitionId -ErrorAction Stop
    $directoryRoleDefCache[$roleDefinitionId] = $rd.DisplayName
    return $rd.DisplayName
  } catch {
    Add-AuditIssue -Area 'Entra' -Message ("Could not resolve role definition {0}: {1}" -f $roleDefinitionId, $_.Exception.Message)
    return $roleDefinitionId
  }
}

$entraAssigned = @()
$assignedRoles = @()
try { $assignedRoles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$userId'" -All -ErrorAction Stop } catch { Add-AuditIssue -Area 'Entra' -Message ("Failed to read permanent role assignments: {0}" -f $_.Exception.Message) }
foreach ($r in $assignedRoles) {
  $roleName = Resolve-DirectoryRoleDefName $r.RoleDefinitionId  # includes custom roles
  $entraAssigned += [PSCustomObject]@{ Type='Permanent'; Role=$roleName }
}
if (-not $entraAssigned) { Write-Host "No permanent Entra ID roles." -ForegroundColor Yellow }  

$entraEligible = @()
$eligibleRoles = @()
try { $eligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$userId'" -All -ErrorAction Stop } catch { Add-AuditIssue -Area 'Entra' -Message ("Failed to read eligible role schedules: {0}" -f $_.Exception.Message) }
foreach ($r in $eligibleRoles) {
  $roleName = Resolve-DirectoryRoleDefName $r.RoleDefinitionId
  $entraEligible += [PSCustomObject]@{ Type='Eligible'; Role=$roleName }
}
if (-not $entraEligible) { Write-Host "No eligible Entra ID roles." -ForegroundColor Yellow }  

# -------------------- Entra PIM groups (PIM for Groups) --------------------
Write-Host "`n>> PIM Groups & Roles" -ForegroundColor Magenta

$allGroupEntries = @()

# Eligible schedules for the user (PIM eligible) 
$eligAll = @()
try {
  $eligAll = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "principalId eq '$userId'" -All -ErrorAction Stop
} catch { Add-AuditIssue -Area 'PIM Groups' -Message ("Failed to read group eligibility schedules: {0}" -f $_.Exception.Message) }
foreach ($e in $eligAll) {
  $allGroupEntries += [PSCustomObject]@{
    GroupId         = $e.GroupId
    MembershipState = "Eligible"
  }
}

# Assignment schedules for the user (PIM active/assigned)
$assignAll = @()
try {
  $assignAll = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedule -Filter "principalId eq '$userId'" -All -ErrorAction Stop
} catch { Add-AuditIssue -Area 'PIM Groups' -Message ("Failed to read group assignment schedules: {0}" -f $_.Exception.Message) }
foreach ($a in $assignAll) {
  $allGroupEntries += [PSCustomObject]@{
    GroupId         = $a.GroupId
    MembershipState = "Active"
  }
}

# Include group membership (non-PIM) for completeness. Transitive membership is used so
# that nested groups (user -> group A -> group B) are captured, not just direct membership,
# since nested membership also affects inherited Entra/Azure roles.
$directGroups = @()
try {
  $directGroups = Get-MgUserTransitiveMemberOfAsGroup -UserId $userId -All -ErrorAction Stop
} catch { Add-AuditIssue -Area 'PIM Groups' -Message ("Failed to read transitive group membership: {0}" -f $_.Exception.Message) }
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
  } catch {
    Add-AuditIssue -Area 'PIM Groups' -Message ("Failed to resolve group name for {0}: {1}" -f $gid, $_.Exception.Message)
  }
}

$allGroupEntries = $allGroupEntries | Sort-Object GroupId, MembershipState -Unique
if (-not $allGroupEntries) {
  Write-Host "No PIM group memberships or group memberships found." -ForegroundColor Yellow
}

# Build structured rows for HTML from the PIM groups discovered above. Each group's role
# assignments/eligibilities are fetched exactly once (previously this was fetched twice:
# once for console display, once for the HTML rows).
$pimGroupRows = New-Object System.Collections.Generic.List[object]
foreach ($entry in $allGroupEntries) {
  $gname = if ($groupNameById.ContainsKey($entry.GroupId)) { $groupNameById[$entry.GroupId] } else { $entry.GroupId }
  Write-Host "`nGroup: $gname — MembershipState: $($entry.MembershipState)" -ForegroundColor Cyan

  $grpAssigned = @()
  $grpEligible = @()
  try { $grpAssigned = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($entry.GroupId)'" -All -ErrorAction Stop } catch { Add-AuditIssue -Area 'PIM Groups' -Message ("Failed to read permanent roles for group {0}: {1}" -f $gname, $_.Exception.Message) }
  try { $grpEligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($entry.GroupId)'" -All -ErrorAction Stop } catch { Add-AuditIssue -Area 'PIM Groups' -Message ("Failed to read eligible roles for group {0}: {1}" -f $gname, $_.Exception.Message) }

  if ($grpAssigned -and $grpAssigned.Count -gt 0) {
    foreach ($r in $grpAssigned) {
      $roleName = Resolve-DirectoryRoleDefName $r.RoleDefinitionId
      Write-Output (" GroupPermanentRole: {0}" -f $roleName)
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
      $roleName = Resolve-DirectoryRoleDefName $r.RoleDefinitionId
      Write-Output (" GroupEligibleRole: {0}" -f $roleName)
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
    Write-Host "  (No Entra ID role assignments on this group)" -ForegroundColor Yellow
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

$subscriptions = @()
try { $subscriptions = Get-AzSubscription -ErrorAction Stop } catch { Add-AuditIssue -Area 'Azure RBAC' -Message ("Failed to enumerate subscriptions: {0}" -f $_.Exception.Message) }
$subNameById = @{}; foreach ($s in $subscriptions) { $subNameById[$s.Id.ToString().ToLower()] = $s.Name }

$roleDefNameById = @{}
function Resolve-RoleDefName([string]$roleDefId) {
  if ([string]::IsNullOrWhiteSpace($roleDefId)) { return $null }
  $guid = $roleDefId
  $m = [regex]::Match($roleDefId, "/providers/Microsoft.Authorization/roleDefinitions/([0-9a-fA-F-]{36})$")
  if ($m.Success) { $guid = $m.Groups[1].Value }
  $key = $guid.ToLower()
  if ($roleDefNameById.ContainsKey($key)) { return $roleDefNameById[$key] }
  try {
    $rd = Get-AzRoleDefinition -Id $guid -ErrorAction Stop
    if ($rd -and $rd.Name) { $roleDefNameById[$key] = $rd.Name; return $rd.Name }
  } catch {
    Add-AuditIssue -Area 'Azure RBAC' -Message ("Could not resolve role definition {0}: {1}" -f $guid, $_.Exception.Message)
  }
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

# Classifies a classic Get-AzRoleAssignment result as "Direct" or via a group the user
# belongs to (works across Az module versions that expose either PrincipalId or ObjectId).
function Get-AzRoleAssignmentSource($ar) {
  $principalId = if ($ar.PSObject.Properties.Match('PrincipalId').Count -gt 0) { $ar.PrincipalId } elseif ($ar.PSObject.Properties.Match('ObjectId').Count -gt 0) { $ar.ObjectId } else { $null }
  if ($principalId -and $allUserGroupIds -and ($allUserGroupIds -contains $principalId)) {
    $grpName = $groupNameById[$principalId]; if (-not $grpName) { $grpName = $principalId }
    return "Group: $grpName"
  }
  return 'Direct'
}

# Tenant root (direct + group-inherited via -ExpandPrincipalGroups)
$tenantAssignments = @()
try { $tenantAssignments = Get-AzRoleAssignment -ObjectId $userId -Scope "/" -ExpandPrincipalGroups -ErrorAction Stop } catch { Add-AuditIssue -Area 'Azure RBAC' -Message ("Failed to read tenant-root role assignments: {0}" -f $_.Exception.Message) }
foreach ($ar in $tenantAssignments) {
  $rbacOutput.Add([PSCustomObject]@{
    AppliedAt="Tenant"; ManagementGroupId=$null; SubscriptionId=$null; SubscriptionName=$null;
    RoleDefinitionId=$null; RoleDefinitionName=$ar.RoleDefinitionName; Scope=$ar.Scope;
    AssignmentState="ActivePermanent"; AssignmentSource=(Get-AzRoleAssignmentSource $ar)
  })
}

# Management groups (direct + group-inherited)
$mgList = @()
try { $mgList = Get-AzManagementGroup -ErrorAction Stop } catch { Add-AuditIssue -Area 'Azure RBAC' -Message ("Failed to enumerate management groups: {0}" -f $_.Exception.Message) }
foreach ($mg in $mgList) {
  $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
  $mgAssignments = @()
  try { $mgAssignments = Get-AzRoleAssignment -ObjectId $userId -Scope $mgScope -ExpandPrincipalGroups -ErrorAction Stop } catch { Add-AuditIssue -Area 'Azure RBAC' -Message ("Failed to read role assignments at management group {0}: {1}" -f $mg.Name, $_.Exception.Message) }
  foreach ($ar in $mgAssignments) {
    $rbacOutput.Add([PSCustomObject]@{
      AppliedAt="ManagementGroup"; ManagementGroupId=$mg.Name; SubscriptionId=$null; SubscriptionName=$null;
      RoleDefinitionId=$null; RoleDefinitionName=$ar.RoleDefinitionName; Scope=$ar.Scope;
      AssignmentState="ActivePermanent"; AssignmentSource=(Get-AzRoleAssignmentSource $ar)
    })
  }
}

# Subscriptions & below: classic permanent assignments (direct + group-inherited).
# Get-AzRoleAssignment has no cross-scope principal filter, so this still loops per
# subscription; PIM schedules below use a single all-scopes query instead.
foreach ($sub in $subscriptions) {
  $subScope = "/subscriptions/$($sub.Id)"
  $assignmentsAtSubScope = @()
  try { $assignmentsAtSubScope = Get-AzRoleAssignment -ObjectId $userId -Scope $subScope -ExpandPrincipalGroups -ErrorAction Stop } catch { Add-AuditIssue -Area 'Azure RBAC' -Message ("Failed to read role assignments for subscription {0}: {1}" -f $sub.Name, $_.Exception.Message) }
  foreach ($ar in $assignmentsAtSubScope) {
    $sid = Get-SubscriptionIdFromScope -scope $ar.Scope
    $sname = $null; if ($sid) { $sname = $subNameById[$sid.ToLower()] }
    $rbacOutput.Add([PSCustomObject]@{
      AppliedAt=Get-AppliedAt $ar.Scope; ManagementGroupId=$null; SubscriptionId=$sid; SubscriptionName=$sname;
      RoleDefinitionId=$null; RoleDefinitionName=$ar.RoleDefinitionName; Scope=$ar.Scope;
      AssignmentState="ActivePermanent"; AssignmentSource=(Get-AzRoleAssignmentSource $ar)
    })
  }
}

# PIM eligibility and active/activated assignment schedules, across ALL scopes (tenant,
# management groups, subscriptions, resource groups, resources) in a single call each,
# using the "assignedTo()" filter which server-side expands group membership. This fixes
# a critical gap in the previous per-subscription loop, which never queried tenant- or
# management-group-scoped PIM schedules at all.
$eligSchedules = @()
try { $eligSchedules = Get-AzRoleEligibilitySchedule -Scope "/" -Filter "assignedTo('$userId')" -ErrorAction Stop } catch { Add-AuditIssue -Area 'Azure RBAC' -Message ("Failed to read role eligibility schedules: {0}" -f $_.Exception.Message) }
foreach ($es in $eligSchedules) {
  $isGroup = ($allUserGroupIds -and $es.PrincipalId -and ($allUserGroupIds -contains $es.PrincipalId))
  $grpName = $null
  if ($isGroup) { $grpName = $groupNameById[$es.PrincipalId]; if (-not $grpName) { $grpName = $es.PrincipalId } }
  $sid = Get-SubscriptionIdFromScope -scope $es.Scope
  $sname = $null; if ($sid) { $sname = $subNameById[$sid.ToLower()] }
  $mgId = $null
  if ($es.Scope -like "/providers/Microsoft.Management/managementGroups/*") { $mgId = ($es.Scope -split '/')[-1] }
  $roleName = if ($es.PSObject.Properties.Match('RoleDefinitionName').Count -gt 0 -and $es.RoleDefinitionName) { $es.RoleDefinitionName } else { Resolve-RoleDefName $es.RoleDefinitionId }
  $rbacOutput.Add([PSCustomObject]@{
    AppliedAt=Get-AppliedAt $es.Scope; ManagementGroupId=$mgId; SubscriptionId=$sid; SubscriptionName=$sname;
    RoleDefinitionId=$es.RoleDefinitionId; RoleDefinitionName=$roleName; Scope=$es.Scope;
    AssignmentState="Eligible"; AssignmentSource=($isGroup ? "PIM-Group: $grpName" : "Direct")
  })
}

# PIM active (activations), across ALL scopes in a single call (see rationale above).
$actSchedules = @()
try { $actSchedules = Get-AzRoleAssignmentSchedule -Scope "/" -Filter "assignedTo('$userId')" -ErrorAction Stop } catch { Add-AuditIssue -Area 'Azure RBAC' -Message ("Failed to read role assignment schedules: {0}" -f $_.Exception.Message) }
foreach ($as in $actSchedules) {
  $isGroup = ($allUserGroupIds -and $as.PrincipalId -and ($allUserGroupIds -contains $as.PrincipalId))
  $grpName = $null
  if ($isGroup) { $grpName = $groupNameById[$as.PrincipalId]; if (-not $grpName) { $grpName = $as.PrincipalId } }
  $sid = Get-SubscriptionIdFromScope -scope $as.Scope
  $sname = $null; if ($sid) { $sname = $subNameById[$sid.ToLower()] }
  $mgId = $null
  if ($as.Scope -like "/providers/Microsoft.Management/managementGroups/*") { $mgId = ($as.Scope -split '/')[-1] }
  $roleName = if ($as.PSObject.Properties.Match('RoleDefinitionName').Count -gt 0 -and $as.RoleDefinitionName) { $as.RoleDefinitionName } else { Resolve-RoleDefName $as.RoleDefinitionId }
  $state = ($as.EndDateTime) ? "ActiveTimeBound" : "ActivePermanent"
  $rbacOutput.Add([PSCustomObject]@{
    AppliedAt=Get-AppliedAt $as.Scope; ManagementGroupId=$mgId; SubscriptionId=$sid; SubscriptionName=$sname;
    RoleDefinitionId=$as.RoleDefinitionId; RoleDefinitionName=$roleName; Scope=$as.Scope;
    AssignmentState=$state; AssignmentSource=($isGroup ? "PIM-Group: $grpName" : "Direct")
  })
}

# Deduplicate Azure RBAC
$unique = @{}
$rbacDedup = foreach ($e in $rbacOutput) {
  $ridKey = if ($e.RoleDefinitionId) { $e.RoleDefinitionId } else { $e.RoleDefinitionName }
  $key = ($ridKey + "|" + $e.Scope + "|" + $e.AssignmentState + "|" + $e.AssignmentSource)
  if (-not $unique.ContainsKey($key)) { $unique[$key] = $true; $e }
}

# -------------------- HTML report --------------------
# Modern, self-contained (no external CDN/network calls) report styling: CSS custom
# properties with an automatic + manual dark mode, a sticky nav, a summary dashboard,
# collapsible cards, colored status chips, and a lightweight per-table search filter.
$style = @"
<style>
:root {
  color-scheme: light dark;
  --bg: #f5f6fb; --bg-elevated: #ffffff; --text: #1c1e29; --text-muted: #5b5f73;
  --border: #e2e4ec; --accent: #5b5bf0; --accent-soft: #eceafd;
  --shadow: 0 1px 2px rgba(20,20,43,.04), 0 8px 24px rgba(20,20,43,.06);
  --chip-direct-bg: #e7f0ff; --chip-direct-fg: #1d4ed8;
  --chip-group-bg: #f1e9fe; --chip-group-fg: #7c3aed;
  --chip-pim-bg: #fff1e0; --chip-pim-fg: #c2600a;
  --chip-active-bg: #e3f8ec; --chip-active-fg: #157347;
  --chip-eligible-bg: #fff8dd; --chip-eligible-fg: #9a7d05;
}
[data-theme="dark"] {
  --bg: #12131c; --bg-elevated: #191b27; --text: #eceef5; --text-muted: #9a9db0;
  --border: #2a2d3d; --accent: #8b8bff; --accent-soft: #23233f;
  --shadow: 0 1px 2px rgba(0,0,0,.3), 0 8px 24px rgba(0,0,0,.35);
  --chip-direct-bg: #16233f; --chip-direct-fg: #93b6ff;
  --chip-group-bg: #2a1f42; --chip-group-fg: #c9a6ff;
  --chip-pim-bg: #3a2712; --chip-pim-fg: #ffbf76;
  --chip-active-bg: #123424; --chip-active-fg: #6fe0a0;
  --chip-eligible-bg: #362e0a; --chip-eligible-fg: #e6cd5c;
}
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", "Inter", system-ui, -apple-system, Arial, sans-serif;
  margin: 0; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.45;
}
a { color: var(--accent); }
.topbar {
  position: sticky; top: 0; z-index: 10; display: flex; align-items: center; gap: 16px;
  padding: 10px 24px; background: var(--bg-elevated); border-bottom: 1px solid var(--border);
  box-shadow: var(--shadow); flex-wrap: wrap;
}
.topbar .brand { font-weight: 600; margin-right: auto; white-space: nowrap; }
.topbar nav a {
  text-decoration: none; color: var(--text-muted); font-size: 13px; padding: 6px 10px;
  border-radius: 8px;
}
.topbar nav a:hover { background: var(--accent-soft); color: var(--accent); }
.theme-toggle {
  border: 1px solid var(--border); background: var(--bg); color: var(--text); cursor: pointer;
  border-radius: 8px; padding: 6px 12px; font-size: 13px;
}
.hero { padding: 28px 24px 8px; }
.hero h1 { font-size: 22px; margin: 0 0 4px; }
.hero .meta { color: var(--text-muted); font-size: 13px; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 24px 40px; }
.summary-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px;
  margin: 20px 0 28px;
}
.stat-card {
  background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 14px;
  padding: 16px 18px; box-shadow: var(--shadow);
}
.stat-card .num { font-size: 26px; font-weight: 700; }
.stat-card .label { color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.stat-card.warn .num { color: #c2600a; }
.stat-card.ok .num { color: #157347; }
.card {
  background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 14px;
  box-shadow: var(--shadow); margin-bottom: 20px; overflow: hidden;
}
.card > summary, .card > .card-head {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 14px 18px; cursor: pointer; list-style: none; font-weight: 600; font-size: 15px;
}
.card > summary::-webkit-details-marker { display: none; }
.card > summary::before { content: "▸"; margin-right: 8px; color: var(--text-muted); }
.card[open] > summary::before { content: "▾"; }
.card .count-badge {
  background: var(--accent-soft); color: var(--accent); font-size: 12px; font-weight: 700;
  padding: 2px 9px; border-radius: 999px;
}
.card-body { padding: 0 18px 18px; }
.filter-input {
  width: 100%; margin-bottom: 10px; padding: 8px 12px; border: 1px solid var(--border);
  border-radius: 8px; background: var(--bg); color: var(--text); font-size: 13px;
}
.table-scroll { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 8px 12px; font-size: 12.5px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }
th { background: var(--accent-soft); color: var(--text); font-weight: 600; position: sticky; top: 0; }
tbody tr:hover { background: var(--accent-soft); }
tbody tr.filtered-out { display: none; }
.note { color: var(--text-muted); font-size: 13px; padding: 4px 0; }
.chip { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11.5px; font-weight: 600; }
.chip-direct   { background: var(--chip-direct-bg);   color: var(--chip-direct-fg); }
.chip-group    { background: var(--chip-group-bg);    color: var(--chip-group-fg); }
.chip-pim      { background: var(--chip-pim-bg);      color: var(--chip-pim-fg); }
.chip-active   { background: var(--chip-active-bg);   color: var(--chip-active-fg); }
.chip-eligible { background: var(--chip-eligible-bg); color: var(--chip-eligible-fg); }
footer { color: var(--text-muted); font-size: 12px; text-align: center; padding: 24px 0 8px; }
@media print {
  .topbar, .filter-input { display: none; }
  .card { break-inside: avoid; box-shadow: none; }
  body { background: #fff; }
}
</style>
"@

$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$upnEncoded = [System.Net.WebUtility]::HtmlEncode($upn)
$pageTitle = "Unified Role Report for $upn — $now"

# Build fragments as strings (normalize to non-null), then wrap in a collapsible
# "card" with an anchor id (for the nav), a row count badge, and a search box.
function New-ReportCard {
  param(
    [Parameter(Mandatory=$true)][string]$Id,
    [Parameter(Mandatory=$true)][string]$Title,
    [Parameter(Mandatory=$true)][int]$Count,
    [Parameter(Mandatory=$true)][string]$BodyHtml,
    [switch]$Open
  )
  $openAttr = if ($Open -or $Count -gt 0) { " open" } else { "" }
  $filterBox = if ($Count -gt 0) { "<input type='text' class='filter-input' placeholder='Filter rows in $([System.Net.WebUtility]::HtmlEncode($Title))...' oninput=`"filterTable(this)`" />" } else { "" }
  @"
<details class='card' id='$Id'$openAttr>
<summary>$Title <span class='count-badge'>$Count</span></summary>
<div class='card-body'>
$filterBox
$BodyHtml
</div>
</details>
"@
}

$exoCount = if ($workloadRbac) { $workloadRbac.Count } else { 0 }
$exoTable = if ($exoCount -gt 0) {
  $body = $workloadRbac |
    Sort-Object Workload, Role, AssignmentSource, Scope |
    Select-Object Workload, Role, AssignmentSource, Scope, RoleAssigneeType, RoleAssigneeName |
    ConvertTo-Html -As Table -Fragment
  Format-Badges "<div class='table-scroll'>$body</div>"
} else {
  "<div class='note'>No Exchange Online RBAC entries found for $upnEncoded.</div>"
}

$entraCombined = @()
if ($entraAssigned) { $entraCombined += $entraAssigned }
if ($entraEligible) { $entraCombined += $entraEligible }
$entraCount = $entraCombined.Count
$entraTable = if ($entraCount -gt 0) {
  $body = $entraCombined |
    Sort-Object Type, Role |
    Select-Object Type, Role |
    ConvertTo-Html -As Table -Fragment
  Format-Badges "<div class='table-scroll'>$body</div>"
} else {
  "<div class='note'>No Entra ID directory roles.</div>"
}

# Detailed PIM Groups & Roles table
$pimCount = if ($pimGroupUnique) { $pimGroupUnique.Count } else { 0 }
$pimGroupsTable = if ($pimCount -gt 0) {
  $body = $pimGroupUnique |
    Sort-Object GroupName, MembershipState, EntraRoleType, EntraRole |
    Select-Object GroupName, GroupId, MembershipState, EntraRoleType, EntraRole |
    ConvertTo-Html -As Table -Fragment
  Format-Badges "<div class='table-scroll'>$body</div>"
} else {
  "<div class='note'>No PIM group memberships or assigned roles.</div>"
}

# Compact grouped PIM summary (enrichment)
$pimCompactCount = if ($pimGroupCompact) { $pimGroupCompact.Count } else { 0 }
$pimGroupsCompactTable = if ($pimCompactCount -gt 0) {
  $body = $pimGroupCompact |
    Sort-Object GroupName, MembershipState |
    Select-Object GroupName, GroupId, MembershipState, PermanentRoles, EligibleRoles |
    ConvertTo-Html -As Table -Fragment
  Format-Badges "<div class='table-scroll'>$body</div>"
} else {
  "<div class='note'>No PIM group memberships or roles.</div>"
}

$azureCount = if ($rbacDedup) { $rbacDedup.Count } else { 0 }
$azureTable = if ($azureCount -gt 0) {
  $body = $rbacDedup |
    Sort-Object AppliedAt, SubscriptionName, AssignmentSource, AssignmentState, RoleDefinitionName, Scope |
    Select-Object AppliedAt, SubscriptionId, SubscriptionName, RoleDefinitionName, RoleDefinitionId, AssignmentState, AssignmentSource, Scope |
    ConvertTo-Html -As Table -Fragment
  Format-Badges "<div class='table-scroll'>$body</div>"
} else {
  "<div class='note'>No Azure RBAC roles found.</div>"
}

# Surface any collection warnings/errors instead of letting them disappear into empty
# catch blocks, so report readers know when a section may be incomplete.
$issuesCount = if ($script:auditIssues) { $script:auditIssues.Count } else { 0 }
$issuesTable = if ($issuesCount -gt 0) {
  $body = $script:auditIssues |
    Select-Object Area, Message, Timestamp |
    ConvertTo-Html -As Table -Fragment
  "<div class='table-scroll'>$body</div>"
} else {
  "<div class='note'>No collection errors were recorded during this run.</div>"
}

$issuesCardClass = if ($issuesCount -gt 0) { "warn" } else { "ok" }
$summaryGrid = @"
<div class='summary-grid'>
  <div class='stat-card'><div class='num'>$exoCount</div><div class='label'>Exchange Online</div></div>
  <div class='stat-card'><div class='num'>$entraCount</div><div class='label'>Entra ID Roles</div></div>
  <div class='stat-card'><div class='num'>$pimCount</div><div class='label'>PIM Group Roles</div></div>
  <div class='stat-card'><div class='num'>$azureCount</div><div class='label'>Azure RBAC</div></div>
  <div class='stat-card $issuesCardClass'><div class='num'>$issuesCount</div><div class='label'>Collection Issues</div></div>
</div>
"@

$header = @"
<div class='topbar'>
  <span class='brand'>🛡️ Unified Role Report</span>
  <nav>
    <a href='#exo'>Exchange</a>
    <a href='#entra'>Entra ID</a>
    <a href='#pim'>PIM Groups</a>
    <a href='#pim-compact'>PIM Summary</a>
    <a href='#azure'>Azure RBAC</a>
    <a href='#issues'>Issues</a>
  </nav>
  <button class='theme-toggle' onclick='toggleTheme()' type='button'>🌓 Theme</button>
</div>
<div class='hero'>
  <h1>$upnEncoded</h1>
  <div class='meta'>Generated $now &middot; PowerShell RBAC audit</div>
</div>
"@

$bodyContent = @"
<div class='wrap'>
$summaryGrid
$(New-ReportCard -Id 'exo' -Title 'Exchange Online RBAC' -Count $exoCount -BodyHtml $exoTable -Open)
$(New-ReportCard -Id 'entra' -Title 'Entra ID Directory Roles' -Count $entraCount -BodyHtml $entraTable -Open)
$(New-ReportCard -Id 'pim' -Title 'PIM Groups & Roles (Detailed)' -Count $pimCount -BodyHtml $pimGroupsTable)
$(New-ReportCard -Id 'pim-compact' -Title 'PIM Groups & Roles (Compact Summary)' -Count $pimCompactCount -BodyHtml $pimGroupsCompactTable)
$(New-ReportCard -Id 'azure' -Title 'Azure RBAC and PIM' -Count $azureCount -BodyHtml $azureTable -Open)
$(New-ReportCard -Id 'issues' -Title 'Collection Warnings/Errors' -Count $issuesCount -BodyHtml $issuesTable)
<footer>Unified Role Report &middot; generated locally by RBACbyUPN.ps1 &middot; no data leaves this machine</footer>
</div>
<script>
function toggleTheme() {
  var root = document.documentElement;
  var current = root.getAttribute('data-theme');
  var next = current === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('rbacReportTheme', next); } catch (e) {}
}
(function () {
  try {
    var saved = localStorage.getItem('rbacReportTheme');
    if (saved) { document.documentElement.setAttribute('data-theme', saved); }
    else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  } catch (e) {}
})();
function filterTable(input) {
  var card = input.closest('.card-body');
  var rows = card.querySelectorAll('table tbody tr');
  var term = input.value.trim().toLowerCase();
  rows.forEach(function (row) {
    var match = !term || row.textContent.toLowerCase().indexOf(term) !== -1;
    row.classList.toggle('filtered-out', !match);
  });
}
</script>
"@

# Assemble the page
$html = ConvertTo-Html -Head $style -Title $pageTitle -PreContent $header -Body $bodyContent

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
} catch {
  Add-AuditIssue -Area 'Export' -Message ("Failed to create export folder {0}: {1}" -f $exportFolder, $_.Exception.Message)
}

$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
# Writes a CSV with a stable header even when $obj is empty (Export-Csv otherwise creates
# no file at all for an empty collection, which previously produced misleading "no data"
# CSVs with no columns to distinguish "empty" from "query failed").
function Safe-ExportCsv($obj, [string[]]$columns, [string]$path) {
  try {
    if ($obj -and @($obj).Count -gt 0) {
      $obj | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
      Write-Host ("CSV written: {0}" -f $path) -ForegroundColor Green
    } else {
      ($columns -join ',') | Out-File -FilePath $path -Encoding UTF8
      Write-Host ("CSV created (empty, header only): {0}" -f $path) -ForegroundColor Yellow
    }
  } catch {
    Add-AuditIssue -Area 'Export' -Message ("Failed to write CSV {0}: {1}" -f $path, $_.Exception.Message)
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

Safe-ExportCsv $csv_EXO   @('Workload','Role','AssignmentSource','Scope','RoleAssigneeType','RoleAssigneeName') (Join-Path $exportFolder ("Exchange_RBAC_{0}.csv" -f $ts))
Safe-ExportCsv $csv_ER_As @('Type','Role') (Join-Path $exportFolder ("Entra_Roles_Assigned_{0}.csv" -f $ts))
Safe-ExportCsv $csv_ER_El @('Type','Role') (Join-Path $exportFolder ("Entra_Roles_Eligible_{0}.csv" -f $ts))
Safe-ExportCsv $csv_PIM_D @('GroupName','GroupId','MembershipState','EntraRoleType','EntraRole') (Join-Path $exportFolder ("PIM_Groups_Detailed_{0}.csv" -f $ts))
Safe-ExportCsv $csv_PIM_C @('GroupName','GroupId','MembershipState','PermanentRoles','EligibleRoles') (Join-Path $exportFolder ("PIM_Groups_Compact_{0}.csv" -f $ts))
Safe-ExportCsv $csv_AZRB  @('AppliedAt','SubscriptionId','SubscriptionName','RoleDefinitionName','RoleDefinitionId','AssignmentState','AssignmentSource','Scope') (Join-Path $exportFolder ("Azure_RBAC_{0}.csv" -f $ts))
Safe-ExportCsv $script:auditIssues @('Area','Message','Timestamp') (Join-Path $exportFolder ("Collection_Issues_{0}.csv" -f $ts))

Write-Host ("All CSVs saved under: {0}" -f $exportFolder) -ForegroundColor Cyan

# -------------------- Disconnect Graph --------------------
Disconnect-MgGraph  # clean up Graph session 
