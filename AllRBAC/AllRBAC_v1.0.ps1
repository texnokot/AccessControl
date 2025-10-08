<#
SYNOPSIS
  App-only audit of Microsoft Entra directory roles and Azure resource RBAC across Management Group and Subscription scopes.

PURPOSE
  Produce a unified report of permanent and PIM-eligible assignments for Users, Groups, and Service Principals (including Managed Identities).

DESCRIPTION
  - Enumerates Entra directory permanent assignments (unifiedRoleAssignments) and PIM eligibilities, plus Azure resource RBAC permanent assignments and PIM eligibilities at management group and subscription scopes.
  - Resolves principals in batches, enriches users with UPN, and tags managed identities when detectable; preserves rows even when principals are deleted or cannot be resolved by falling back to assignment payload names.
  - Normalizes role names and IDs across providers, renders friendly scope names for management groups and subscriptions, and deduplicates Azure permanent results across overlapping scopes.

FEATURES
  - Permanent RBAC: Users, Groups, Service Principals (incl. Managed Identities).
  - PIM eligibilities: Entra directory roles and Azure resource RBAC.
  - Principal resolution with display name and UPN enrichment; resilient fallbacks for orphaned principals.
  - Role name/ID normalization and friendly scope labels; de-duplication across scopes.

OUTPUT COLUMNS
  Scope, RoleName, RoleNameId, ObjectType, DisplayName, ObjectId, UPN, AssignmentType (Eligible|Permanent), Provider (Entra|Azure).

PREREQUISITES
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

AUTH
  - Microsoft Graph: App-only (certificate or client secret), no delegated scopes.
  - Azure: Sign in with the same service principal used for Graph.

SCOPE COVERAGE AND LIMITS
  - Management group and subscription scopes are covered by default; add resource group or resource scopes if deeper coverage is required.
  - Azure permanent assignments are de-duplicated by (PrincipalId, Scope, RoleDefinition) to avoid repeated rows due to inheritance across queried scopes.

PERFORMANCE NOTES
  - Principal lookups are batched to reduce Graph round trips; selective Get-MgUser calls backfill UPNs only for user objects missing that value.
  - Role definition names are cached per provider to minimize repeated role lookups.

AUTHOR
  Victoria Almazova (texnokot)

DATE
  2025-10-03

VERSION
  1.0
#>


# ===== Settings for service principal to connect. This is lab aprroach. Ensure to keep secret out of the code! =====
$TenantId  = "TENANT_ID"
$ClientId  = "CLIENT_ID"
$SecureSecret = ConvertTo-SecureString 'CLIENT_SECRET' -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $SecureSecret

# Optional toggle for SP -> ManagedIdentity enrichment
$ResolveManagedIdentity = $true

# ===== App-only Graph Connect =====
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential

# Validate Graph context
$gctx = Get-MgContext
if (-not $gctx -or $gctx.AuthType -ne "AppOnly") { throw "Graph app-only authentication not established; connect with certificate or client secret (no -Scopes)." }
Write-Host ("Graph AppOnly connected. Tenant: {0} AppId: {1}" -f $gctx.TenantId, $gctx.ClientId) -ForegroundColor Cyan

# ===== Az Connect (SPN) =====
Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential

Write-Host "Ensuring Az context is available..." -ForegroundColor Cyan
$azCtx = Get-AzContext
if (-not $azCtx) {
    Connect-AzAccount | Out-Null
}
$azCtx = Get-AzContext
if (-not $azCtx) { throw "Failed to authenticate to Azure (Az). Ensure the SP has access." }

# ===== Management groups (flat map) =====
$allMg = Get-AzManagementGroup
$mgMapById = @{}
foreach ($g in $allMg) { $mgMapById[$g.Id] = $g.DisplayName }

# ===== Subscriptions (flat map) =====
$subs = Get-AzSubscription | Select-Object Id, Name
$subMapByGuid = @{}
foreach ($s in $subs) { $subMapByGuid[$s.Id.ToString().ToLower()] = $s.Name }

# ===== Scope lists for Azure RBAC (PIM + Permanent) =====
$subScopes = $subs | ForEach-Object { "/subscriptions/$($_.Id)" }
$mgScopes  = $mgMapById.Keys
$allScopes = @($subScopes + $mgScopes)

# ===== Entra PIM eligible (instances) =====
$entraEligible = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All `
    | Select-Object Id, PrincipalId, DirectoryScopeId, RoleDefinitionId

# ===== Azure RBAC PIM eligible (instances) per scope =====
$azureEligible = New-Object System.Collections.Generic.List[object]
foreach ($scope in $allScopes) {
    try {
        $items = Get-AzRoleEligibilityScheduleInstance -Scope $scope -ErrorAction Stop
        foreach ($i in $items) {
            $azureEligible.Add([PSCustomObject]@{
                PrincipalId          = $i.PrincipalId
                DirectoryScopeId     = $scope
                RoleDefinitionId     = $i.RoleDefinitionId
                Provider             = 'Azure'
                AssignmentType       = 'Eligible'
                PrincipalDisplayName = $null
                PrincipalSignInName  = $null
                PrincipalTypeRaw     = $null
            })
        }
    } catch {}
}

# ===== Normalize Entra eligibilities =====
$entraShaped = $entraEligible | ForEach-Object {
    [PSCustomObject]@{
        PrincipalId          = $_.PrincipalId
        DirectoryScopeId     = $_.DirectoryScopeId
        RoleDefinitionId     = $_.RoleDefinitionId
        Provider             = 'Entra'
        AssignmentType       = 'Eligible'
        PrincipalDisplayName = $null
        PrincipalSignInName  = $null
        PrincipalTypeRaw     = $null
    }
}

# ===== Entra permanent role assignments (directory RBAC) =====
$entraPermanentRaw = Get-MgRoleManagementDirectoryRoleAssignment -All | Select-Object Id, PrincipalId, DirectoryScopeId, RoleDefinitionId
$entraPermanent = $entraPermanentRaw | ForEach-Object {
    [PSCustomObject]@{
        PrincipalId          = $_.PrincipalId
        DirectoryScopeId     = $_.DirectoryScopeId
        RoleDefinitionId     = $_.RoleDefinitionId
        Provider             = 'Entra'
        AssignmentType       = 'Permanent'
        PrincipalDisplayName = $null
        PrincipalSignInName  = $null
        PrincipalTypeRaw     = $null
    }
}

# ===== Azure permanent role assignments (resource RBAC) =====
# Enumerate at MG and Subscription scope, include only Users, Groups, ServicePrincipals; de-duplicate across overlapping scopes
$azurePermanent = New-Object System.Collections.Generic.List[object]
$seen = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($scope in $allScopes) {
    try {
        $items = Get-AzRoleAssignment -Scope $scope -ErrorAction Stop
        foreach ($i in $items) {
            # Normalize principal type property across Az versions
            $pType = $null
            if ($i.PSObject.Properties.Name -contains 'PrincipalType' -and $i.PrincipalType) { $pType = $i.PrincipalType }
            elseif ($i.PSObject.Properties.Name -contains 'ObjectType' -and $i.ObjectType) { $pType = $i.ObjectType }

            if (-not $pType -or @('User','Group','ServicePrincipal') -notcontains $pType) { continue }

            # Prefer RoleDefinitionId, fall back to RoleDefinitionName
            $roleIdOrName = $null
            if ($i.PSObject.Properties.Name -contains 'RoleDefinitionId' -and $i.RoleDefinitionId) { $roleIdOrName = $i.RoleDefinitionId.ToString() }
            elseif ($i.PSObject.Properties.Name -contains 'RoleDefinitionName' -and $i.RoleDefinitionName) { $roleIdOrName = $i.RoleDefinitionName }

            $dedupeKey = "{0}|{1}|{2}" -f $i.PrincipalId, $i.Scope, $roleIdOrName
            if ($seen.Add($dedupeKey)) {
                $azurePermanent.Add([PSCustomObject]@{
                    PrincipalId          = $i.PrincipalId  # may be null for orphaned subjects
                    DirectoryScopeId     = $i.Scope
                    RoleDefinitionId     = $roleIdOrName
                    Provider             = 'Azure'
                    AssignmentType       = 'Permanent'
                    PrincipalDisplayName = ($i.PSObject.Properties.Name -contains 'DisplayName') ? $i.DisplayName : $null
                    PrincipalSignInName  = ($i.PSObject.Properties.Name -contains 'SignInName') ? $i.SignInName : $null
                    PrincipalTypeRaw     = $pType
                })
            }
        }
    } catch {
        # Ignore scope access errors and continue
    }
}

# ===== Combine: PIM eligible + Permanent (keep all, even if PrincipalId is null) =====
$eligibleAll    = @($entraShaped + $azureEligible)
$assignmentsAll = @($eligibleAll + $entraPermanent + $azurePermanent)

# ===== Principal resolution via directoryObjects.getByIds (best-effort, capture UPN when available) =====
function Resolve-PrincipalsBatch {
    param([string[]]$Ids)
    $resolved = @{}
    if (-not $Ids -or $Ids.Count -eq 0) { return $resolved }
    $chunkSize = 1000
    for ($i=0; $i -lt $Ids.Count; $i += $chunkSize) {
        $chunk = $Ids[$i..([Math]::Min($i+$chunkSize-1, $Ids.Count-1))]
        $resp = Get-MgDirectoryObjectById -Ids $chunk -Types @('user','group','servicePrincipal')
        foreach ($obj in $resp) {
            $odataType = $null
            if ($obj.PSObject.Properties.Name -contains 'AdditionalProperties') {
                $odataType = $obj.AdditionalProperties['@odata.type']
            }
            $type = switch -Wildcard ($odataType) {
                '*microsoft.graph.user'             { 'User' }
                '*microsoft.graph.group'            { 'Group' }
                '*microsoft.graph.servicePrincipal' { 'ServicePrincipal' }
                default {
                    $t = $obj.GetType().Name
                    if ($t -like '*User*') { 'User' }
                    elseif ($t -like '*Group*') { 'Group' }
                    elseif ($t -like '*ServicePrincipal*') { 'ServicePrincipal' }
                    else { 'Other' }
                }
            }
            $display = $null
            if ($obj.PSObject.Properties.Name -contains 'DisplayName' -and $obj.DisplayName) {
                $display = $obj.DisplayName
            } elseif ($obj.PSObject.Properties.Name -contains 'AdditionalProperties' -and $obj.AdditionalProperties['displayName']) {
                $display = $obj.AdditionalProperties['displayName']
            }
            $upn = $null
            if ($type -eq 'User' -and $obj.PSObject.Properties.Name -contains 'AdditionalProperties' -and $obj.AdditionalProperties['userPrincipalName']) {
                $upn = $obj.AdditionalProperties['userPrincipalName']
            }
            $resolved[$obj.Id] = [PSCustomObject]@{
                Id          = $obj.Id
                Type        = $type
                DisplayName = $display
                Upn         = $upn
            }
        }
    }
    return $resolved
}

$principalIds = $assignmentsAll.PrincipalId | Where-Object { $_ } | Select-Object -Unique
$principalMap = Resolve-PrincipalsBatch -Ids $principalIds

# ===== Backfill missing UPNs for user principals via Get-MgUser =====
$userIdsNeedingUpn = @()
foreach ($kv in $principalMap.GetEnumerator()) {
    if ($kv.Value.Type -eq 'User' -and ([string]::IsNullOrWhiteSpace($kv.Value.Upn))) {
        $userIdsNeedingUpn += $kv.Key
    }
}
foreach ($uid in $userIdsNeedingUpn) {
    try {
        $u = Get-MgUser -UserId $uid -Property Id,DisplayName,UserPrincipalName
        if ($u -and $principalMap.ContainsKey($uid)) {
            if ([string]::IsNullOrWhiteSpace($principalMap[$uid].DisplayName) -and $u.DisplayName) {
                $principalMap[$uid].DisplayName = $u.DisplayName
            }
            $principalMap[$uid].Upn = $u.UserPrincipalName
        }
    } catch {
        # ignore lookup failures
    }
}

# ===== Optional: refine SP -> ManagedIdentity =====
$miCache = @{}
if ($ResolveManagedIdentity) {
    $spIds = $principalMap.GetEnumerator() | Where-Object { $_.Value.Type -eq 'ServicePrincipal' } | ForEach-Object { $_.Key }
    foreach ($spId in $spIds) {
        try {
            $sp = Get-MgServicePrincipal -ServicePrincipalId $spId -Property Id,DisplayName,ServicePrincipalType
            $miCache[$spId] = ($sp.ServicePrincipalType -eq 'ManagedIdentity')
        } catch {
            $miCache[$spId] = $false
        }
    }
}

# ===== Role definition maps =====
# Entra directory roles (unifiedRoleDefinition) => id -> displayName
$entraRoleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All | Select-Object Id, DisplayName
$entraRoleMap = @{}
foreach ($r in $entraRoleDefs) { $entraRoleMap[$r.Id] = $r.DisplayName }

# Extract GUID from any Azure roleDefinitionId form (GUID or full resourceId)
function Extract-RoleGuid {
    param([string]$RoleDefinitionId)
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return $null }
    if ($RoleDefinitionId -match '^[0-9a-fA-F-]{36}$') { return $RoleDefinitionId.ToLower() }
    if ($RoleDefinitionId -match '/providers/Microsoft\.Authorization/roleDefinitions/([0-9a-fA-F-]{36})') { return $Matches[1].ToLower() }
    if ($RoleDefinitionId -match '/subscriptions/[0-9a-fA-F-]{36}/providers/Microsoft\.Authorization/roleDefinitions/([0-9a-fA-F-]{36})') { return $Matches[1].ToLower() }
    return $null
}

# Azure roles: resolve unique GUIDs from all assignments
$azureRoleGuids = $assignmentsAll `
    | Where-Object { $_.Provider -eq 'Azure' -and $_.RoleDefinitionId } `
    | ForEach-Object { Extract-RoleGuid -RoleDefinitionId $_.RoleDefinitionId } `
    | Where-Object { $_ } `
    | Select-Object -Unique

$azureRoleMap = @{}
foreach ($rid in $azureRoleGuids) {
    try {
        $role = Get-AzRoleDefinition -Id $rid -ErrorAction Stop
        $display = if ($role.PSObject.Properties.Name -contains 'RoleName' -and $role.RoleName) { $role.RoleName } else { $role.Name }
        if ($display) { $azureRoleMap[$rid] = $display }
    } catch {
        # Skip if not visible
    }
}

function Resolve-RoleName {
    param([string]$Provider, [string]$RoleDefinitionId)
    if ($Provider -eq 'Entra') {
        if ($entraRoleMap.ContainsKey($RoleDefinitionId)) { return $entraRoleMap[$RoleDefinitionId] }
        try {
            $r = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $RoleDefinitionId -ErrorAction Stop
            return $r.DisplayName
        } catch { return $RoleDefinitionId }
    } else {
        $guid = Extract-RoleGuid -RoleDefinitionId $RoleDefinitionId
        if ($guid -and $azureRoleMap.ContainsKey($guid)) { return $azureRoleMap[$guid] }
        if ($guid) {
            try {
                $role = Get-AzRoleDefinition -Id $guid -ErrorAction Stop
                $display = if ($role.PSObject.Properties.Name -contains 'RoleName' -and $role.RoleName) { $role.RoleName } else { $role.Name }
                if ($display) { return $display }
            } catch {}
        }
        return $RoleDefinitionId
    }
}

# ===== Scope resolver =====
function Resolve-ScopeFriendly {
    param([string]$DirectoryScopeId)
    if ([string]::IsNullOrWhiteSpace($DirectoryScopeId)) { return 'Unknown' }
    if ($DirectoryScopeId -eq '/') { return 'Tenant' }
    if ($DirectoryScopeId -match '^/subscriptions/([0-9a-fA-F-]{36})(/resourceGroups/([^/]+))?($|/.*)') {
        $sid = $Matches[1].ToLower()
        $rg  = $Matches[3]
        $sName = $subMapByGuid.ContainsKey($sid) ? $subMapByGuid[$sid] : $sid
        if ($rg) { return "ResourceGroup: $rg (Subscription: $sName)" }
        return "Subscription: $sName"
    }
    if ($mgMapById.ContainsKey($DirectoryScopeId)) { return "ManagementGroup: $($mgMapById[$DirectoryScopeId])" }
    return $DirectoryScopeId
}

# ===== Build final result =====
$result = foreach ($e in $assignmentsAll) {
    # Best-effort directory lookup; avoid null index errors by guarding
    $p = $null
    if ($e.PSObject.Properties.Name -contains 'PrincipalId' -and $e.PrincipalId) {
        $p = $principalMap[$e.PrincipalId]
    }

    # Prefer Graph-resolved type when available, otherwise Azure-assignment raw type, else 'Other'
    $otype = if ($null -ne $p) { $p.Type }
             elseif ($e.Provider -eq 'Azure' -and $e.PSObject.Properties.Name -contains 'PrincipalTypeRaw' -and $e.PrincipalTypeRaw) { $e.PrincipalTypeRaw }
             else { 'Other' }

    if ($otype -eq 'ServicePrincipal' -and $ResolveManagedIdentity -and $e.PrincipalId -and $miCache.ContainsKey($e.PrincipalId) -and $miCache[$e.PrincipalId]) {
        $otype = 'ManagedIdentity'
    }

    # RoleNameId: Entra uses unified roleDefinitionId; Azure extract GUID if possible
    $roleNameId = if ($e.Provider -eq 'Azure') { Extract-RoleGuid -RoleDefinitionId $e.RoleDefinitionId } else { $e.RoleDefinitionId }

    # Friendly name fallbacks: Graph displayName -> Azure assignment DisplayName -> SignInName -> raw PrincipalId
    $friendly = $null
    if ($null -ne $p -and $p.DisplayName) { $friendly = $p.DisplayName }
    elseif ($e.PSObject.Properties.Name -contains 'PrincipalDisplayName' -and $e.PrincipalDisplayName) { $friendly = $e.PrincipalDisplayName }
    elseif ($e.PSObject.Properties.Name -contains 'PrincipalSignInName' -and $e.PrincipalSignInName) { $friendly = $e.PrincipalSignInName }
    else { $friendly = $e.PrincipalId }

    # UPN: Graph user UPN -> Azure SignInName -> null
    $upn = $null
    if ($otype -eq 'User') {
        if ($null -ne $p -and $p.PSObject.Properties.Name -contains 'Upn' -and $p.Upn) {
            $upn = $p.Upn
        } elseif ($e.PSObject.Properties.Name -contains 'PrincipalSignInName' -and $e.PrincipalSignInName) {
            $upn = $e.PrincipalSignInName
        }
    }

    [PSCustomObject]@{
        Scope          = (Resolve-ScopeFriendly -DirectoryScopeId $e.DirectoryScopeId)
        RoleName       = (Resolve-RoleName -Provider $e.Provider -RoleDefinitionId $e.RoleDefinitionId)
        RoleNameId     = $roleNameId
        ObjectType     = $otype
        DisplayName   = $friendly
        ObjectId       = $e.PrincipalId
        UPN            = $upn
        AssignmentType = $e.AssignmentType
        Provider       = $e.Provider
    }
}

# ===== Output =====
# In the console, if needed for debugging or quick review
 $result | Sort-Object Scope, RoleName, ObjectType, DisplayName |
    Format-Table Scope, RoleName, RoleNameId, ObjectType, DisplayName, ObjectId, UPN, AssignmentType, Provider

# Optional export:
$result | Export-Csv -Path ("RBAC-Assignments-All_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')) -NoTypeInformation

<#
    # Optional HTML export with minimal styling
    # Filename includes timestamp to avoid overwriting
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'  # timestamp for filename 
    $columns = 'Scope','RoleName','RoleNameId','ObjectType','DisplayName','ObjectId','UPN','AssignmentType','Provider'

    # Minimal, readable styling for the HTML table 
    $css = @"
    <style>
    body { font-family: Segoe UI, Arial, sans-serif; font-size: 12px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 6px; }
    th { background: #f4f4f4; position: sticky; top: 0; }
    tr:nth-child(even) { background: #fafafa; }
    </style>
    "@

    $html = $result |
    Select-Object $columns |
    Sort-Object Scope, RoleName, ObjectType, FriendlyName |
    ConvertTo-Html -As Table -Title "RBAC Assignments ($ts)" -Head $css -PreContent "<h2>RBAC Assignments</h2><p>Generated: $(Get-Date)</p>"  

    $outHtml = "RBAC-Assignments-All_$ts.html"
    $html | Out-File -FilePath $outHtml -Encoding utf8  # write as UTF-8 

    # Optional: open in default browser
    Start-Process $outHtml
#>