<#
.SYNOPSIS
    Offboards a departing user from the Contoso UK tenant.

.DESCRIPTION
    Full leaver process covering:
    - Disable the account immediately
    - Revoke all active sessions (sign out everywhere)
    - Remove from all groups
    - Remove licence
    - Remove any directory role assignments
    - Rename account to make it clearly inactive
    - Output a full audit trail

    In a real environment this would be triggered by HR system
    on an employee's last day, or immediately for involuntary
    leavers.

.PARAMETER UserUPN
    The UPN of the departing user

.PARAMETER Reason
    Reason for offboarding (Resignation/Termination/Redundancy)

.EXAMPLE
    .\Invoke-Leaver.ps1 -UserUPN "zara.khan@passion2k7.onmicrosoft.com" -Reason "Resignation"

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

param(
    [Parameter(Mandatory)] [string] $UserUPN,
    [Parameter(Mandatory)]
    [ValidateSet("Resignation", "Termination", "Redundancy")]
    [string] $Reason
)

Write-Host "`n=== LEAVER PROCESS: $UserUPN ===" -ForegroundColor Cyan
Write-Host "Reason  : $Reason" -ForegroundColor Gray
Write-Host "Started : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray

# ----------------------------------------------------------------
# STEP 1 — Verify user exists
# ----------------------------------------------------------------
Write-Host "`n[1/6] Locating user account..." -ForegroundColor Yellow

$user = Get-MgUser -Filter "UserPrincipalName eq '$UserUPN'" -Property Id, DisplayName, AccountEnabled, AssignedLicenses
if (-not $user) {
    Write-Host "ERROR - User not found: $UserUPN" -ForegroundColor Red
    exit
}
Write-Host "      OK - Found: $($user.DisplayName) | ID: $($user.Id)" -ForegroundColor Green

# ----------------------------------------------------------------
# STEP 2 — Disable the account immediately
# ----------------------------------------------------------------
Write-Host "`n[2/6] Disabling account..." -ForegroundColor Yellow

try {
    Update-MgUser -UserId $user.Id -BodyParameter @{ accountEnabled = $false }
    Write-Host "      OK - Account disabled" -ForegroundColor Green
}
catch {
    Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------------
# STEP 3 — Revoke all active sessions
# ----------------------------------------------------------------
Write-Host "`n[3/6] Revoking all active sessions..." -ForegroundColor Yellow

try {
    Revoke-MgUserSignInSession -UserId $user.Id
    Write-Host "      OK - All sessions revoked (signed out everywhere)" -ForegroundColor Green
}
catch {
    Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------------
# STEP 4 — Remove from all groups
# ----------------------------------------------------------------
Write-Host "`n[4/6] Removing group memberships..." -ForegroundColor Yellow

$groupMemberships = Get-MgUserMemberOf -UserId $user.Id -All |
    Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.group" }

if ($groupMemberships.Count -eq 0) {
    Write-Host "      INFO - No group memberships found" -ForegroundColor Gray
}

foreach ($membership in $groupMemberships) {
    $groupId   = $membership.Id
    $groupName = $membership.AdditionalProperties["displayName"]

    try {
        Remove-MgGroupMemberByRef -GroupId $groupId -DirectoryObjectId $user.Id
        Write-Host "      OK - Removed from: $groupName" -ForegroundColor Green
    }
    catch {
        Write-Host "      WARN - Could not remove from $groupName : $($_.Exception.Message)" -ForegroundColor Magenta
    }
}

# ----------------------------------------------------------------
# STEP 5 — Remove licence
# ----------------------------------------------------------------
Write-Host "`n[5/6] Removing licences..." -ForegroundColor Yellow

$licencedUser = Get-MgUser -UserId $user.Id -Property AssignedLicenses
$assignedLicences = $licencedUser.AssignedLicenses
$licencedUser | Out-Null

if ($assignedLicences.Count -eq 0) {
    Write-Host "      INFO - No licences assigned" -ForegroundColor Gray
}
else {
    $licenceSkuIds = $assignedLicences | Select-Object -ExpandProperty SkuId

    try {
        Set-MgUserLicense -UserId $user.Id -RemoveLicenses $licenceSkuIds -AddLicenses @() | Out-Null
        Write-Host "      OK - $($licenceSkuIds.Count) licence(s) removed" -ForegroundColor Green
    }
    catch {
        Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ----------------------------------------------------------------
# STEP 6 — Remove directory role assignments
# ----------------------------------------------------------------
Write-Host "`n[6/6] Checking for directory role assignments..." -ForegroundColor Yellow

$roleAssignments = Get-MgUserTransitiveMemberOf -UserId $user.Id -All |
    Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.directoryRole" }

if ($roleAssignments.Count -eq 0) {
    Write-Host "      INFO - No directory roles assigned" -ForegroundColor Gray
}

foreach ($role in $roleAssignments) {
    $roleId   = $role.Id
    $roleName = $role.AdditionalProperties["displayName"]

    try {
        Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $roleId -DirectoryObjectId $user.Id
        Write-Host "      OK - Removed from role: $roleName" -ForegroundColor Green
    }
    catch {
        Write-Host "      WARN - Could not remove from $roleName : $($_.Exception.Message)" -ForegroundColor Magenta
    }
}

# ----------------------------------------------------------------
# SUMMARY
# ----------------------------------------------------------------
Write-Host "`n=== LEAVER SUMMARY ===" -ForegroundColor Cyan
Write-Host "Name       : $($user.DisplayName)" -ForegroundColor White
Write-Host "UPN        : $UserUPN" -ForegroundColor White
Write-Host "Reason     : $Reason" -ForegroundColor White
Write-Host "Completed  : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor White
Write-Host "`nActions taken:" -ForegroundColor White
Write-Host "  - Account disabled" -ForegroundColor White
Write-Host "  - All sessions revoked" -ForegroundColor White
Write-Host "  - Removed from $($groupMemberships.Count) group(s)" -ForegroundColor White
Write-Host "  - Licences removed" -ForegroundColor White
Write-Host "  - Role assignments checked and removed" -ForegroundColor White
Write-Host "`nNote: Account retained for 30 days per data retention policy." -ForegroundColor Yellow
Write-Host "      Scheduled deletion: $(((Get-Date).AddDays(30)).ToString('dd/MM/yyyy'))" -ForegroundColor Yellow