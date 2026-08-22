<#
.SYNOPSIS
    Automated incident response for a compromised privileged account.

.DESCRIPTION
    Executes immediate containment actions when a privileged account
    is suspected to be compromised:
    - Revokes all active sessions immediately
    - Disables the account to prevent new sign-ins
    - Removes all directory role assignments
    - Captures sign-in and audit log evidence
    - Outputs a full incident response record

    In production this would be triggered automatically by:
    - An Entra ID Identity Protection high-risk detection
    - A SIEM alert (e.g. Microsoft Sentinel)
    - A PIM activation from an unexpected location
    - A break-glass sign-in alert

.PARAMETER UserUPN
    UPN of the suspected compromised account

.PARAMETER Reason
    Brief description of why this response was triggered

.EXAMPLE
    .\Invoke-CompromisedAccountResponse.ps1 `
        -UserUPN "sarah.thompson@passion2k7.onmicrosoft.com" `
        -Reason "PIM activation from anonymous IP detected by Identity Protection"

.NOTES
    Author:  Omar
    Created: July 2026
    Requires: Connect-Tenant.ps1 to have been run first
    Requires: AuditLog.Read.All, RoleManagement.ReadWrite.Directory
    
    IMPORTANT: This script takes immediate containment action.
    Only run against accounts where compromise is confirmed or
    strongly suspected. All actions are logged and irreversible
    without manual intervention.
#>

param(
    [Parameter(Mandatory)] [string] $UserUPN,
    [Parameter(Mandatory)] [string] $Reason
)

$incidentTime = Get-Date
$incidentRef  = "IR-$(Get-Date -Format 'yyyyMMdd-HHmm')"

Write-Host "`n=== COMPROMISED ACCOUNT RESPONSE ===" -ForegroundColor Red
Write-Host "Incident Ref : $incidentRef" -ForegroundColor Red
Write-Host "Target       : $UserUPN" -ForegroundColor Red
Write-Host "Reason       : $Reason" -ForegroundColor Red
Write-Host "Initiated    : $($incidentTime.ToString('dd/MM/yyyy HH:mm:ss'))`n" -ForegroundColor Red

# ----------------------------------------------------------------
# STEP 1 — Verify account exists
# ----------------------------------------------------------------
Write-Host "[1/5] Locating account..." -ForegroundColor Yellow

$user = Get-MgUser -Filter "UserPrincipalName eq '$UserUPN'" `
    -Property Id, DisplayName, AccountEnabled, UserPrincipalName

if (-not $user) {
    Write-Host "ERROR - Account not found: $UserUPN" -ForegroundColor Red
    exit
}

Write-Host "      OK - Found: $($user.DisplayName) | ID: $($user.Id)" -ForegroundColor Green
Write-Host "           Account currently enabled: $($user.AccountEnabled)" -ForegroundColor Gray

# ----------------------------------------------------------------
# STEP 2 — Revoke all active sessions immediately
# ----------------------------------------------------------------
Write-Host "`n[2/5] Revoking all active sessions..." -ForegroundColor Yellow

try {
    Revoke-MgUserSignInSession -UserId $user.Id
    Write-Host "      OK - All sessions revoked — user signed out everywhere" -ForegroundColor Green
    Write-Host "           This invalidates all existing tokens immediately" -ForegroundColor Gray
}
catch {
    Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------------
# STEP 3 — Disable the account
# ----------------------------------------------------------------
Write-Host "`n[3/5] Disabling account..." -ForegroundColor Yellow

try {
    Update-MgUser -UserId $user.Id -BodyParameter @{ accountEnabled = $false }
    Write-Host "      OK - Account disabled — no new sign-ins possible" -ForegroundColor Green
}
catch {
    Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------------
# STEP 4 — Remove all directory role assignments
# ----------------------------------------------------------------
Write-Host "`n[4/5] Removing privileged role assignments..." -ForegroundColor Yellow

$roleAssignments = Get-MgUserTransitiveMemberOf -UserId $user.Id -All |
    Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.directoryRole" }

if ($roleAssignments.Count -eq 0) {
    Write-Host "      INFO - No permanent directory roles found" -ForegroundColor Gray
}

$removedRoles = @()
foreach ($role in $roleAssignments) {
    $roleId   = $role.Id
    $roleName = $role.AdditionalProperties["displayName"]

    try {
        Remove-MgDirectoryRoleMemberByRef `
            -DirectoryRoleId    $roleId `
            -DirectoryObjectId  $user.Id
        Write-Host "      OK - Removed from role: $roleName" -ForegroundColor Green
        $removedRoles += $roleName
    }
    catch {
        Write-Host "      ERROR - Could not remove from $roleName : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Also check PIM eligible assignments
Write-Host "      Checking PIM eligible assignments..." -ForegroundColor Gray
$pimSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All |
    Where-Object { $_.PrincipalId -eq $user.Id }

if ($pimSchedules.Count -gt 0) {
    Write-Host "      WARN - $($pimSchedules.Count) PIM eligible assignment(s) found" -ForegroundColor Magenta
    Write-Host "             These require manual review in the Entra portal" -ForegroundColor Magenta
    Write-Host "             PIM eligible roles cannot be auto-removed via this script" -ForegroundColor Magenta
    foreach ($schedule in $pimSchedules) {
        $role = Get-MgRoleManagementDirectoryRoleDefinition `
            -UnifiedRoleDefinitionId $schedule.RoleDefinitionId
        Write-Host "             - $($role.DisplayName) (eligible until $($schedule.ScheduleInfo.Expiration.EndDateTime.ToString('dd/MM/yyyy')))" -ForegroundColor Magenta
    }
}
else {
    Write-Host "      OK - No PIM eligible assignments found" -ForegroundColor Green
}

# ----------------------------------------------------------------
# STEP 5 — Capture evidence from sign-in logs
# ----------------------------------------------------------------
Write-Host "`n[5/5] Capturing recent sign-in evidence..." -ForegroundColor Yellow

$cutoff = (Get-Date).AddHours(-24).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

try {
    $recentSignIns = Get-MgAuditLogSignIn `
        -Filter "userPrincipalName eq '$UserUPN' and createdDateTime ge $cutoff" `
        -All `
        -ErrorAction Stop

    if ($recentSignIns.Count -gt 0) {
        Write-Host "      Found $($recentSignIns.Count) sign-in(s) in last 24 hours:" -ForegroundColor Magenta

        $evidence = $recentSignIns | ForEach-Object {
            [PSCustomObject]@{
                DateTime    = $_.CreatedDateTime.ToString('dd/MM/yyyy HH:mm:ss')
                Status      = if ($_.Status.ErrorCode -eq 0) { "SUCCESS" } else { "FAILED" }
                IPAddress   = $_.IPAddress
                Location    = "$($_.Location.City), $($_.Location.CountryOrRegion)"
                App         = $_.AppDisplayName
                Device      = $_.DeviceDetail.OperatingSystem
                RiskLevel   = $_.RiskLevelDuringSignIn
            }
        }

        $evidence | Format-Table DateTime, Status, IPAddress, Location, App, RiskLevel -AutoSize

        # Export evidence
        $evidenceFile = ".\$incidentRef-SignInEvidence.csv"
        $evidence | Export-Csv -Path $evidenceFile -NoTypeInformation
        Write-Host "      Evidence exported: $evidenceFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "      INFO - No sign-ins found in last 24 hours" -ForegroundColor Gray
    }
}
catch {
    Write-Host "      WARN - Could not retrieve sign-in logs: $($_.Exception.Message)" -ForegroundColor Magenta
}

# ----------------------------------------------------------------
# INCIDENT SUMMARY
# ----------------------------------------------------------------
Write-Host "`n=== INCIDENT RESPONSE SUMMARY ===" -ForegroundColor Red
Write-Host "Incident Ref     : $incidentRef" -ForegroundColor White
Write-Host "Account          : $($user.DisplayName) ($UserUPN)" -ForegroundColor White
Write-Host "Trigger          : $Reason" -ForegroundColor White
Write-Host "Response time    : $($incidentTime.ToString('dd/MM/yyyy HH:mm:ss'))" -ForegroundColor White
Write-Host "Completed        : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor White
Write-Host "`nActions taken:" -ForegroundColor White
Write-Host "  - All active sessions revoked" -ForegroundColor White
Write-Host "  - Account disabled" -ForegroundColor White
Write-Host "  - $($removedRoles.Count) permanent role(s) removed: $($removedRoles -join ', ')" -ForegroundColor White
Write-Host "`nRequired manual follow-up:" -ForegroundColor Yellow
Write-Host "  1. Review sign-in evidence exported above" -ForegroundColor Yellow
Write-Host "  2. Manually review and remove PIM eligible assignments if appropriate" -ForegroundColor Yellow
Write-Host "  3. Investigate how the account was compromised" -ForegroundColor Yellow
Write-Host "  4. Notify the account owner and their manager" -ForegroundColor Yellow
Write-Host "  5. Determine whether to re-enable account after investigation" -ForegroundColor Yellow
Write-Host "  6. Document incident with full timeline" -ForegroundColor Yellow
Write-Host "`n  ACCOUNT REMAINS DISABLED until manually re-enabled by an administrator." -ForegroundColor Red