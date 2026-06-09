<#
.SYNOPSIS
    Produces a full privileged user audit report.

.DESCRIPTION
    Consolidates all sources of privilege in the tenant into
    a single report:
    - Permanent directory role assignments
    - PIM eligible role assignments
    - Members of privileged groups (GRP-PrivilegedUsers)
    - Break-glass account status verification

    This report answers the auditor question: "Who has elevated
    access in this environment and is it appropriate?"

    Commonly requested for:
    - ISO 27001 audits
    - Cyber Essentials Plus assessments
    - Internal quarterly access reviews
    - New CISO/security manager onboarding

.PARAMETER ExportPath
    Path to export CSV. Defaults to current directory.

.EXAMPLE
    .\Get-PrivilegedUserAudit.ps1
    .\Get-PrivilegedUserAudit.ps1 -ExportPath "C:\Reports"

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

param(
    [string] $ExportPath = "."
)

$reportDate = Get-Date -Format "yyyyMMdd-HHmm"
$exportFile = "$ExportPath\PrivilegedUserAudit-$reportDate.csv"

Write-Host "`n=== PRIVILEGED USER AUDIT ===" -ForegroundColor Cyan
Write-Host "Started : $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n" -ForegroundColor Gray

$fullReport = @()

# ----------------------------------------------------------------
# SECTION 1 — Permanent directory role assignments
# ----------------------------------------------------------------
Write-Host "[1/4] Querying permanent role assignments..." -ForegroundColor Yellow

$activeRoles = Get-MgDirectoryRole -All

foreach ($role in $activeRoles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All

    foreach ($member in $members) {
        $user = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
        if ($user) {
            $fullReport += [PSCustomObject]@{
                UserName       = $user.DisplayName
                UPN            = $user.UserPrincipalName
                Department     = $user.Department
                PrivilegeType  = "Permanent Role"
                PrivilegeName  = $role.DisplayName
                RiskLevel      = switch -Wildcard ($role.DisplayName) {
                    "Global Administrator"    { "CRITICAL" }
                    "*Administrator*"         { "HIGH" }
                    "*Reader*"                { "LOW" }
                    default                   { "MEDIUM" }
                }
                EligibleUntil  = "Permanent"
                AccountEnabled = $user.AccountEnabled
                ReviewAction   = "Certify or Revoke"
            }
        }
    }
}

Write-Host "      Found $($fullReport.Count) permanent role assignment(s)" -ForegroundColor Gray

# ----------------------------------------------------------------
# SECTION 2 — PIM eligible assignments
# ----------------------------------------------------------------
Write-Host "`n[2/4] Querying PIM eligible assignments..." -ForegroundColor Yellow

$eligibleSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
$pimCount = 0

foreach ($schedule in $eligibleSchedules) {
    $user = Get-MgUser -UserId $schedule.PrincipalId -ErrorAction SilentlyContinue
    $role = Get-MgRoleManagementDirectoryRoleDefinition `
                -UnifiedRoleDefinitionId $schedule.RoleDefinitionId `
                -ErrorAction SilentlyContinue

    if ($user -and $role) {
        $fullReport += [PSCustomObject]@{
            UserName       = $user.DisplayName
            UPN            = $user.UserPrincipalName
            Department     = $user.Department
            PrivilegeType  = "PIM Eligible"
            PrivilegeName  = $role.DisplayName
            RiskLevel      = switch -Wildcard ($role.DisplayName) {
                "Global Administrator"    { "CRITICAL" }
                "*Administrator*"         { "HIGH" }
                "*Reader*"                { "LOW" }
                default                   { "MEDIUM" }
            }
            EligibleUntil  = $schedule.ScheduleInfo.Expiration.EndDateTime.ToString('dd/MM/yyyy')
            AccountEnabled = $user.AccountEnabled
            ReviewAction   = "Certify or Revoke"
        }
        $pimCount++
    }
}

Write-Host "      Found $pimCount PIM eligible assignment(s)" -ForegroundColor Gray

# ----------------------------------------------------------------
# SECTION 3 — Privileged group members
# ----------------------------------------------------------------
Write-Host "`n[3/4] Querying privileged group membership..." -ForegroundColor Yellow

$privGroup = Get-MgGroup -Filter "DisplayName eq 'GRP-PrivilegedUsers'" -ErrorAction SilentlyContinue

if ($privGroup) {
    $privMembers = Get-MgGroupMember -GroupId $privGroup.Id -All

    foreach ($member in $privMembers) {
        $user = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
        if ($user) {
            $fullReport += [PSCustomObject]@{
                UserName       = $user.DisplayName
                UPN            = $user.UserPrincipalName
                Department     = $user.Department
                PrivilegeType  = "Privileged Group"
                PrivilegeName  = "GRP-PrivilegedUsers"
                RiskLevel      = "HIGH"
                EligibleUntil  = "Permanent (group membership)"
                AccountEnabled = $user.AccountEnabled
                ReviewAction   = "Certify or Remove from group"
            }
        }
    }
    Write-Host "      GRP-PrivilegedUsers has $($privMembers.Count) member(s)" -ForegroundColor Gray
}
else {
    Write-Host "      INFO - GRP-PrivilegedUsers not found" -ForegroundColor Gray
}

# ----------------------------------------------------------------
# SECTION 4 — Break-glass account verification
# ----------------------------------------------------------------
Write-Host "`n[4/4] Verifying break-glass accounts..." -ForegroundColor Yellow

$breakGlassUPNs = @(
    "breakglass1@passion2k7.onmicrosoft.com"
    "breakglass2@passion2k7.onmicrosoft.com"
)

foreach ($upn in $breakGlassUPNs) {
    $bgUser = Get-MgUser `
        -Filter "UserPrincipalName eq '$upn'" `
        -Property DisplayName, AccountEnabled, UserPrincipalName `
        -ErrorAction SilentlyContinue

    if ($bgUser) {
        $status = if ($bgUser.AccountEnabled) { "OK - Enabled" } else { "WARN - Disabled" }
        $colour = if ($bgUser.AccountEnabled) { "Green" } else { "Red" }
        Write-Host "      $status : $upn" -ForegroundColor $colour
    }
    else {
        Write-Host "      WARN - Not found: $upn" -ForegroundColor Red
    }
}

# ----------------------------------------------------------------
# DISPLAY & EXPORT
# ----------------------------------------------------------------
Write-Host "`n=== PRIVILEGED ACCESS SUMMARY ===" -ForegroundColor Cyan

# Count by risk level
$critical = ($fullReport | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$high     = ($fullReport | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$medium   = ($fullReport | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$low      = ($fullReport | Where-Object { $_.RiskLevel -eq "LOW" }).Count

Write-Host "Total privileged assignments : $($fullReport.Count)" -ForegroundColor White
Write-Host "Critical                     : $critical" -ForegroundColor Red
Write-Host "High                         : $high" -ForegroundColor Magenta
Write-Host "Medium                       : $medium" -ForegroundColor Yellow
Write-Host "Low                          : $low" -ForegroundColor Green

# Show critical and high risk first
Write-Host "`nCritical and high risk assignments:" -ForegroundColor Red
$fullReport |
    Where-Object { $_.RiskLevel -in @("CRITICAL","HIGH") } |
    Sort-Object RiskLevel, PrivilegeType |
    Format-Table UserName, Department, PrivilegeType, PrivilegeName, RiskLevel, EligibleUntil -AutoSize

# Export full report
$fullReport | Sort-Object RiskLevel, PrivilegeType |
    Export-Csv -Path $exportFile -NoTypeInformation
Write-Host "Full report exported to: $exportFile" -ForegroundColor Cyan
Write-Host "`nCompleted: $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray