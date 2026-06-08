<#
.SYNOPSIS
    Exports a full access review report for the tenant.

.DESCRIPTION
    Produces a comprehensive access review covering:
    - All group memberships (who is in which group)
    - Directory role assignments (who has admin roles)
    - PIM eligible assignments (who can elevate to what)
    - Licence assignments (who has what licence)

    This report is used in quarterly access reviews where
    managers certify whether their staff still need the
    access they have. A core IAM governance process.

.PARAMETER ExportPath
    Path to export CSV reports. Defaults to current directory.

.EXAMPLE
    .\Get-AccessReview.ps1
    .\Get-AccessReview.ps1 -ExportPath "C:\Reports\Q2-2026"

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

param(
    [string] $ExportPath = "."
)

$reportDate = Get-Date -Format "yyyyMMdd-HHmm"

Write-Host "`n=== ACCESS REVIEW EXPORT ===" -ForegroundColor Cyan
Write-Host "Started : $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n" -ForegroundColor Gray

# ----------------------------------------------------------------
# SECTION 1 — Group membership report
# ----------------------------------------------------------------
Write-Host "[1/4] Exporting group memberships..." -ForegroundColor Yellow

$groupReport = @()

$allGroups = Get-MgGroup -All | Where-Object { $_.DisplayName -like "GRP-*" }

foreach ($group in $allGroups) {
    $members = Get-MgGroupMember -GroupId $group.Id -All

    if ($members.Count -eq 0) {
        $groupReport += [PSCustomObject]@{
            GroupName  = $group.DisplayName
            MemberName = "-- No members --"
            MemberUPN  = ""
            Department = ""
        }
        continue
    }

    foreach ($member in $members) {
        $user = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
        if ($user) {
            $groupReport += [PSCustomObject]@{
                GroupName  = $group.DisplayName
                MemberName = $user.DisplayName
                MemberUPN  = $user.UserPrincipalName
                Department = $user.Department
            }
        }
    }
}

$groupExport = "$ExportPath\AccessReview-Groups-$reportDate.csv"
$groupReport | Export-Csv -Path $groupExport -NoTypeInformation
Write-Host "      OK - $($groupReport.Count) group membership records exported" -ForegroundColor Green

# ----------------------------------------------------------------
# SECTION 2 — Directory role assignments
# ----------------------------------------------------------------
Write-Host "`n[2/4] Exporting directory role assignments..." -ForegroundColor Yellow

$roleReport = @()

$activeRoles = Get-MgDirectoryRole -All

foreach ($role in $activeRoles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All

    foreach ($member in $members) {
        $user = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
        if ($user) {
            $roleReport += [PSCustomObject]@{
                RoleName       = $role.DisplayName
                AssignmentType = "Permanent"
                UserName       = $user.DisplayName
                UPN            = $user.UserPrincipalName
                Department     = $user.Department
                ReviewAction   = "Certify or Revoke"
            }
        }
    }
}

$roleExport = "$ExportPath\AccessReview-Roles-$reportDate.csv"
$roleReport | Export-Csv -Path $roleExport -NoTypeInformation
Write-Host "      OK - $($roleReport.Count) role assignment records exported" -ForegroundColor Green

# ----------------------------------------------------------------
# SECTION 3 — PIM eligible assignments
# ----------------------------------------------------------------
Write-Host "`n[3/4] Exporting PIM eligible assignments..." -ForegroundColor Yellow

$pimReport = @()

$eligibleSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All

foreach ($schedule in $eligibleSchedules) {
    $user = Get-MgUser -UserId $schedule.PrincipalId -ErrorAction SilentlyContinue
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $schedule.RoleDefinitionId -ErrorAction SilentlyContinue

    if ($user -and $role) {
        $pimReport += [PSCustomObject]@{
            RoleName       = $role.DisplayName
            AssignmentType = "PIM Eligible"
            UserName       = $user.DisplayName
            UPN            = $user.UserPrincipalName
            Department     = $user.Department
            EligibleUntil  = $schedule.ScheduleInfo.Expiration.EndDateTime
            ReviewAction   = "Certify or Revoke"
        }
    }
}

$pimExport = "$ExportPath\AccessReview-PIM-$reportDate.csv"
$pimReport | Export-Csv -Path $pimExport -NoTypeInformation
Write-Host "      OK - $($pimReport.Count) PIM eligible assignment records exported" -ForegroundColor Green

# ----------------------------------------------------------------
# SECTION 4 — Licence assignments
# ----------------------------------------------------------------
Write-Host "`n[4/4] Exporting licence assignments..." -ForegroundColor Yellow

$licenceReport = @()

$licensedUsers = Get-MgUser -All -Property DisplayName, UserPrincipalName, Department, AccountEnabled, AssignedLicenses |
    Where-Object { $_.AssignedLicenses.Count -gt 0 }

$skus = Get-MgSubscribedSku

foreach ($user in $licensedUsers) {
    foreach ($licence in $user.AssignedLicenses) {
        $skuName = ($skus | Where-Object { $_.SkuId -eq $licence.SkuId }).SkuPartNumber
        $licenceReport += [PSCustomObject]@{
            UserName       = $user.DisplayName
            UPN            = $user.UserPrincipalName
            Department     = $user.Department
            AccountEnabled = $user.AccountEnabled
            Licence        = $skuName
            ReviewAction   = "Certify or Revoke"
        }
    }
}

$licenceExport = "$ExportPath\AccessReview-Licences-$reportDate.csv"
$licenceReport | Export-Csv -Path $licenceExport -NoTypeInformation
Write-Host "      OK - $($licenceReport.Count) licence assignment records exported" -ForegroundColor Green

# ----------------------------------------------------------------
# SUMMARY
# ----------------------------------------------------------------
Write-Host "`n=== ACCESS REVIEW SUMMARY ===" -ForegroundColor Cyan
Write-Host "Group memberships   : $($groupReport.Count) records" -ForegroundColor White
Write-Host "Role assignments    : $($roleReport.Count) records" -ForegroundColor White
Write-Host "PIM eligible roles  : $($pimReport.Count) records" -ForegroundColor White
Write-Host "Licence assignments : $($licenceReport.Count) records" -ForegroundColor White
Write-Host "`nFiles exported:" -ForegroundColor White
Write-Host "  $groupExport" -ForegroundColor Gray
Write-Host "  $roleExport" -ForegroundColor Gray
Write-Host "  $pimExport" -ForegroundColor Gray
Write-Host "  $licenceExport" -ForegroundColor Gray
Write-Host "`nCompleted : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray
Write-Host "`nNext step : Send CSVs to department managers for certification." -ForegroundColor Yellow