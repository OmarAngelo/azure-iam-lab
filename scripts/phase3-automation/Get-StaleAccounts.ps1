<#
.SYNOPSIS
    Detects and reports on stale user accounts in Entra ID.

.DESCRIPTION
    Queries sign-in activity for all users and flags accounts that
    haven't signed in within the defined threshold. Exports results
    to a CSV for audit purposes.

    Stale accounts are a common audit finding — active accounts
    with no recent sign-in represent unnecessary attack surface
    and should be reviewed, disabled, or deleted.

.PARAMETER DaysThreshold
    Number of days without sign-in to consider an account stale.
    Defaults to 90 days.

.PARAMETER ExportPath
    Path to export the CSV report. Defaults to current directory.

.EXAMPLE
    .\Get-StaleAccounts.ps1
    .\Get-StaleAccounts.ps1 -DaysThreshold 30
    .\Get-StaleAccounts.ps1 -DaysThreshold 60 -ExportPath "C:\Reports"

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
    Requires: AuditLog.Read.All scope
#>

param(
    [int]    $DaysThreshold = 90,
    [string] $ExportPath    = "."
)

$cutoffDate  = (Get-Date).AddDays(-$DaysThreshold)
$reportDate  = Get-Date -Format "yyyyMMdd-HHmm"
$exportFile  = "$ExportPath\StaleAccounts-$reportDate.csv"

Write-Host "`n=== STALE ACCOUNT REPORT ===" -ForegroundColor Cyan
Write-Host "Threshold : $DaysThreshold days (cutoff: $($cutoffDate.ToString('dd/MM/yyyy')))" -ForegroundColor Gray
Write-Host "Started   : $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n" -ForegroundColor Gray

# --- Get all users with sign-in activity ---
Write-Host "Retrieving users and sign-in activity..." -ForegroundColor Yellow

$allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, Department, JobTitle, CreatedDateTime, SignInActivity |
    Where-Object {
        $_.UserPrincipalName -notlike "breakglass*" -and
        $_.UserPrincipalName -notlike "OmarP@*"
    }

Write-Host "Total users retrieved: $($allUsers.Count)" -ForegroundColor Gray

# --- Categorise each user ---
$staleAccounts   = @()
$activeAccounts  = @()
$neverSignedIn   = @()

foreach ($user in $allUsers) {

    $lastSignIn = $user.SignInActivity.LastSignInDateTime

    if (-not $lastSignIn) {
        # Never signed in — created but never used
        $neverSignedIn += [PSCustomObject]@{
            DisplayName       = $user.DisplayName
            UPN               = $user.UserPrincipalName
            Department        = $user.Department
            JobTitle          = $user.JobTitle
            AccountEnabled    = $user.AccountEnabled
            LastSignIn        = "Never"
            DaysSinceSignIn   = "N/A"
            CreatedDate       = $user.CreatedDateTime.ToString('dd/MM/yyyy')
            Status            = "Never signed in"
            RecommendedAction = "Review — disable if not needed"
        }
    }
    elseif ($lastSignIn -lt $cutoffDate) {
        # Signed in but not recently — stale
        $daysSince = [int]((Get-Date) - $lastSignIn).TotalDays
        $staleAccounts += [PSCustomObject]@{
            DisplayName       = $user.DisplayName
            UPN               = $user.UserPrincipalName
            Department        = $user.Department
            JobTitle          = $user.JobTitle
            AccountEnabled    = $user.AccountEnabled
            LastSignIn        = $lastSignIn.ToString('dd/MM/yyyy')
            DaysSinceSignIn   = $daysSince
            CreatedDate       = $user.CreatedDateTime.ToString('dd/MM/yyyy')
            Status            = "Stale"
            RecommendedAction = "Disable and notify manager"
        }
    }
    else {
        # Active
        $daysSince = [int]((Get-Date) - $lastSignIn).TotalDays
        $activeAccounts += [PSCustomObject]@{
            DisplayName       = $user.DisplayName
            UPN               = $user.UserPrincipalName
            Department        = $user.Department
            AccountEnabled    = $user.AccountEnabled
            LastSignIn        = $lastSignIn.ToString('dd/MM/yyyy')
            DaysSinceSignIn   = $daysSince
            Status            = "Active"
        }
    }
}

# --- Display summary ---
Write-Host "`n=== RESULTS SUMMARY ===" -ForegroundColor Cyan
Write-Host "Active accounts    : $($activeAccounts.Count)" -ForegroundColor Green
Write-Host "Stale accounts     : $($staleAccounts.Count)" -ForegroundColor Red
Write-Host "Never signed in    : $($neverSignedIn.Count)" -ForegroundColor Magenta

# --- Show stale accounts ---
if ($staleAccounts.Count -gt 0) {
    Write-Host "`nStale accounts (last sign-in > $DaysThreshold days ago):" -ForegroundColor Red
    $staleAccounts | Format-Table DisplayName, Department, LastSignIn, DaysSinceSignIn, RecommendedAction -AutoSize
}

# --- Show never signed in ---
if ($neverSignedIn.Count -gt 0) {
    Write-Host "Accounts that have never signed in:" -ForegroundColor Magenta
    $neverSignedIn | Format-Table DisplayName, Department, CreatedDate, RecommendedAction -AutoSize
}

# --- Export full report to CSV ---
$fullReport = $staleAccounts + $neverSignedIn
if ($fullReport.Count -gt 0) {
    $fullReport | Export-Csv -Path $exportFile -NoTypeInformation
    Write-Host "Report exported to: $exportFile" -ForegroundColor Cyan
}
else {
    Write-Host "`nNo stale accounts found." -ForegroundColor Green
}

Write-Host "`nCompleted: $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray