<#
.SYNOPSIS
    Detects and reports any changes made to break-glass accounts.

.DESCRIPTION
    Queries the Entra ID audit log for any operations performed
    on break-glass accounts in the specified time window.

    Changes to break-glass accounts are high-severity events.
    Any unexpected modification could indicate:
    - An attacker attempting to take over emergency access
    - Accidental misconfiguration of a critical account
    - Unauthorised administrative activity

    In production this script would run on a schedule (e.g. every
    15 minutes via Azure Automation) and send an alert email or
    Teams message if any changes are detected.

.PARAMETER HoursBack
    How many hours of audit log to check. Defaults to 24.

.EXAMPLE
    .\Watch-BreakGlassChanges.ps1
    .\Watch-BreakGlassChanges.ps1 -HoursBack 168  # Check last 7 days

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
    Requires: AuditLog.Read.All scope
#>

param(
    [int] $HoursBack = 24
)

$cutoff         = (Get-Date).AddHours(-$HoursBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$breakGlassUPNs = @(
    "breakglass1@passion2k7.onmicrosoft.com"
    "breakglass2@passion2k7.onmicrosoft.com"
)

Write-Host "`n=== BREAK-GLASS ACCOUNT CHANGE MONITOR ===" -ForegroundColor Cyan
Write-Host "Checking last $HoursBack hours of audit logs..." -ForegroundColor Gray
Write-Host "Accounts monitored: $($breakGlassUPNs -join ', ')`n" -ForegroundColor Gray

$allFindings = @()

foreach ($upn in $breakGlassUPNs) {

    Write-Host "Checking: $upn" -ForegroundColor Yellow

    # Get the user object so we can search by ID
    $bgUser = Get-MgUser -Filter "UserPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
    if (-not $bgUser) {
        Write-Host "  WARN - Account not found: $upn" -ForegroundColor Magenta
        continue
    }

    # Query audit logs for any activity targeting this user
    # We filter by the target object ID and time window
    $auditLogs = Get-MgAuditLogDirectoryAudit -Filter "targetResources/any(t: t/id eq '$($bgUser.Id)') and activityDateTime ge $cutoff" -All

    if ($auditLogs.Count -eq 0) {
        Write-Host "  OK - No changes detected" -ForegroundColor Green
        continue
    }

    # Changes found — this is noteworthy
    Write-Host "  ALERT - $($auditLogs.Count) change(s) detected!" -ForegroundColor Red

    foreach ($log in $auditLogs) {
        $finding = [PSCustomObject]@{
            Account       = $upn
            DateTime      = $log.ActivityDateTime.ToString('dd/MM/yyyy HH:mm:ss')
            Operation     = $log.ActivityDisplayName
            Result        = $log.Result
            InitiatedBy   = if ($log.InitiatedBy.User.UserPrincipalName) {
                                $log.InitiatedBy.User.UserPrincipalName
                            } else {
                                $log.InitiatedBy.App.DisplayName
                            }
            Severity      = "HIGH"
        }

        $allFindings += $finding

        Write-Host "  -----------------------------------------------" -ForegroundColor Red
        Write-Host "  Operation   : $($finding.Operation)" -ForegroundColor Red
        Write-Host "  When        : $($finding.DateTime)" -ForegroundColor Red
        Write-Host "  Initiated by: $($finding.InitiatedBy)" -ForegroundColor Red
        Write-Host "  Result      : $($finding.Result)" -ForegroundColor Red
    }
}

# --- Summary ---
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan

if ($allFindings.Count -eq 0) {
    Write-Host "No changes detected to break-glass accounts in the last $HoursBack hours." -ForegroundColor Green
    Write-Host "Status: NORMAL" -ForegroundColor Green
}
else {
    Write-Host "ALERT: $($allFindings.Count) change(s) detected across break-glass accounts!" -ForegroundColor Red
    Write-Host "Status: INVESTIGATE IMMEDIATELY" -ForegroundColor Red
    Write-Host "`nFindings:" -ForegroundColor Red
    $allFindings | Format-Table Account, DateTime, Operation, InitiatedBy, Result -AutoSize

    # Export findings for incident record
    $exportFile = ".\BreakGlassChanges-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
    $allFindings | Export-Csv -Path $exportFile -NoTypeInformation
    Write-Host "Findings exported to: $exportFile" -ForegroundColor Red

    Write-Host "`nRecommended actions:" -ForegroundColor Yellow
    Write-Host "  1. Identify who made the change and why" -ForegroundColor Yellow
    Write-Host "  2. Verify break-glass credentials are still secure" -ForegroundColor Yellow
    Write-Host "  3. Check if change was authorised and documented" -ForegroundColor Yellow
    Write-Host "  4. If unauthorised — treat as security incident" -ForegroundColor Yellow
}

Write-Host "`nCompleted: $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray