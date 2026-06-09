<#
.SYNOPSIS
    Detects and alerts on any sign-ins from break-glass accounts.

.DESCRIPTION
    Queries the Entra ID sign-in log for any authentication events
    from break-glass accounts in the specified time window.

    A break-glass sign-in is a high-severity event that indicates
    either a genuine emergency or potential account compromise.
    Either way it requires immediate investigation.

    In production this script runs every 15-30 minutes via Azure
    Automation and sends an immediate alert to the security team
    via email or Teams webhook if any sign-in is detected.

.PARAMETER HoursBack
    How many hours of sign-in log to check. Defaults to 24.

.EXAMPLE
    .\Get-BreakGlassSignIns.ps1
    .\Get-BreakGlassSignIns.ps1 -HoursBack 168  # Check last 7 days

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
    Requires: AuditLog.Read.All scope

.LINK
    https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access
#>

param(
    [int] $HoursBack = 24
)

$cutoff         = (Get-Date).AddHours(-$HoursBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$breakGlassUPNs = @(
    "breakglass1@passion2k7.onmicrosoft.com"
    "breakglass2@passion2k7.onmicrosoft.com"
)

Write-Host "`n=== BREAK-GLASS SIGN-IN MONITOR ===" -ForegroundColor Cyan
Write-Host "Checking last $HoursBack hours of sign-in logs..." -ForegroundColor Gray
Write-Host "Accounts monitored: $($breakGlassUPNs -join ', ')`n" -ForegroundColor Gray

$allSignIns = @()

foreach ($upn in $breakGlassUPNs) {

    Write-Host "Checking: $upn" -ForegroundColor Yellow

    # Query sign-in logs for this account within the time window
    $signIns = Get-MgAuditLogSignIn `
        -Filter "userPrincipalName eq '$upn' and createdDateTime ge $cutoff" `
        -All `
        -ErrorAction SilentlyContinue

    if (-not $signIns -or $signIns.Count -eq 0) {
        Write-Host "  OK - No sign-ins detected" -ForegroundColor Green
        continue
    }

    # Sign-ins found — immediate alert
    Write-Host "  ALERT - $($signIns.Count) sign-in(s) detected!" -ForegroundColor Red

    foreach ($signIn in $signIns) {
        $finding = [PSCustomObject]@{
            Account         = $upn
            DateTime        = $signIn.CreatedDateTime.ToString('dd/MM/yyyy HH:mm:ss')
            Status          = $signIn.Status.ErrorCode -eq 0 ? "SUCCESS" : "FAILED"
            IPAddress       = $signIn.IPAddress
            Location        = "$($signIn.Location.City), $($signIn.Location.CountryOrRegion)"
            AppUsed         = $signIn.AppDisplayName
            ClientApp       = $signIn.ClientAppUsed
            DeviceOS        = $signIn.DeviceDetail.OperatingSystem
            ConditionalAccess = $signIn.ConditionalAccessStatus
            Severity        = "CRITICAL"
        }

        $allSignIns += $finding

        $statusColour = if ($finding.Status -eq "SUCCESS") { "Red" } else { "Magenta" }

        Write-Host "  -----------------------------------------------" -ForegroundColor Red
        Write-Host "  Status    : $($finding.Status)" -ForegroundColor $statusColour
        Write-Host "  When      : $($finding.DateTime)" -ForegroundColor Red
        Write-Host "  From IP   : $($finding.IPAddress)" -ForegroundColor Red
        Write-Host "  Location  : $($finding.Location)" -ForegroundColor Red
        Write-Host "  App used  : $($finding.AppUsed)" -ForegroundColor Red
        Write-Host "  Device OS : $($finding.DeviceOS)" -ForegroundColor Red
    }
}

# --- Summary ---
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan

if ($allSignIns.Count -eq 0) {
    Write-Host "No sign-ins detected from break-glass accounts in the last $HoursBack hours." -ForegroundColor Green
    Write-Host "Status: NORMAL" -ForegroundColor Green
}
else {
    $successCount = ($allSignIns | Where-Object { $_.Status -eq "SUCCESS" }).Count
    $failedCount  = ($allSignIns | Where-Object { $_.Status -eq "FAILED" }).Count

    Write-Host "CRITICAL ALERT: Break-glass account activity detected!" -ForegroundColor Red
    Write-Host "Successful sign-ins : $successCount" -ForegroundColor Red
    Write-Host "Failed sign-ins     : $failedCount" -ForegroundColor Magenta
    Write-Host "`nFull details:" -ForegroundColor Red
    $allSignIns | Format-Table Account, DateTime, Status, IPAddress, Location, AppUsed -AutoSize

    # Export for incident record
    $exportFile = ".\BreakGlassSignIns-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
    $allSignIns | Export-Csv -Path $exportFile -NoTypeInformation
    Write-Host "Incident record exported to: $exportFile" -ForegroundColor Red

    Write-Host "`nImmediate actions required:" -ForegroundColor Yellow
    Write-Host "  1. Confirm with the team whether this was an authorised emergency" -ForegroundColor Yellow
    Write-Host "  2. If unauthorised — isolate and investigate immediately" -ForegroundColor Yellow
    Write-Host "  3. Review what actions were taken during the session" -ForegroundColor Yellow
    Write-Host "  4. Rotate break-glass credentials after any use" -ForegroundColor Yellow
    Write-Host "  5. Document the incident with timeline and justification" -ForegroundColor Yellow

    if ($successCount -gt 0) {
        Write-Host "`n  WARNING: Successful sign-in detected — treat as P1 incident" -ForegroundColor Red
        Write-Host "           until authorisation is confirmed." -ForegroundColor Red
    }
}

Write-Host "`nCompleted: $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray