<#
.SYNOPSIS
    Queries Entra ID Identity Protection for risky sign-ins.

.DESCRIPTION
    Retrieves sign-ins flagged as risky by Entra ID Identity
    Protection and categorises them by risk level. Also checks
    for users currently flagged as at-risk.

    Identity Protection analyses every sign-in for signals including:
    - Impossible travel (signing in from two countries in an hour)
    - Anonymous IP addresses (Tor, VPN)
    - Password spray attack patterns
    - Leaked credential matches (against known breach databases)
    - Unfamiliar sign-in properties

    This report is used by security teams for threat hunting and
    by IAM teams to identify accounts needing remediation.

.PARAMETER HoursBack
    How many hours of sign-in log to query. Defaults to 168 (7 days).

.PARAMETER RiskLevel
    Minimum risk level to report. Options: low, medium, high.
    Defaults to low (shows all).

.EXAMPLE
    .\Get-RiskySignIns.ps1
    .\Get-RiskySignIns.ps1 -HoursBack 720 -RiskLevel high

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
    Requires: IdentityRiskEvent.Read.All scope
#>

param(
    [int]    $HoursBack  = 168,
    [ValidateSet("low","medium","high")]
    [string] $RiskLevel  = "low"
)

$cutoff = (Get-Date).AddHours(-$HoursBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "`n=== RISKY SIGN-IN REPORT ===" -ForegroundColor Cyan
Write-Host "Period    : Last $HoursBack hours" -ForegroundColor Gray
Write-Host "Min risk  : $RiskLevel" -ForegroundColor Gray
Write-Host "Started   : $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n" -ForegroundColor Gray

# ----------------------------------------------------------------
# SECTION 1 — Risky sign-ins
# ----------------------------------------------------------------
Write-Host "[1/2] Querying risky sign-ins..." -ForegroundColor Yellow

try {
    $riskySignIns = Get-MgRiskDetection `
        -Filter "activityDateTime ge $cutoff" `
        -All `
        -ErrorAction Stop

    if ($riskySignIns.Count -eq 0) {
        Write-Host "      OK - No risk detections found" -ForegroundColor Green
    }
    else {
        # Filter by requested risk level
        $levelOrder = @{ "low" = 1; "medium" = 2; "high" = 3 }
        $minLevel   = $levelOrder[$RiskLevel]

        $filtered = $riskySignIns | Where-Object {
            $levelOrder[$_.RiskLevel.ToString().ToLower()] -ge $minLevel
        }

        Write-Host "      Found $($filtered.Count) detection(s) at $RiskLevel risk or above" -ForegroundColor Magenta

        $riskReport = $filtered | ForEach-Object {
            [PSCustomObject]@{
                DateTime    = $_.ActivityDateTime.ToString('dd/MM/yyyy HH:mm')
                User        = $_.UserDisplayName
                UPN         = $_.UserPrincipalName
                RiskLevel   = $_.RiskLevel.ToString().ToUpper()
                DetectionType = $_.RiskEventType
                IPAddress   = $_.IPAddress
                Location    = "$($_.Location.City), $($_.Location.CountryOrRegion)"
                Status      = $_.RiskState
            }
        }

        $riskReport | Sort-Object RiskLevel -Descending |
            Format-Table DateTime, User, RiskLevel, DetectionType, Location -AutoSize
    }
}
catch {
    Write-Host "      WARN - Could not query risk detections: $($_.Exception.Message)" -ForegroundColor Magenta
    Write-Host "             This is normal on a dev tenant with no real sign-in activity." -ForegroundColor Gray
}

# ----------------------------------------------------------------
# SECTION 2 — Users currently at risk
# ----------------------------------------------------------------
Write-Host "`n[2/2] Querying users currently flagged as at-risk..." -ForegroundColor Yellow

try {
    $riskyUsers = Get-MgRiskyUser -All -ErrorAction Stop |
        Where-Object { $_.RiskLevel -ne "none" -and $_.RiskState -ne "dismissed" }

    if ($riskyUsers.Count -eq 0) {
        Write-Host "      OK - No users currently flagged as at-risk" -ForegroundColor Green
    }
    else {
        Write-Host "      ALERT - $($riskyUsers.Count) user(s) currently at risk!" -ForegroundColor Red

        $riskyUsers | ForEach-Object {
            [PSCustomObject]@{
                User          = $_.UserDisplayName
                UPN           = $_.UserPrincipalName
                RiskLevel     = $_.RiskLevel.ToString().ToUpper()
                RiskState     = $_.RiskState
                LastUpdated   = $_.RiskLastUpdatedDateTime.ToString('dd/MM/yyyy HH:mm')
                RecommendedAction = switch ($_.RiskLevel.ToString().ToLower()) {
                    "high"   { "Force password reset + revoke sessions immediately" }
                    "medium" { "Investigate sign-in history, consider password reset" }
                    "low"    { "Monitor — review if risk level increases" }
                }
            }
        } | Format-Table User, RiskLevel, RiskState, RecommendedAction -AutoSize -Wrap
    }
}
catch {
    Write-Host "      WARN - Could not query risky users: $($_.Exception.Message)" -ForegroundColor Magenta
    Write-Host "             Requires IdentityRiskyUser.Read.All scope." -ForegroundColor Gray
}

# --- Summary ---
Write-Host "`n=== GUIDANCE ===" -ForegroundColor Cyan
Write-Host "High risk   → Immediate action. Force password reset, revoke sessions." -ForegroundColor Red
Write-Host "Medium risk → Investigate within 24 hours." -ForegroundColor Magenta
Write-Host "Low risk    → Monitor. Escalate if pattern continues." -ForegroundColor Yellow
Write-Host "`nCompleted: $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray