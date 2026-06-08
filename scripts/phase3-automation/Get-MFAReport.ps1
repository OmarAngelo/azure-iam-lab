<#
.SYNOPSIS
    Reports on MFA registration status for all users.

.DESCRIPTION
    Queries authentication method registrations for all users
    and produces a report showing:
    - Who has MFA registered
    - What MFA methods they're using
    - Who has no MFA registered at all (highest risk)
    - Who is MFA capable vs MFA registered

    This report is commonly requested by:
    - Security auditors
    - Compliance teams (ISO 27001, Cyber Essentials Plus)
    - Management wanting MFA adoption metrics

.PARAMETER ExportPath
    Path to export CSV report. Defaults to current directory.

.EXAMPLE
    .\Get-MFAReport.ps1
    .\Get-MFAReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
    Requires: UserAuthenticationMethod.Read.All scope
#>

param(
    [string] $ExportPath = "."
)

$reportDate = Get-Date -Format "yyyyMMdd-HHmm"
$exportFile = "$ExportPath\MFAReport-$reportDate.csv"

Write-Host "`n=== MFA REGISTRATION REPORT ===" -ForegroundColor Cyan
Write-Host "Started : $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n" -ForegroundColor Gray

# --- Get all users excluding break-glass and admin ---
Write-Host "Retrieving users..." -ForegroundColor Yellow

$allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Department, AccountEnabled |
    Where-Object {
        $_.UserPrincipalName -notlike "breakglass*" -and
        $_.UserPrincipalName -notlike "OmarP@*" -and
        $_.AccountEnabled -eq $true
    }

Write-Host "Users to process: $($allUsers.Count)" -ForegroundColor Gray
Write-Host "Querying authentication methods (this may take a moment)...`n" -ForegroundColor Yellow

$report = @()

foreach ($user in $allUsers) {

    # Get all registered authentication methods for this user
    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id

    # The password method is always present — it doesn't count as MFA
    # We filter it out to get true MFA methods only
    $mfaMethods = $authMethods | Where-Object {
        $_.AdditionalProperties["@odata.type"] -ne "#microsoft.graph.passwordAuthenticationMethod"
    }

    # Identify which specific methods are registered
    $methodNames = $mfaMethods | ForEach-Object {
        switch ($_.AdditionalProperties["@odata.type"]) {
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { "Microsoft Authenticator" }
            "#microsoft.graph.phoneAuthenticationMethod"                  { "SMS/Phone" }
            "#microsoft.graph.fido2AuthenticationMethod"                  { "FIDO2 Security Key" }
            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"{ "Windows Hello" }
            "#microsoft.graph.softwareOathAuthenticationMethod"           { "TOTP App" }
            "#microsoft.graph.temporaryAccessPassAuthenticationMethod"    { "Temporary Access Pass" }
            default                                                        { "Other" }
        }
    }

    $hasMFA      = $mfaMethods.Count -gt 0
    $methodList  = if ($methodNames) { $methodNames -join ", " } else { "None" }

    $report += [PSCustomObject]@{
        DisplayName    = $user.DisplayName
        UPN            = $user.UserPrincipalName
        Department     = $user.Department
        AccountEnabled = $user.AccountEnabled
        MFARegistered  = $hasMFA
        MethodCount    = $mfaMethods.Count
        Methods        = $methodList
        RiskLevel      = if (-not $hasMFA) { "HIGH" } elseif ($mfaMethods.Count -eq 1) { "MEDIUM" } else { "LOW" }
    }

    $status = if ($hasMFA) { "✓" } else { "✗" }
    $colour = if ($hasMFA) { "Green" } else { "Red" }
    Write-Host "  $status $($user.DisplayName) ($($user.Department)) — $methodList" -ForegroundColor $colour
}

# --- Summary statistics ---
$mfaRegistered    = ($report | Where-Object { $_.MFARegistered }).Count
$mfaNotRegistered = ($report | Where-Object { -not $_.MFARegistered }).Count
$highRisk         = ($report | Where-Object { $_.RiskLevel -eq "HIGH" }).Count

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total users        : $($report.Count)" -ForegroundColor White
Write-Host "MFA registered     : $mfaRegistered" -ForegroundColor Green
Write-Host "No MFA registered  : $mfaNotRegistered" -ForegroundColor Red
Write-Host "High risk accounts : $highRisk" -ForegroundColor Red
Write-Host "MFA adoption rate  : $([math]::Round($mfaRegistered / $report.Count * 100, 1))%" -ForegroundColor White

# --- Show high risk users ---
$highRiskUsers = $report | Where-Object { $_.RiskLevel -eq "HIGH" }
if ($highRiskUsers.Count -gt 0) {
    Write-Host "`nHigh risk users (no MFA registered):" -ForegroundColor Red
    $highRiskUsers | Format-Table DisplayName, Department, MFARegistered, RiskLevel -AutoSize
}

# --- Export ---
$report | Export-Csv -Path $exportFile -NoTypeInformation
Write-Host "Report exported to: $exportFile" -ForegroundColor Cyan
Write-Host "Completed : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray