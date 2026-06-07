<#
.SYNOPSIS
    Assigns Azure AD Premium P2 licences to all lab users.

.DESCRIPTION
    Retrieves the AAD_PREMIUM_P2 SKU from the tenant and assigns
    it to all lab users. Skips users who already have it.
    P2 enables PIM, Conditional Access, and Identity Protection.

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

# --- Get the P2 licence SKU ---
$sku = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq "AAD_PREMIUM_P2" }

if (-not $sku) {
    Write-Host "ERROR - AAD_PREMIUM_P2 licence not found in tenant" -ForegroundColor Red
    exit
}

$available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
Write-Host "Licence: $($sku.SkuPartNumber)" -ForegroundColor Cyan
Write-Host "Available slots: $available" -ForegroundColor Cyan

# --- Get all lab users excluding admin ---
$users = Get-MgUser -All -Property DisplayName, UserPrincipalName, Id, AssignedLicenses |
    Where-Object { 
        $_.UserPrincipalName -like "*@passion2k7.onmicrosoft.com" -and
        $_.UserPrincipalName -notlike "OmarP@*"
    }

Write-Host "Users to process: $($users.Count)`n" -ForegroundColor Cyan

foreach ($user in $users) {

    # Check if user already has this licence
    $alreadyLicensed = $user.AssignedLicenses | 
        Where-Object { $_.SkuId -eq $sku.SkuId }

    if ($alreadyLicensed) {
        Write-Host "SKIP  - Already licensed: $($user.DisplayName)" -ForegroundColor Yellow
        continue
    }

    # Assign the licence
    $licenceParams = @{
        AddLicenses    = @(@{ SkuId = $sku.SkuId })
        RemoveLicenses = @()
    }

    try {
        Set-MgUserLicense -UserId $user.Id @licenceParams
        Write-Host "LICENSED - $($user.DisplayName)" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR    - $($user.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nDone. Verifying licence assignment..." -ForegroundColor Cyan

# --- Summary: count licensed users ---
$licensedCount = (Get-MgUser -All -Property AssignedLicenses |
    Where-Object { $_.AssignedLicenses.Count -gt 0 }).Count

Write-Host "Total licensed users in tenant: $licensedCount" -ForegroundColor Green