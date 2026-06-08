<#
.SYNOPSIS
    Onboards a new user to the Contoso UK tenant.

.DESCRIPTION
    Full joiner process covering:
    - Create the user account with correct attributes
    - Add to department security group
    - Add to GRP-AllStaff
    - Assign AAD Premium P2 licence
    - Output a summary for the IT ticket/audit trail

    In a real environment this script would be triggered by an
    HR system (e.g. Workday, SAP) via an API call or Azure
    Automation runbook when a new starter is added.

.PARAMETER FirstName
    New user's first name

.PARAMETER LastName
    New user's last name

.PARAMETER Department
    Department name — must match an existing GRP- group

.PARAMETER JobTitle
    User's job title

.EXAMPLE
    .\Invoke-Joiner.ps1 -FirstName "Zara" -LastName "Khan" -Department "IT" -JobTitle "Junior IAM Analyst"

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

param(
    [Parameter(Mandatory)] [string] $FirstName,
    [Parameter(Mandatory)] [string] $LastName,
    [Parameter(Mandatory)] [string] $Department,
    [Parameter(Mandatory)] [string] $JobTitle
)

# --- Configuration ---
$domain      = "passion2k7.onmicrosoft.com"
$tempPassword = "Welcome@Contoso2026!"
$usageLocation = "GB"

# --- Derived values ---
$upn         = "$($FirstName.ToLower()).$($LastName.ToLower())@$domain"
$displayName = "$FirstName $LastName"
$mailNickname = "$($FirstName.ToLower()).$($LastName.ToLower())"

Write-Host "`n=== JOINER PROCESS: $displayName ===" -ForegroundColor Cyan
Write-Host "Started : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Gray

# ----------------------------------------------------------------
# STEP 1 — Check user doesn't already exist
# ----------------------------------------------------------------
Write-Host "`n[1/4] Checking for existing account..." -ForegroundColor Yellow

$existing = Get-MgUser -Filter "UserPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "ERROR - User already exists: $upn" -ForegroundColor Red
    Write-Host "Joiner process aborted." -ForegroundColor Red
    exit
}
Write-Host "      OK - No existing account found" -ForegroundColor Green

# ----------------------------------------------------------------
# STEP 2 — Create the user account
# ----------------------------------------------------------------
Write-Host "`n[2/4] Creating user account..." -ForegroundColor Yellow

$userParams = @{
    DisplayName       = $displayName
    GivenName         = $FirstName
    Surname           = $LastName
    UserPrincipalName = $upn
    MailNickname      = $mailNickname
    Department        = $Department
    JobTitle          = $JobTitle
    UsageLocation     = $usageLocation
    AccountEnabled    = $true
    PasswordProfile   = @{
        Password                      = $tempPassword
        ForceChangePasswordNextSignIn = $true
    }
}

try {
    $newUser = New-MgUser @userParams
    Write-Host "      OK - Account created: $upn" -ForegroundColor Green
    Write-Host "           ID: $($newUser.Id)" -ForegroundColor Gray
}
catch {
    Write-Host "ERROR - Failed to create account: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ----------------------------------------------------------------
# STEP 3 — Assign to groups
# ----------------------------------------------------------------
Write-Host "`n[3/4] Assigning group membership..." -ForegroundColor Yellow

# Department group
$deptGroupName = "GRP-$Department"
$deptGroup = Get-MgGroup -Filter "DisplayName eq '$deptGroupName'" -ErrorAction SilentlyContinue

if ($deptGroup) {
    try {
        New-MgGroupMember -GroupId $deptGroup.Id -DirectoryObjectId $newUser.Id
        Write-Host "      OK - Added to $deptGroupName" -ForegroundColor Green
    }
    catch {
        Write-Host "      WARN - Could not add to $deptGroupName : $($_.Exception.Message)" -ForegroundColor Magenta
    }
}
else {
    Write-Host "      WARN - Department group not found: $deptGroupName" -ForegroundColor Magenta
}

# AllStaff group
$allStaffGroup = Get-MgGroup -Filter "DisplayName eq 'GRP-AllStaff'"
try {
    New-MgGroupMember -GroupId $allStaffGroup.Id -DirectoryObjectId $newUser.Id
    Write-Host "      OK - Added to GRP-AllStaff" -ForegroundColor Green
}
catch {
    Write-Host "      WARN - Could not add to GRP-AllStaff: $($_.Exception.Message)" -ForegroundColor Magenta
}

# ----------------------------------------------------------------
# STEP 4 — Assign licence
# ----------------------------------------------------------------
Write-Host "`n[4/4] Assigning licence..." -ForegroundColor Yellow

$sku = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq "AAD_PREMIUM_P2" }

try {
    Set-MgUserLicense -UserId $newUser.Id -AddLicenses @(@{ SkuId = $sku.SkuId }) -RemoveLicenses @()
    Write-Host "      OK - AAD Premium P2 assigned" -ForegroundColor Green
}
catch {
    Write-Host "      WARN - Licence assignment failed: $($_.Exception.Message)" -ForegroundColor Magenta
}

# ----------------------------------------------------------------
# SUMMARY
# ----------------------------------------------------------------
Write-Host "`n=== JOINER SUMMARY ===" -ForegroundColor Cyan
Write-Host "Name          : $displayName" -ForegroundColor White
Write-Host "UPN           : $upn" -ForegroundColor White
Write-Host "Department    : $Department" -ForegroundColor White
Write-Host "Job Title     : $JobTitle" -ForegroundColor White
Write-Host "Temp Password : $tempPassword" -ForegroundColor White
Write-Host "Groups        : $deptGroupName, GRP-AllStaff" -ForegroundColor White
Write-Host "Licence       : AAD_PREMIUM_P2" -ForegroundColor White
Write-Host "Completed     : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor White
Write-Host "`nAction required: Provide temp password to user via secure channel." -ForegroundColor Yellow