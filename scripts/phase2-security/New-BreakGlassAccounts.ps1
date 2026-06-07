<#
.SYNOPSIS
    Creates and configures break-glass emergency admin accounts.

.DESCRIPTION
    Break-glass accounts are cloud-only Global Admin accounts used
    when normal administrative access is unavailable. Examples:
    - MFA system outage blocking normal admin sign-in
    - Federated identity provider (e.g. ADFS) going down
    - Primary admin account compromised or locked

    Microsoft recommends every tenant has at least two break-glass
    accounts, excluded from all Conditional Access policies, with
    credentials stored securely offline.

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first

.LINK
    https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access
#>

# --- Configuration ---
$domain       = "passion2k7.onmicrosoft.com"

# In production these passwords would be:
# - Randomly generated (e.g. 40+ characters)
# - Split across two envelopes stored in a physical safe
# - Never stored digitally
# For the lab we use known passwords so we can document them
$breakGlassUsers = @(
    @{
        DisplayName       = "Break Glass Account 1"
        UserPrincipalName = "breakglass1@$domain"
        MailNickname      = "breakglass1"
        # In production: use a random 40-char password
        Password          = "Br3akGl@ss!Lab2026#1"
        Description       = "EMERGENCY ACCESS ONLY - Break Glass Account 1. Any use must be immediately reported to the security team."
    }
    @{
        DisplayName       = "Break Glass Account 2"
        UserPrincipalName = "breakglass2@$domain"
        MailNickname      = "breakglass2"
        Password          = "Br3akGl@ss!Lab2026#2"
        Description       = "EMERGENCY ACCESS ONLY - Break Glass Account 2. Any use must be immediately reported to the security team."
    }
)

Write-Host "Creating break-glass accounts..." -ForegroundColor Cyan

$createdAccounts = @()

foreach ($bgUser in $breakGlassUsers) {

    # Check if already exists
    $existing = Get-MgUser -Filter "UserPrincipalName eq '$($bgUser.UserPrincipalName)'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "SKIP - Already exists: $($bgUser.UserPrincipalName)" -ForegroundColor Yellow
        $createdAccounts += $existing
        continue
    }

    $params = @{
        DisplayName       = $bgUser.DisplayName
        UserPrincipalName = $bgUser.UserPrincipalName
        MailNickname      = $bgUser.MailNickname
        AccountEnabled    = $true
        PasswordProfile   = @{
            Password                      = $bgUser.Password
            ForceChangePasswordNextSignIn = $false  # Password must stay as set
        }
    }

    try {
        $newUser = New-MgUser @params
        Write-Host "CREATED - $($bgUser.UserPrincipalName)" -ForegroundColor Green
        $createdAccounts += $newUser
    }
    catch {
        Write-Host "ERROR   - $($bgUser.UserPrincipalName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Assign Global Administrator role ---
Write-Host "`nAssigning Global Administrator role..." -ForegroundColor Cyan

$globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'"

foreach ($account in $createdAccounts) {

    $existingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
    $alreadyAssigned = $existingMembers | Where-Object { $_.Id -eq $account.Id }

    if ($alreadyAssigned) {
        Write-Host "SKIP  - Already Global Admin: $($account.UserPrincipalName)" -ForegroundColor Yellow
        continue
    }

    try {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $globalAdminRole.Id -BodyParameter @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($account.Id)"
        }
        Write-Host "ASSIGNED - Global Administrator → $($account.UserPrincipalName)" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Exclude from Conditional Access ---
Write-Host "`nExcluding break-glass accounts from Conditional Access policies..." -ForegroundColor Cyan

# Get all CA policies
$caPolicies = Get-MgIdentityConditionalAccessPolicy

# Get the IDs of both break-glass accounts
$bgIds = $createdAccounts | Select-Object -ExpandProperty Id

foreach ($policy in $caPolicies) {

    # Get current excluded users
    $currentExclusions = $policy.Conditions.Users.ExcludeUsers

    # Add break-glass IDs if not already excluded
    $newExclusions = ($currentExclusions + $bgIds) | Select-Object -Unique

    try {
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter @{
            Conditions = @{
                Users = @{
                    IncludeUsers = $policy.Conditions.Users.IncludeUsers
                    ExcludeUsers = @($newExclusions)
                }
            }
        }
        Write-Host "UPDATED - $($policy.DisplayName) — break-glass accounts excluded" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR   - $($policy.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Summary ---
Write-Host "`n=== Break-Glass Account Summary ===" -ForegroundColor Yellow
Write-Host "Accounts created  : $($createdAccounts.Count)" -ForegroundColor White
Write-Host "Role assigned     : Global Administrator" -ForegroundColor White
Write-Host "CA policies updated: $($caPolicies.Count)" -ForegroundColor White
Write-Host "`nCRITICAL REMINDERS:" -ForegroundColor Red
Write-Host "  1. Store passwords in a physical safe — never digitally" -ForegroundColor Red
Write-Host "  2. Set up an alert for any sign-in from these accounts" -ForegroundColor Red
Write-Host "  3. Test access quarterly — do not let credentials expire" -ForegroundColor Red
Write-Host "  4. Never use these accounts for day-to-day administration" -ForegroundColor Red