<#
.SYNOPSIS
    Creates lab users in Entra ID from a CSV file.

.DESCRIPTION
    Reads users.csv and creates each user in the tenant with a
    standard password, correct department, job title, and usage
    location. Skips any user that already exists.

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

# --- Configuration ---
$csvPath       = "$PSScriptRoot\users.csv"
$defaultDomain = "passion2k7.onmicrosoft.com"
$tempPassword  = "Contoso@2026!"  # Users would change this on first login

# --- Import the CSV ---
$users = Import-Csv -Path $csvPath
Write-Host "Found $($users.Count) users in CSV" -ForegroundColor Cyan

# --- Loop through each row and create the user ---
foreach ($user in $users) {

    # Build the UserPrincipalName from first and last name
    # e.g. James Patel → james.patel@passion2k7.onmicrosoft.com
    $upn = "$($user.FirstName.ToLower()).$($user.LastName.ToLower())@$defaultDomain"

    # Check if user already exists — skip if so
    $existing = Get-MgUser -Filter "UserPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "SKIP - already exists: $upn" -ForegroundColor Yellow
        continue
    }

    # Build the parameter set for the new user
    $params = @{
        DisplayName       = "$($user.FirstName) $($user.LastName)"
        GivenName         = $user.FirstName
        Surname           = $user.LastName
        UserPrincipalName = $upn
        MailNickname      = "$($user.FirstName.ToLower()).$($user.LastName.ToLower())"
        Department        = $user.Department
        JobTitle          = $user.JobTitle
        UsageLocation     = $user.UsageLocation
        AccountEnabled    = $true
        PasswordProfile   = @{
            Password                             = $tempPassword
            ForceChangePasswordNextSignIn        = $true
        }
    }

    try {
        New-MgUser @params
        Write-Host "CREATED - $($params.DisplayName) ($upn)" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR   - $($params.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nDone. Check above for any errors." -ForegroundColor Cyan