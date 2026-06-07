<#
.SYNOPSIS
    Creates department security groups in Entra ID.

.DESCRIPTION
    Creates one security group per department plus organisation-wide
    groups. These groups will be used for licence assignment, 
    Conditional Access, and RBAC in later sessions.

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

# --- Define the groups to create ---
$groups = @(
    # Department groups
    @{ Name = "GRP-IT";         Description = "All IT department staff" }
    @{ Name = "GRP-Finance";    Description = "All Finance department staff" }
    @{ Name = "GRP-HR";         Description = "All HR department staff" }
    @{ Name = "GRP-Operations"; Description = "All Operations department staff" }
    @{ Name = "GRP-Legal";      Description = "All Legal department staff" }
    @{ Name = "GRP-Security";   Description = "All Security department staff" }

    # Organisation-wide groups
    @{ Name = "GRP-AllStaff";       Description = "All Contoso UK employees" }
    @{ Name = "GRP-MFAExempt";      Description = "Accounts exempt from MFA — keep this empty in production" }
    @{ Name = "GRP-PrivilegedUsers"; Description = "Users with elevated permissions — used in PIM policies" }
)

Write-Host "Creating $($groups.Count) security groups..." -ForegroundColor Cyan

foreach ($group in $groups) {

    # Check if group already exists
    $existing = Get-MgGroup -Filter "DisplayName eq '$($group.Name)'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "SKIP - already exists: $($group.Name)" -ForegroundColor Yellow
        continue
    }

    $params = @{
        DisplayName     = $group.Name
        Description     = $group.Description
        MailEnabled     = $false        # Security group — not mail-enabled
        MailNickname    = $group.Name.Replace("-","").ToLower()
        SecurityEnabled = $true
    }

    try {
        $newGroup = New-MgGroup @params
        Write-Host "CREATED - $($group.Name) | ID: $($newGroup.Id)" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR   - $($group.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nDone. Verifying groups in tenant..." -ForegroundColor Cyan

# --- Verify: list all GRP- groups ---
Get-MgGroup -All | 
    Where-Object { $_.DisplayName -like "GRP-*" } |
    Select-Object DisplayName, Description |
    Sort-Object DisplayName |
    Format-Table -AutoSize