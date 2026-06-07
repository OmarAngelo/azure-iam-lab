<#
.SYNOPSIS
    Assigns Entra ID directory roles to lab users.

.DESCRIPTION
    Assigns realistic role assignments that mirror a real IAM environment:
    - Sarah Thompson (IAM Engineer) → User Administrator
    - Ryan Mitchell (Security Analyst) → Security Reader
    - Charlotte Davis (Compliance Officer) → Global Reader
    - James Patel (IT Support) → Helpdesk Administrator
    
    These assignments demonstrate least-privilege — each person gets
    only the role their job function requires, nothing more.

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first

.LINK
    https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
#>

# --- Define role assignments ---
# Format: UPN → Role Display Name
$roleAssignments = @(
    @{
        UserUPN  = "sarah.thompson@passion2k7.onmicrosoft.com"
        RoleName = "User Administrator"
        Reason   = "IAM Engineer — manages user lifecycle"
    }
    @{
        UserUPN  = "ryan.mitchell@passion2k7.onmicrosoft.com"
        RoleName = "Security Reader"
        Reason   = "Security Analyst — read-only security visibility"
    }
    @{
        UserUPN  = "charlotte.davis@passion2k7.onmicrosoft.com"
        RoleName = "Global Reader"
        Reason   = "Compliance Officer — read-only across all services"
    }
    @{
        UserUPN  = "james.patel@passion2k7.onmicrosoft.com"
        RoleName = "Helpdesk Administrator"
        Reason   = "IT Support — can reset passwords and manage basic users"
    }
)

Write-Host "Processing $($roleAssignments.Count) role assignments..." -ForegroundColor Cyan

foreach ($assignment in $roleAssignments) {

    # Get the user
    $user = Get-MgUser -Filter "UserPrincipalName eq '$($assignment.UserUPN)'"
    if (-not $user) {
        Write-Host "ERROR - User not found: $($assignment.UserUPN)" -ForegroundColor Red
        continue
    }

    # Get the role template
    $roleTemplate = Get-MgDirectoryRoleTemplate | 
        Where-Object { $_.DisplayName -eq $assignment.RoleName }
    if (-not $roleTemplate) {
        Write-Host "ERROR - Role not found: $($assignment.RoleName)" -ForegroundColor Red
        continue
    }

    # Activate the role in the tenant if not already active
    # (Roles must be activated before they can be assigned)
    $activeRole = Get-MgDirectoryRole -Filter "DisplayName eq '$($assignment.RoleName)'" -ErrorAction SilentlyContinue
    if (-not $activeRole) {
        Write-Host "Activating role: $($assignment.RoleName)..." -ForegroundColor Gray
        $activeRole = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id
    }

    # Check if user already has this role
    $existingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $activeRole.Id
    $alreadyAssigned = $existingMembers | Where-Object { $_.Id -eq $user.Id }

    if ($alreadyAssigned) {
        Write-Host "SKIP  - $($user.DisplayName) already has $($assignment.RoleName)" -ForegroundColor Yellow
        continue
    }

    # Assign the role
    try {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $activeRole.Id -BodyParameter @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)"
        }
        Write-Host "ASSIGNED - $($user.DisplayName) → $($assignment.RoleName)" -ForegroundColor Green
        Write-Host "           Reason: $($assignment.Reason)" -ForegroundColor Gray
    }
    catch {
        Write-Host "ERROR - $($user.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Audit report: show all current role assignments ---
Write-Host "`nCurrent directory role assignments:" -ForegroundColor Cyan

Get-MgDirectoryRole |
    ForEach-Object {
        $role = $_
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
        foreach ($member in $members) {
            $memberDetails = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
            if ($memberDetails) {
                [PSCustomObject]@{
                    Role        = $role.DisplayName
                    User        = $memberDetails.DisplayName
                    UPN         = $memberDetails.UserPrincipalName
                }
            }
        }
    } | Sort-Object Role | Format-Table -AutoSize