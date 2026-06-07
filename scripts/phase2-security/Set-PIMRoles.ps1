<#
.SYNOPSIS
    Configures PIM eligible role assignments for lab users.

.DESCRIPTION
    Creates PIM eligible assignments for privileged roles.
    Eligible means the user has ZERO standing privilege — they must
    explicitly activate the role, provide a reason, and it expires
    automatically after the defined hours.

    This is the modern least-privilege approach replacing permanent
    role assignments for sensitive roles.

    Assignments created:
    - Sarah Thompson → User Administrator (eligible, 4hr max)
    - David Okafor   → Global Reader (eligible, 8hr max)
    - Ryan Mitchell  → Security Administrator (eligible, 4hr max)
    - Omar P         → Global Administrator (eligible, 8hr max)

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
    Scope:   RoleManagement.ReadWrite.Directory
#>

# --- Define PIM eligible assignments ---
$eligibleAssignments = @(
    @{
        UserUPN       = "sarah.thompson@passion2k7.onmicrosoft.com"
        RoleName      = "User Administrator"
        MaxActivation = 4   # Hours
        Justification = "IAM Engineer — activate only when managing user lifecycle tasks"
    }
    @{
        UserUPN       = "david.okafor@passion2k7.onmicrosoft.com"
        RoleName      = "Global Reader"
        MaxActivation = 8
        Justification = "Systems Administrator — activate for read-only audit tasks"
    }
    @{
        UserUPN       = "ryan.mitchell@passion2k7.onmicrosoft.com"
        RoleName      = "Security Administrator"
        MaxActivation = 4
        Justification = "Security Analyst — activate only for policy changes"
    }
    @{
        UserUPN       = "OmarP@passion2k7.onmicrosoft.com"
        RoleName      = "Global Administrator"
        MaxActivation = 8
        Justification = "Lab admin — activate only when permanent GA access is required"
    }
)

Write-Host "Creating PIM eligible assignments..." -ForegroundColor Cyan

foreach ($assignment in $eligibleAssignments) {

    # Get the user
    $user = Get-MgUser -Filter "UserPrincipalName eq '$($assignment.UserUPN)'"
    if (-not $user) {
        Write-Host "ERROR - User not found: $($assignment.UserUPN)" -ForegroundColor Red
        continue
    }

    # Get the role definition
    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$($assignment.RoleName)'"
    if (-not $roleDefinition) {
        Write-Host "ERROR - Role not found: $($assignment.RoleName)" -ForegroundColor Red
        continue
    }

    # Build the schedule — eligible for 1 year from today
    # In production you'd review and renew annually
    $startTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $endTime   = (Get-Date).AddYears(1).ToString("yyyy-MM-ddTHH:mm:ssZ")

    $params = @{
        Action           = "adminAssign"        # Admin is creating this eligibility
        Justification    = $assignment.Justification
        RoleDefinitionId = $roleDefinition.Id
        DirectoryScopeId = "/"                  # Tenant-wide scope
        PrincipalId      = $user.Id
        ScheduleInfo     = @{
            StartDateTime = $startTime
            Expiration    = @{
                Type        = "afterDateTime"
                EndDateTime = $endTime
            }
        }
    }

    try {
        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
        Write-Host "ELIGIBLE - $($user.DisplayName) → $($assignment.RoleName)" -ForegroundColor Green
        Write-Host "           Max activation: $($assignment.MaxActivation) hours | Eligible for: 1 year" -ForegroundColor Gray
    }
    catch {
        # Already eligible is not a real error
        if ($_.Exception.Message -like "*already exists*") {
            Write-Host "SKIP  - Already eligible: $($user.DisplayName) → $($assignment.RoleName)" -ForegroundColor Yellow
        }
        else {
            Write-Host "ERROR - $($user.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# --- Audit: show all current eligible assignments ---
Write-Host "`nCurrent PIM eligible assignments:" -ForegroundColor Cyan

Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All |
    ForEach-Object {
        $schedule = $_
        $user = Get-MgUser -UserId $schedule.PrincipalId -ErrorAction SilentlyContinue
        $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $schedule.RoleDefinitionId -ErrorAction SilentlyContinue
    }
        if ($user -and $role) {
            [PSCustomObject]@{
                User      = $user.DisplayName
                Role      = $role.DisplayName
                Expires   = $schedule.ScheduleInfo.Expiration.EndDateTime
            }
        }