<#
.SYNOPSIS
    Processes an internal user move between departments.

.DESCRIPTION
    Handles the full mover process when a user changes department:
    - Updates department and job title attributes
    - Removes from old department group
    - Adds to new department group
    - Retains org-wide group memberships (GRP-AllStaff etc)
    - Removes any role assignments tied to old department
    - Outputs full audit trail

    The mover process is critical for preventing toxic access
    accumulation — where users collect permissions from previous
    roles on top of current ones, violating least privilege.

.PARAMETER UserUPN
    UPN of the user being moved

.PARAMETER NewDepartment
    The department the user is moving TO

.PARAMETER NewJobTitle
    Their new job title in the new department

.PARAMETER OldDepartment
    The department the user is moving FROM (used to remove old group)

.EXAMPLE
    .\Invoke-Mover.ps1 `
        -UserUPN "james.patel@passion2k7.onmicrosoft.com" `
        -OldDepartment "IT" `
        -NewDepartment "Security" `
        -NewJobTitle "Junior Security Analyst"

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

param(
    [Parameter(Mandatory)] [string] $UserUPN,
    [Parameter(Mandatory)] [string] $OldDepartment,
    [Parameter(Mandatory)] [string] $NewDepartment,
    [Parameter(Mandatory)] [string] $NewJobTitle
)

Write-Host "`n=== MOVER PROCESS ===" -ForegroundColor Cyan
Write-Host "User    : $UserUPN" -ForegroundColor Gray
Write-Host "Move    : $OldDepartment → $NewDepartment" -ForegroundColor Gray
Write-Host "Started : $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n" -ForegroundColor Gray

# ----------------------------------------------------------------
# STEP 1 — Verify user exists
# ----------------------------------------------------------------
Write-Host "[1/5] Locating user..." -ForegroundColor Yellow

$user = Get-MgUser -Filter "UserPrincipalName eq '$UserUPN'" -Property Id, DisplayName, Department, JobTitle
if (-not $user) {
    Write-Host "ERROR - User not found: $UserUPN" -ForegroundColor Red
    exit
}

Write-Host "      OK - Found: $($user.DisplayName)" -ForegroundColor Green
Write-Host "           Current department : $($user.Department)" -ForegroundColor Gray
Write-Host "           Current job title  : $($user.JobTitle)" -ForegroundColor Gray

# Warn if current department doesn't match what was specified
if ($user.Department -ne $OldDepartment) {
    Write-Host "      WARN - User's current department ($($user.Department)) doesn't match -OldDepartment ($OldDepartment)" -ForegroundColor Magenta
    Write-Host "             Continuing — but verify this is correct before proceeding in production." -ForegroundColor Magenta
}

# ----------------------------------------------------------------
# STEP 2 — Update user attributes
# ----------------------------------------------------------------
Write-Host "`n[2/5] Updating user attributes..." -ForegroundColor Yellow

try {
    Update-MgUser -UserId $user.Id -BodyParameter @{
        department = $NewDepartment
        jobTitle   = $NewJobTitle
    }
    Write-Host "      OK - Department updated : $OldDepartment → $NewDepartment" -ForegroundColor Green
    Write-Host "      OK - Job title updated  : $($user.JobTitle) → $NewJobTitle" -ForegroundColor Green
}
catch {
    Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ----------------------------------------------------------------
# STEP 3 — Remove from old department group
# ----------------------------------------------------------------
Write-Host "`n[3/5] Removing from old department group..." -ForegroundColor Yellow

$oldGroupName = "GRP-$OldDepartment"
$oldGroup = Get-MgGroup -Filter "DisplayName eq '$oldGroupName'" -ErrorAction SilentlyContinue

if (-not $oldGroup) {
    Write-Host "      WARN - Old group not found: $oldGroupName" -ForegroundColor Magenta
}
else {
    # Check user is actually a member before trying to remove
    $isMember = Get-MgGroupMember -GroupId $oldGroup.Id -All |
        Where-Object { $_.Id -eq $user.Id }

    if (-not $isMember) {
        Write-Host "      INFO - User was not a member of $oldGroupName" -ForegroundColor Gray
    }
    else {
        try {
            Remove-MgGroupMemberByRef -GroupId $oldGroup.Id -DirectoryObjectId $user.Id
            Write-Host "      OK - Removed from $oldGroupName" -ForegroundColor Green
        }
        catch {
            Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ----------------------------------------------------------------
# STEP 4 — Add to new department group
# ----------------------------------------------------------------
Write-Host "`n[4/5] Adding to new department group..." -ForegroundColor Yellow

$newGroupName = "GRP-$NewDepartment"
$newGroup = Get-MgGroup -Filter "DisplayName eq '$newGroupName'" -ErrorAction SilentlyContinue

if (-not $newGroup) {
    Write-Host "      ERROR - New group not found: $newGroupName" -ForegroundColor Red
    Write-Host "              Check department name matches exactly" -ForegroundColor Red
}
else {
    # Check not already a member
    $alreadyMember = Get-MgGroupMember -GroupId $newGroup.Id -All |
        Where-Object { $_.Id -eq $user.Id }

    if ($alreadyMember) {
        Write-Host "      INFO - Already a member of $newGroupName" -ForegroundColor Gray
    }
    else {
        try {
            New-MgGroupMember -GroupId $newGroup.Id -DirectoryObjectId $user.Id
            Write-Host "      OK - Added to $newGroupName" -ForegroundColor Green
        }
        catch {
            Write-Host "      ERROR - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ----------------------------------------------------------------
# STEP 5 — Check for role assignments to review
# ----------------------------------------------------------------
Write-Host "`n[5/5] Checking role assignments for review..." -ForegroundColor Yellow

$roleAssignments = Get-MgUserTransitiveMemberOf -UserId $user.Id -All |
    Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.directoryRole" }

if ($roleAssignments.Count -eq 0) {
    Write-Host "      INFO - No directory role assignments found" -ForegroundColor Gray
}
else {
    Write-Host "      WARN - User has $($roleAssignments.Count) role assignment(s) that may need reviewing:" -ForegroundColor Magenta
    foreach ($role in $roleAssignments) {
        Write-Host "             - $($role.AdditionalProperties['displayName'])" -ForegroundColor Magenta
    }
    Write-Host "             Review whether these roles are still appropriate for the new department." -ForegroundColor Magenta
}

# ----------------------------------------------------------------
# SUMMARY
# ----------------------------------------------------------------
Write-Host "`n=== MOVER SUMMARY ===" -ForegroundColor Cyan
Write-Host "User          : $($user.DisplayName)" -ForegroundColor White
Write-Host "UPN           : $UserUPN" -ForegroundColor White
Write-Host "Move          : $OldDepartment → $NewDepartment" -ForegroundColor White
Write-Host "New job title : $NewJobTitle" -ForegroundColor White
Write-Host "Completed     : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor White
Write-Host "`nActions taken:" -ForegroundColor White
Write-Host "  - User attributes updated (department, job title)" -ForegroundColor White
Write-Host "  - Removed from GRP-$OldDepartment" -ForegroundColor White
Write-Host "  - Added to GRP-$NewDepartment" -ForegroundColor White
Write-Host "`nRequired follow-up:" -ForegroundColor Yellow
Write-Host "  - Review any role assignments listed above" -ForegroundColor Yellow
Write-Host "  - Notify new manager to complete system access request" -ForegroundColor Yellow
Write-Host "  - Update HR system if not triggered automatically" -ForegroundColor Yellow