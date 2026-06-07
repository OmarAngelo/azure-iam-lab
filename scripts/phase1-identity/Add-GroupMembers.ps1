<#
.SYNOPSIS
    Assigns users to their department security groups.

.DESCRIPTION
    Reads all lab users from the tenant, matches each user's Department
    field to the correct GRP- group, and adds them as members.
    Also adds all staff to GRP-AllStaff.

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
#>

# --- Map department names to group names ---
$departmentGroupMap = @{
    "IT"         = "GRP-IT"
    "Finance"    = "GRP-Finance"
    "HR"         = "GRP-HR"
    "Operations" = "GRP-Operations"
    "Legal"      = "GRP-Legal"
    "Security"   = "GRP-Security"
}

$allStaffGroupName = "GRP-AllStaff"

# --- Get all lab users (exclude the admin account) ---
$users = Get-MgUser -All -Property DisplayName, Department, UserPrincipalName, Id |
    Where-Object { $_.UserPrincipalName -like "*@passion2k7.onmicrosoft.com" -and
                   $_.UserPrincipalName -notlike "OmarP@*" -and
                   $_.Department -ne $null }

Write-Host "Found $($users.Count) users to process" -ForegroundColor Cyan

# --- Get the AllStaff group ---
$allStaffGroup = Get-MgGroup -Filter "DisplayName eq '$allStaffGroupName'"

foreach ($user in $users) {

    # 1. Add to department group
    $groupName = $departmentGroupMap[$user.Department]

    if ($groupName) {
        $group = Get-MgGroup -Filter "DisplayName eq '$groupName'"

        if ($group) {
            try {
                New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id
                Write-Host "ADDED - $($user.DisplayName) → $groupName" -ForegroundColor Green
            }
            catch {
                # Most likely already a member — not a real error
                Write-Host "SKIP  - $($user.DisplayName) → $groupName (already member)" -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "WARN  - No group mapping for department: $($user.Department)" -ForegroundColor Magenta
    }

    # 2. Add everyone to AllStaff
    try {
        New-MgGroupMember -GroupId $allStaffGroup.Id -DirectoryObjectId $user.Id
        Write-Host "ADDED - $($user.DisplayName) → $allStaffGroupName" -ForegroundColor Green
    }
    catch {
        Write-Host "SKIP  - $($user.DisplayName) → $allStaffGroupName (already member)" -ForegroundColor Yellow
    }
}

Write-Host "`nDone. Verifying membership counts..." -ForegroundColor Cyan

# --- Show a summary of how many members each group has ---
Get-MgGroup -All |
    Where-Object { $_.DisplayName -like "GRP-*" } |
    Sort-Object DisplayName |
    ForEach-Object {
        $memberCount = (Get-MgGroupMember -GroupId $_.Id -All).Count
        [PSCustomObject]@{
            Group   = $_.DisplayName
            Members = $memberCount
        }
    } | Format-Table -AutoSize