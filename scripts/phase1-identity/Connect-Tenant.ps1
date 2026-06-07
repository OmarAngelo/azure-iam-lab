<#
.SYNOPSIS
    Connects PowerShell to the lab Microsoft 365 tenant.

.DESCRIPTION
    Establishes an authenticated session to Microsoft Graph.
    Run this at the start of every lab session before any other script.

.NOTES
    Author:  Omar
    Created: June 2026
    Module:  Microsoft.Graph 2.37.0
    Account: OmarP@passion2k7.onmicrosoft.com
    Tenant:  ace847f5-71b1-4ba8-9bd6-b50bec7fbbf4
#>

$graphScopes = @(
    "User.ReadWrite.All"
    "Group.ReadWrite.All"
    "Directory.ReadWrite.All"
    "RoleManagement.ReadWrite.Directory"
    "Policy.ReadWrite.ConditionalAccess"
    "AuditLog.Read.All"
    "UserAuthenticationMethod.ReadWrite.All"
)

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan

Connect-MgGraph -Scopes $graphScopes -NoWelcome -UseDeviceAuthentication

$context = Get-MgContext
Write-Host "Connected as : $($context.Account)" -ForegroundColor Green
Write-Host "Tenant ID    : $($context.TenantId)" -ForegroundColor Green
Write-Host "Scopes granted: $($context.Scopes.Count)" -ForegroundColor Green
Write-Host "`nReady. You can now run any Phase 1 script." -ForegroundColor Green
