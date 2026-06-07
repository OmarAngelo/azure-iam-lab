<#
.SYNOPSIS
    Creates Conditional Access policies to enforce MFA.

.DESCRIPTION
    Creates two foundational CA policies:
    1. Require MFA for all users on all cloud apps
    2. Block legacy authentication protocols

    These are the two most important baseline security policies
    in any Entra ID environment and appear in every CIS benchmark.

.NOTES
    Author:  Omar
    Created: June 2026
    Requires: Connect-Tenant.ps1 to have been run first
    
    IMPORTANT: Policies are created in REPORT-ONLY mode first.
    This means they are evaluated but not enforced — safe for a lab.
    In production you would monitor report-only for 2-4 weeks before
    switching to Enabled to avoid locking users out.
#>

# ----------------------------------------------------------------
# POLICY 1 — Require MFA for all users
# ----------------------------------------------------------------
Write-Host "Creating Policy 1: Require MFA for All Users..." -ForegroundColor Cyan

$mfaPolicy = @{
    DisplayName = "LAB-CA001 - Require MFA for All Users"
    State       = "enabledForReportingButNotEnforced"  # Report-only mode
    
    Conditions = @{
        Users = @{
            IncludeUsers = @("All")         # Target every user
            ExcludeUsers = @()              # In production: exclude break-glass accounts here
        }
        Applications = @{
            IncludeApplications = @("All")  # All cloud apps
        }
        ClientAppTypes = @(                 # Modern auth clients only
            "browser"
            "mobileAppsAndDesktopClients"
        )
    }

    GrantControls = @{
        Operator        = "OR"
        BuiltInControls = @("mfa")          # Require MFA to grant access
    }
}

try {
    $policy1 = New-MgIdentityConditionalAccessPolicy -BodyParameter $mfaPolicy
    Write-Host "CREATED - $($policy1.DisplayName)" -ForegroundColor Green
    Write-Host "         ID: $($policy1.Id)" -ForegroundColor Gray
    Write-Host "         State: $($policy1.State)" -ForegroundColor Gray
}
catch {
    Write-Host "ERROR - $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------------
# POLICY 2 — Block legacy authentication
# ----------------------------------------------------------------
Write-Host "`nCreating Policy 2: Block Legacy Authentication..." -ForegroundColor Cyan

$legacyBlockPolicy = @{
    DisplayName = "LAB-CA002 - Block Legacy Authentication"
    State       = "enabledForReportingButNotEnforced"

    Conditions = @{
        Users = @{
            IncludeUsers = @("All")
        }
        Applications = @{
            IncludeApplications = @("All")
        }
        ClientAppTypes = @(                 # These are the legacy auth protocols
            "exchangeActiveSync"            # Old Exchange mobile sync
            "other"                         # SMTP, IMAP, POP3, older Office clients
        )
    }

    GrantControls = @{
        Operator        = "OR"
        BuiltInControls = @("block")        # Block access entirely
    }
}

try {
    $policy2 = New-MgIdentityConditionalAccessPolicy -BodyParameter $legacyBlockPolicy
    Write-Host "CREATED - $($policy2.DisplayName)" -ForegroundColor Green
    Write-Host "         ID: $($policy2.Id)" -ForegroundColor Gray
    Write-Host "         State: $($policy2.State)" -ForegroundColor Gray
}
catch {
    Write-Host "ERROR - $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------------
# Verify — list all CA policies in the tenant
# ----------------------------------------------------------------
Write-Host "`nAll Conditional Access policies in tenant:" -ForegroundColor Cyan

Get-MgIdentityConditionalAccessPolicy |
    Select-Object DisplayName, State, Id |
    Format-Table -AutoSize