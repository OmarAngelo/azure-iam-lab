<#
.SYNOPSIS
    Creates department OUs and provisions lab users in Active Directory.

.DESCRIPTION
    Creates a Contoso UK OU structure with department sub-OUs,
    then provisions 16 users from a defined list into their
    correct department OUs.

.NOTES
    Author:  Omar
    Created: July 2026
    Domain:  contoso.local
    DC:      192.168.100.10
#>

param(
    [string] $DCHostname = "192.168.100.10"
)

$credential = Get-Credential -Message "Enter DC admin credentials (CONTOSO\Administrator)"

Invoke-Command -ComputerName $DCHostname -Credential $credential -ScriptBlock {

    # --- Create OU structure ---
    Write-Host "Creating OU structure..." -ForegroundColor Cyan

    New-ADOrganizationalUnit -Name "Contoso UK" -Path "DC=contoso,DC=local" -ErrorAction SilentlyContinue

    $deptOUs = @("IT","Finance","HR","Operations","Legal","Security")
    foreach ($dept in $deptOUs) {
        New-ADOrganizationalUnit -Name $dept -Path "OU=Contoso UK,DC=contoso,DC=local" -ErrorAction SilentlyContinue
        Write-Host "  Created OU: $dept" -ForegroundColor Green
    }

    # --- Create users ---
    Write-Host "`nProvisioning users..." -ForegroundColor Cyan

    $users = @(
        @{ First="James";     Last="Patel";     Department="IT";         Title="IT Support Analyst" }
        @{ First="Sarah";     Last="Thompson";  Department="IT";         Title="IAM Engineer" }
        @{ First="David";     Last="Okafor";    Department="IT";         Title="Systems Administrator" }
        @{ First="Emma";      Last="Clarke";    Department="Finance";    Title="Finance Analyst" }
        @{ First="Mohammed";  Last="Ali";       Department="Finance";    Title="Senior Accountant" }
        @{ First="Lucy";      Last="Bennett";   Department="Finance";    Title="Finance Manager" }
        @{ First="Thomas";    Last="Wright";    Department="HR";         Title="HR Advisor" }
        @{ First="Priya";     Last="Sharma";    Department="HR";         Title="HR Manager" }
        @{ First="Daniel";    Last="Evans";     Department="HR";         Title="Recruitment Coordinator" }
        @{ First="Sophie";    Last="Wilson";    Department="Operations"; Title="Operations Analyst" }
        @{ First="Marcus";    Last="Johnson";   Department="Operations"; Title="Logistics Coordinator" }
        @{ First="Aisha";     Last="Rahman";    Department="Operations"; Title="Operations Manager" }
        @{ First="Oliver";    Last="Brown";     Department="Legal";      Title="Legal Counsel" }
        @{ First="Charlotte"; Last="Davis";     Department="Legal";      Title="Compliance Officer" }
        @{ First="Ryan";      Last="Mitchell";  Department="Security";   Title="Security Analyst" }
        @{ First="Fatima";    Last="Hussein";   Department="Security";   Title="Security Engineer" }
    )

    $defaultPassword = ConvertTo-SecureString "Welcome@Contoso2026!" -AsPlainText -Force

    foreach ($user in $users) {
        $sam = "$($user.First.ToLower()).$($user.Last.ToLower())"
        $ou  = "OU=$($user.Department),OU=Contoso UK,DC=contoso,DC=local"
        $upn = "$sam@contoso.local"

        try {
            New-ADUser `
                -GivenName         $user.First `
                -Surname           $user.Last `
                -Name              "$($user.First) $($user.Last)" `
                -SamAccountName    $sam `
                -UserPrincipalName $upn `
                -Department        $user.Department `
                -Title             $user.Title `
                -Path              $ou `
                -AccountPassword   $defaultPassword `
                -Enabled           $true
            Write-Host "  CREATED - $($user.First) $($user.Last) → $($user.Department)" -ForegroundColor Green
        }
        catch {
            Write-Host "  ERROR   - $($user.First) $($user.Last): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "`nDone. Total users: $((Get-ADUser -Filter *).Count - 3)" -ForegroundColor Cyan
}
