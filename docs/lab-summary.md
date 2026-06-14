# Azure IAM Lab — Project Summary

## Overview
A self-directed hands-on lab built to develop practical Microsoft Entra ID 
and Azure IAM skills while transitioning into an IAM analyst role. Built on 
a Microsoft 365 Developer tenant using PowerShell 7 and the Microsoft Graph 
PowerShell SDK.

All scripts are version controlled on GitHub and reflect real-world IAM 
processes and security standards.

---

## Background
Prior to this project I worked at Royal Mail, where I developed experience 
working within large-scale operational environments with complex access 
requirements across a large workforce. This lab was built to translate that 
operational understanding into hands-on technical IAM skills using the 
Microsoft cloud stack.

---

## Technology stack
- PowerShell 7
- Microsoft Graph PowerShell SDK (v2.37.0)
- Microsoft Entra ID (Azure AD)
- Microsoft 365 Developer Tenant
- Azure AD Premium P2
- Git / GitHub

---

## Phase 1 — Identity Foundation

**Goal:** Build a realistic organisational identity structure from scratch.

**What I built:**
- Provisioned 16 users across 6 departments (IT, Finance, HR, Operations, 
  Legal, Security) from a CSV file, mirroring a bulk onboarding process
- Created 9 security groups — one per department plus organisation-wide 
  groups including GRP-AllStaff and GRP-PrivilegedUsers
- Automated group membership assignment based on user department attributes
- Assigned Azure AD Premium P2 licences to all users

**Key skills demonstrated:**
- Microsoft Graph PowerShell for identity provisioning
- Bulk user creation from structured data sources
- Group-based access management principles
- Licence lifecycle management

**Why it matters:**
Group-based access control is the foundation of scalable IAM. Assigning 
access to groups rather than individuals means joiners and leavers are 
managed by changing group membership rather than hunting through individual 
permissions — critical at any organisation with more than a handful of users.

---

## Phase 2 — Security & Access Controls

**Goal:** Implement a professional security posture using modern IAM controls.

**What I built:**

**Conditional Access policies**
- CA001: Require MFA for all users across all cloud applications
- CA002: Block legacy authentication protocols (SMTP, IMAP, ActiveSync)
- Both created in report-only mode — the production-safe approach before 
  enforcing policies that could lock users out

**Break-glass accounts**
- Two cloud-only Global Administrator accounts for emergency access
- Excluded from all Conditional Access policies
- Configured following Microsoft's emergency access guidance
- Documented with reminders for physical credential storage and quarterly 
  access testing

**RBAC role assignments**
- Assigned least-privilege directory roles matching each person's job function:
  - IAM Engineer → User Administrator
  - Security Analyst → Security Reader  
  - Compliance Officer → Global Reader
  - IT Support → Helpdesk Administrator
- No user given more privilege than their role requires

**Privileged Identity Management (PIM)**
- Converted sensitive role assignments from permanent to eligible
- Users have zero standing privilege — must activate roles explicitly
- Activation limited to 4-8 hours depending on role sensitivity
- Every activation logged with justification — full audit trail

**Audit finding and remediation**
Running the privileged user audit (Phase 4) identified that one user held 
both a permanent User Administrator role assignment AND a PIM eligible 
assignment for the same role — a violation of least privilege, since the 
permanent assignment defeats the purpose of PIM's zero-standing-privilege 
model. This was remediated by removing the permanent assignment, leaving 
only the PIM eligible one. This demonstrates the audit-remediate cycle that 
forms the basis of ongoing access governance.

**Key skills demonstrated:**
- Conditional Access policy design and implementation
- Break-glass account configuration to Microsoft best practice
- Least-privilege RBAC design
- PIM eligible assignment configuration
- Understanding of attack surface reduction principles

**Why it matters:**
Blocking legacy auth and requiring MFA are the two controls that prevent 
the majority of identity-based attacks. PIM eliminates standing privilege — 
meaning a compromised account has no admin rights until explicitly activated. 
These controls appear in every serious IAM job specification and every 
security framework including CIS, ISO 27001, and Cyber Essentials Plus.

---

## Phase 3 — Automation & Reporting

**Goal:** Build repeatable, auditable IAM processes that reflect real 
operational workflows.

**Joiner script (Invoke-Joiner.ps1)**
Fully automated onboarding process triggered with a single command:
- Creates user account with correct attributes
- Assigns to department group and GRP-AllStaff
- Assigns licence
- Outputs audit summary with completion timestamp

**Leaver script (Invoke-Leaver.ps1)**
Fully automated offboarding covering all critical security steps:
- Disables account immediately
- Revokes all active sessions (signs out all devices)
- Removes all group memberships
- Removes licence
- Checks and removes any directory role assignments
- Outputs full audit trail with 30-day retention notice

**Stale account detection (Get-StaleAccounts.ps1)**
Configurable report identifying dormant accounts:
- Configurable threshold (default 90 days)
- Categorises accounts as Active, Stale, or Never signed in
- Exports CSV for management review
- Includes recommended action per account

**MFA registration report (Get-MFAReport.ps1)**
Security posture report for MFA adoption:
- Queries authentication methods for every user
- Identifies specific MFA methods registered
- Risk-rates each user (HIGH/MEDIUM/LOW)
- Calculates organisation-wide MFA adoption percentage
- Exports CSV for auditor or management reporting

**Access review export (Get-AccessReview.ps1)**
Quarterly access review report across four dimensions:
- Group memberships — who is in which group
- Directory role assignments — who has admin roles
- PIM eligible assignments — who can elevate to what
- Licence assignments — who has what licence
- Exports four separate CSVs for manager certification

**Key skills demonstrated:**
- Parameterised script design
- Joiner/Mover/Leaver automation
- Audit trail generation
- CSV reporting for non-technical stakeholders
- Sign-in log and authentication method queries via Graph API

**Why it matters:**
Manual joiner/leaver processes are slow, inconsistent, and error-prone. 
A leaver whose account isn't disabled on their last day is a security 
incident waiting to happen. Automation ensures the process is followed 
completely every time, with a full audit trail — something regulators 
and auditors specifically look for.

---

## Key learning outcomes
**Technical**
- Microsoft Graph PowerShell SDK for identity lifecycle management
- Entra ID architecture — users, groups, roles, licences, policies
- Conditional Access design and implementation
- PIM configuration and the principle of zero standing privilege
- PowerShell scripting — parameterised functions, error handling, 
  CSV import/export, pipeline operations
- Git version control for script management

**Conceptual**
- Least privilege as a practical design principle, not just a theory
- The difference between authentication (who are you) and 
  authorisation (what can you do)
- Why blocking legacy auth matters — MFA bypass attack vectors
- Access review as a governance process — certify, revoke, document
- The IAM identity lifecycle — joiner, mover, leaver

---

## Scripts reference

| Script | Phase | Purpose |
|--------|-------|---------|
| Connect-Tenant.ps1 | Setup | Authenticate to Microsoft Graph |
| New-LabUsers.ps1 | 1 | Bulk user provisioning from CSV |
| New-LabGroups.ps1 | 1 | Create department security groups |
| Add-GroupMembers.ps1 | 1 | Assign users to groups |
| Set-UserLicences.ps1 | 1 | Assign P2 licences |
| Set-MFAPolicy.ps1 | 2 | Conditional Access — require MFA |
| New-BreakGlassAccounts.ps1 | 2 | Emergency access accounts |
| Set-RBACAssignments.ps1 | 2 | Least-privilege role assignments |
| Set-PIMRoles.ps1 | 2 | PIM eligible assignments |
| Invoke-Joiner.ps1 | 3 | Automated user onboarding |
| Invoke-Leaver.ps1 | 3 | Automated user offboarding |
| Get-StaleAccounts.ps1 | 3 | Stale account detection report |
| Get-MFAReport.ps1 | 3 | MFA registration status report |
| Get-AccessReview.ps1 | 3 | Quarterly access review export |

---

## Repository
github.com/OmarAngelo/azure-iam-lab