# azure-iam-lab
Practice tenant

# Azure IAM Lab

A hands-on Microsoft Entra ID and Azure IAM lab built using PowerShell 7, VS Code 
and the Microsoft Graph PowerShell SDK, covering the full identity lifecycle 
from provisioning through to governance and reporting.

Built as a self-directed project while transitioning into an IAM analyst role.

📄 **[Full project summary and documentation](docs/lab-summary.md)**

---

## What this lab covers

| Area | Topics |
|------|--------|
| Identity provisioning | Bulk user creation, group management, licence assignment |
| Security controls | Conditional Access, MFA enforcement, legacy auth blocking |
| Privileged access | RBAC least-privilege, PIM eligible assignments, break-glass |
| Automation | Joiner/Leaver scripts, parameterised workflows |
| Reporting | Stale accounts, MFA status, access review exports |

---

## Structure
azure-iam-lab/
├── scripts/
│   ├── phase1-identity/      # User provisioning, groups, licences
│   ├── phase2-security/      # CA policies, RBAC, PIM
│   └── phase3-automation/    # Joiner/Leaver, reporting scripts
├── docs/
│   └── lab-summary.md        # Full project documentation
└── README.md

---

## Tech stack
- PowerShell 7
- Microsoft Graph PowerShell SDK v2.37.0
- Microsoft Entra ID (Azure AD Premium P2)
- Microsoft 365 Developer Tenant
- Git / GitHub