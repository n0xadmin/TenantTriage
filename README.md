```                                       .    .                                           
                                    ..................                                  
                            '.. .'..'''`,,`'`^,:^`''''..... ..                          
                         ...:'^.'```^!:.   .:"'..:<:"^`''``.`'''                        
           .    ''.. .. .'.'^^:'^,I+`    ..`?!:`'  `?+"^`^^`"^`'. ....``    .           
              .',,'....',>,',,;"![:     ..`"f}>I"'.  ,}~,,,^"^::'.....^;`..             
        ......'."`...'.^",:^":>{{.     ..'^:rt]i;^''  '[{!;",,""^'.'.'^,'''.....        
       .`",I<!;iI"`^",^`^;l;,I(\'      .'`,lCn}~!:"`'  "(1I,:l:^``",^^^;iIi+!:,`.   ..  
''`"^'.   '`:<1c{<l;;I:^;_!::>Y,'   ....'^;iLu1+iI,,`'. ;u_;:::"`^:::Ii]c\~;"`    .`^`'.
 .;I^'.  ..;>l}vQJ},^"^^l?iI!c]".......'":I;>11?<l;,^'''`~UiIlI,````^_YOY)i!l..  ..'":' 
  .' ..:!`.^i:It{~i"^""^;<>l[YI`^...'`""`      "!<!I,`'"`,j|!iiI"`^^^l+{f!:<,.`II'      
    ';+l`"..'.',I"^^^:;;;;;iX_""^.`":,'          .:>I,``,`!Y_illI;,^^^,;;^'' ..`!<i`.   
   `,:,/LC\I`'..'^,,::,l>i!)("^:.^:"                "l:`"^'[ji<<!::::,"''..'!1?<?^",^   
   .`}zJzufn+^^i^``^^;I!l;!ti^,'",.                  .,:'"",/<I!iIl^^^`'`^}Uv-!il. .    
    '!?n/f(<!,:[++""!!,"^"][i"',^                      `:``!~[,,,;>>:^`:/ZJ(i:!!...     
     .'`,^`^;;I<?>->^^``':_+^.:.                         ,"'i_I``"``^I)nx/;";>i'..      
       '."l",Ill__::i,...I~,'I .         ...... .         ^i^>!....^-]<t{^":<l'..       
       .. .'^:,",":^`"l'`;"""  '     ..................'.  .l^:^  l_!l;+!;"II ..`..     
     .'.'"^'..',!!l`^''^;,,`   ^..'.......'''''......'`.    .:,,^,!-\}I",,< '``''.      
     .  ^""":l,.`^^,,'."l^'   .,''`'`'...''`'''''''^'`^'...  '";>!I<~:^"!`''^"^. .      
      . ,:,"",>;`''''."!.'.  .',`^;;:``''`````''''',`^,^'..  .`'Ii;^'^":'',^,,"'...     
      '`::,^I:.  '`. '<^.`.  ..^^"I;:^"```````````^I",;,`'' ..^''<`'`"^. "+,:""^`'.     
        '`^";;`'.'. '`I:'''  ^.`^,,",,;^````````^^:_,:I,`'. .```:l,^.  '`:<^""^. .      
       ..'`,II!I^. .^'.^^`'` '^'`^,:I;>,^^``````,;:i,,I"... ^^"",`^;`.'`:i!I,`'..       
         .`I<~{1?>:^`'. .'^"`. '''`^I:+;""`````","``^''.. .^,"`` '^"IIi-}[+~l^..        
       .^`''^,-jvj[!"`    ..^,. .'`'I^l:,^^^^``^`'`",.`. ',"''.  .`,l?\nr],"''^"'.      
         '"I>!,^;!;Il>;'. .'..`". .'^``^"^^^``'''^.''. ',^.`^. '`;~>I:l!""l<i,`.        
        ..";^^i1};. .''`,"````'.'`   "`''`'''....... .^` '.  .":"``'..,](<^^,"'  
        								      ____       __          __        
        						   ____  / __ \_  __/ /   ____ _/ /_  _____
		        				  / __ \/ / / / |/_/ /   / __ `/ __ \/ ___/
        						 / / / / /_/ />  </ /___/ /_/ / /_/ (__  ) 
        						/_/ /_/\____/_/|_/_____/\__,_/_.___/____/  
		.......................................................................
```


# TenantTriage

**Rapid evidence collection and triage for Microsoft 365 / Entra ID incident response.**

Built for MSSP and IR-firm scale. Menu-driven. Chain-of-custody aware. Integrates with [Microsoft-Extractor-Suite](https://github.com/invictus-ir/Microsoft-Extractor-Suite).

---

## What is this?

TenantTriage is a PowerShell-based incident response toolkit for investigating compromised accounts in Microsoft 365 and Entra ID (Azure AD) environments. It wraps Microsoft Graph API, Exchange Online, and optionally the Invictus IR Microsoft-Extractor-Suite into a single menu-driven interface with built-in case management, artifact hashing, and HTML reporting.

It was designed around six questions that structure every competent M365 compromise investigation:

1. **How did they get in?** — Sign-in logs, risky users, authentication anomalies
2. **What session/token did they use?** — Session correlation across workloads
3. **What persistence did they leave?** — Inbox rules, forwarding, delegates, MFA changes
4. **What data did they access?** — MailItemsAccessed, file activity
5. **What privileges/apps did they add?** — Admin roles, OAuth consent grants
6. **What other workloads did they touch?** — SharePoint, OneDrive, Teams, Azure

## Why not just use existing tools?

You should use existing tools — this toolkit integrates with them rather than replacing them. The gap it fills:

- **Microsoft-Extractor-Suite** is excellent for raw acquisition but doesn't score, correlate, or produce triage reports. TenantTriage layers case management, suspicious-pattern detection (inbox rule scoring, OAuth risk flagging, hidden rule detection), and HTML reporting on top of MES output.
- **The Entra/M365 admin portals** require clicking through dozens of blades per user. TenantTriage pulls the same data via API, scoped to your incident window, in seconds.
- **Manual PowerShell scripts** work once but don't enforce case structure, hash artifacts, or produce evidence bundles suitable for counsel or a cyber insurance carrier.

## Features

### Evidence Collection
- Entra ID sign-in logs (Interactive, NonInteractive, ServicePrincipal)
- Risky users and risk detections (Identity Protection)
- Inbox rules with **suspicion scoring** (0-10 scale based on real BEC patterns)
- **Hidden inbox rule detection** via `Get-InboxRule -IncludeHidden` (catches MAPI-set `ST_HIDDEN` rules invisible to Graph/OWA)
- Mailbox forwarding (both `ForwardingSmtpAddress` and `ForwardingAddress`)
- Mailbox delegations (FullAccess, SendAs, SendOnBehalf, Calendar)
- Authentication method / MFA changes with self-registration flagging
- Admin role assignment changes and current holder snapshots
- OAuth consent grants with high-risk scope detection and unverified publisher flagging
- Service principal inventory

### Microsoft-Extractor-Suite Integration
- Unified Audit Log via `Get-UALGraph` (battle-tested chunked paging)
- MailItemsAccessed (scoping what mail was read/synced)
- Message trace (outbound BEC / thread hijacking)
- Session correlation
- Full automated evidence collection via `Start-EvidenceCollection`
- Run any MES function ad-hoc with output imported into the case

### Case Management
- Timestamped case folder structure with category-based organization
- SHA-256 hashing of every artifact with tamper-evident manifest
- Streaming action log (JSONL — survives crashes)
- Zip case bundles with sidecar hashes
- Analyst attribution (configurable at case, session, or report level)

### Reporting
- Single-page HTML triage report with executive summary
- Color-coded finding severity (critical/warning/clear)
- Organized by IR phase with data tables, stats, and top-N breakdowns
- Print-friendly / PDF-convertible
- Includes full artifact manifest with SHA-256 hashes

### Auth & Resilience
- Three auth modes: Interactive, Device Code, App-Only (certificate)
- Automatic WAM broker fallback (handles the MSAL DLL conflicts common in 2025-2026 M365 PowerShell)
- Post-connection validation (catches broken tokens before the triage run starts)
- Clean disconnect-before-reconnect (prevents corrupted auth state)
- Graph API wrapper with proper OData paging, exponential backoff on 429/503, and immediate failure on definitive errors (403/404)

---

## Requirements

- **PowerShell 7.2+** (7.4+ recommended)
- **Microsoft.Graph.Authentication** module
- **ExchangeOnlineManagement** module (optional — required for EXO-dependent collectors)
- **Microsoft-Extractor-Suite** module (optional — required for MES integration features)
- Appropriate permissions in the target tenant (see [Permissions](#permissions))

## Installation

```powershell
# Clone the repository
git clone https://github.com/YOUR-ORG/TenantTriage.git
cd TenantTriage

# Install dependencies
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# Optional: Install Microsoft-Extractor-Suite for UAL, MailItemsAccessed, etc.
Install-Module Microsoft-Extractor-Suite -Scope CurrentUser

# Verify
.\tests\Invoke-SmokeTest.ps1
```

No module registration required. No `Import-Module`. Just run the script.

---

## Quick Start

### Interactive mode (recommended)

```powershell
.\TenantTriage.ps1
```

The menu walks you through everything:

```
  ┌─────────────────────────────────────────────────────┐
  │              CASE & CONNECTION                      │
  ├─────────────────────────────────────────────────────┤
  │  1.  New Case                                      │
  │  2.  Connect to Tenant                             │
  │  3.  Show Current Context                          │
  ├─────────────────────────────────────────────────────┤
  │              PRE-FLIGHT                             │
  ├─────────────────────────────────────────────────────┤
  │  4.  Audit Readiness Check                         │
  ├─────────────────────────────────────────────────────┤
  │       PHASE 1: How did they get in?                │
  ├─────────────────────────────────────────────────────┤
  │  5.  Sign-In Logs (single user)                    │
  │  6.  Sign-In Logs (all users)                      │
  │  7.  Risky Users & Detections                      │
  ├─────────────────────────────────────────────────────┤
  │       PHASE 3: What persistence did they leave?    │
  ├─────────────────────────────────────────────────────┤
  │  8.  Inbox Rules (single user)                     │
  │  9.  Inbox Rules (all users, tenant-wide)          │
  │  10. Inbox Rules + Hidden Rules (single user)      │
  │  11. Inbox Rules + Hidden Rules (ALL users)        │
  │  12. Mailbox Forwarding (single user)              │
  │  13. Mailbox Forwarding (all users)                │
  │  14. Mailbox Delegations (single user)             │
  │  15. Mailbox Delegations (all users)               │
  │  16. Auth Method / MFA Changes (single user)       │
  │  17. Auth Method / MFA Changes (all users)         │
  ├─────────────────────────────────────────────────────┤
  │       PHASE 5: What privileges/apps did they add?  │
  ├─────────────────────────────────────────────────────┤
  │  18. Admin Role Changes + Current Holders          │
  │  19. OAuth Grants & Service Principals             │
  │  20. OAuth Grants (single user)                    │
  ├─────────────────────────────────────────────────────┤
  │              ORCHESTRATORS                         │
  ├─────────────────────────────────────────────────────┤
  │  21. FULL TRIAGE (single user - all phases)        │
  │  22. FULL TRIAGE (tenant-wide - all phases)        │
  ├─────────────────────────────────────────────────────┤
  │       EXTRACTOR SUITE (MES) INTEGRATION            │
  ├─────────────────────────────────────────────────────┤
  │  23. MES Full Evidence Collection (auto-all)       │
  │  24. MES Unified Audit Log (Get-UALGraph)          │
  │  25. MES MailItemsAccessed (what was read)         │
  │  26. MES Message Trace (mail flow)                 │
  │  27. MES Session Correlation                       │
  │  28. MES Run Any Collector                         │
  ├─────────────────────────────────────────────────────┤
  │              REPORTING & CASE MGMT                 │
  ├─────────────────────────────────────────────────────┤
  │  29. Generate Triage Summary Report (HTML)         │
  │  30. Finalize Case (manifest + zip)                │
  │  31. Disconnect & Exit                             │
  └─────────────────────────────────────────────────────┘
```

### Non-interactive mode (scripted / automated)

```powershell
# Quick single-user triage
.\TenantTriage.ps1 -QuickTriage -TenantId 'contoso.onmicrosoft.com' -FocusUpn 'cfo@contoso.com'

# Full tenant-wide sweep
.\TenantTriage.ps1 -FullTriage -TenantId 'contoso.onmicrosoft.com' `
    -FocusUpn 'cfo@contoso.com','ap@contoso.com' -Days 30
```

### Standalone collector mode (ad-hoc)

```powershell
# Load shared libraries
. .\lib\Initialize-TT.ps1

# Load specific collectors
. .\collectors\Get-TTSignInLogs.ps1
. .\collectors\Get-TTInboxRules.ps1

# Create case and connect
New-TTCase -ClientName 'Contoso' -IncidentRef 'IR-2026-0417'
Connect-TTTenant -AuthMode DeviceCode -TenantId 'contoso.onmicrosoft.com'

# Run what you need
Get-TTSignInLogs -Upn 'cfo@contoso.com' -Days 14
Get-TTInboxRules -UserUpn 'cfo@contoso.com' -IncludeHiddenRules

# Finalize
Complete-TTCase -Zip
```

---

## Typical IR Workflow

### Scenario: CFO account suspected compromised via AiTM phishing

```
Option 1  → New Case (client name, incident ref, analyst)
Option 2  → Connect (tenant ID, Device Code auth, EXO enabled)
Option 4  → Audit Readiness Check (verify logging is actually on)
Option 5  → Sign-In Logs for CFO (look for anomalous IPs, apps, user agents)
Option 10 → Inbox Rules + Hidden Rules for CFO (catch MAPI-set persistence)
Option 12 → Mailbox Forwarding for CFO (check for exfil via forwarding)
Option 14 → Mailbox Delegations for CFO (check for FullAccess/SendAs grants)
Option 16 → Auth Method Changes for CFO (did attacker add their own MFA?)
Option 20 → OAuth Grants for CFO (check for illicit consent grants)
Option 24 → MES Unified Audit Log for CFO (what did the session actually do?)
Option 25 → MES MailItemsAccessed for CFO (what mail was read/synced?)
Option 18 → Admin Role Changes (did they escalate privileges?)
Option 29 → Generate Triage Report (HTML — hand to counsel or carrier)
Option 30 → Finalize Case (manifest + zip — chain-of-custody bundle)
```

Total time: 10-20 minutes for a single-user triage. The report opens in your browser automatically.

---

## Project Structure

```
TenantTriage/
├── TenantTriage.ps1                     ← Run this. Launcher + menu.
├── lib/                                 ← Shared plumbing
│   ├── Initialize-TT.ps1               ← Single entry point for all helpers
│   ├── Write-TTLog.ps1                  ← Unified logging (console + JSONL)
│   ├── Invoke-TTGraphRequest.ps1        ← Graph wrapper (paging + backoff)
│   ├── Save-TTArtifact.ps1              ← Artifact writer (JSONL/CSV + SHA-256)
│   ├── Assert-TTDependency.ps1          ← Runtime dependency checker
│   ├── Case-Management.ps1             ← New-TTCase, Complete-TTCase
│   └── Connect-TTTenant.ps1            ← Multi-modal auth with WAM fallback
├── collectors/                          ← One script per collector
│   ├── Get-TTSignInLogs.ps1
│   ├── Get-TTInboxRules.ps1
│   ├── Get-TTMailboxForwarding.ps1
│   ├── Get-TTMailboxDelegates.ps1
│   ├── Get-TTOAuthGrants.ps1
│   ├── Get-TTAuthMethodChanges.ps1
│   ├── Get-TTAdminRoleChanges.ps1
│   ├── Get-TTRiskyUsers.ps1
│   ├── Test-TTAuditReadiness.ps1
│   ├── Invoke-TTFullTriage.ps1          ← Runs all collectors in IR-phase order
│   ├── Invoke-MESIntegration.ps1        ← Microsoft-Extractor-Suite bridge
│   └── New-TTTriageReport.ps1           ← HTML report generator
├── tests/
│   └── Invoke-SmokeTest.ps1             ← Offline validation, no deps needed
└── README.md
```

Every collector is independently runnable. Each starts with a two-line header that auto-loads the shared libraries if not already loaded, so you can dot-source any single collector without the launcher.

---

## Case Folder Layout

```
D:\Cases\20260417-143022-Contoso-IR-2026-0417\
├── _meta/
│   ├── case.json                  Case metadata (analyst, tenant, timestamps)
│   ├── action.log.jsonl           Streaming audit trail of every action
│   ├── manifest.json              Artifact index with SHA-256 hashes
│   └── manifest.sha256            Hash of the manifest itself
├── Identity/
│   ├── EntraSignInLogs-Interactive-*.{jsonl,csv}
│   ├── EntraSignInLogs-NonInteractive-*
│   ├── EntraSignInLogs-ServicePrincipal-*
│   ├── RiskDetections-*
│   ├── AuthMethodChanges-*
│   ├── AuthMethodChanges-SelfRegistered-*
│   ├── AdminRoleChanges-*
│   └── AdminRoles-CurrentHolders-*
├── Mail/
│   ├── InboxRules-All-*
│   ├── InboxRules-Suspicious-*        (score >= 3 only)
│   ├── MailboxForwarding-*
│   ├── MailboxForwarding-External-*
│   ├── MailboxPermissions-FullAccess-*
│   ├── MailboxPermissions-SendAs-*
│   ├── MailboxPermissions-SendOnBehalf-*
│   └── MES-UAL-*, MES-MessageTrace-*  (if MES was used)
├── Apps/
│   ├── OAuthGrants-All-*
│   ├── OAuthGrants-Risky-*
│   ├── OAuthGrants-UnverifiedExternal-*
│   └── ServicePrincipals-Inventory-*
├── Config/
│   ├── AuditReadiness-*
│   └── TriageRunSummary-*
├── Devices/
│   └── MES-Devices-*                  (if MES was used)
├── _mes_raw/                          (raw MES output, pre-import)
└── TriageReport-*.html                The deliverable
```

---

## Inbox Rule Suspicion Scoring

Every inbox rule is scored against patterns observed in real BEC investigations:

| Signal | Score | Why |
|--------|-------|-----|
| External forward target | +5 | Data exfiltration via rule-based forwarding |
| Move to RSS / Conversation History / Junk / Notes | +4 | Classic hiding folders — attacker hides evidence |
| BEC keyword in conditions (invoice, wire, payment, bank, ACH, routing) | +4 | Financial keyword interception |
| Empty or punctuation-only rule name (`.`, `-`, space) | +3 | BEC actors rarely name their rules properly |
| Delete action | +3 | Destroying evidence of the compromise |
| Mark as read | +1 | Silencing inbox notifications |
| Hidden rule (EXO-only, not visible in Graph/OWA) | +10 | Definitive indicator — MAPI-set `ST_HIDDEN` persistence |

Rules scoring >= 3 are written to a separate `InboxRules-Suspicious` artifact for fast triage.

---

## OAuth Risk Scoring

OAuth consent grants are checked against:

- **High-risk scopes**: `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `offline_access`, `full_access_as_user`
- **Unverified publishers**: Apps without a verified publisher that are owned by a tenant other than the one being investigated
- **Recent grants**: When `-RecentDays` is specified, only grants within that window are returned (correlates with the incident timeline)

Three artifacts produced: all grants, risky-scoped only, and unverified external only.

---

## Permissions

### Delegated (Interactive / Device Code)

The analyst account needs these Microsoft Graph scopes:

- `AuditLog.Read.All`
- `Directory.Read.All`
- `SecurityEvents.Read.All`
- `IdentityRiskEvent.Read.All`
- `IdentityRiskyUser.Read.All`
- `Policy.Read.All`
- `Application.Read.All`
- `User.Read.All`
- `MailboxSettings.Read`

For Exchange Online, the analyst needs at minimum:

- **Global Reader** role (pragmatic minimum), or
- **View-Only Audit Logs** + **View-Only Recipients** (tighter least-privilege)

### Application (App-Only / Certificate)

For retainer clients with a pre-staged multi-tenant app registration, configure the same scopes as application permissions and grant admin consent.

---

## Microsoft-Extractor-Suite Integration

TenantTriage integrates with [Microsoft-Extractor-Suite](https://github.com/invictus-ir/Microsoft-Extractor-Suite) by Invictus IR for capabilities where MES's battle-tested implementations are stronger:

| Capability | Handled by | Why |
|---|---|---|
| Unified Audit Log (chunked paging, 50k handling) | MES `Get-UALGraph` | Years of production-tested edge case handling |
| MailItemsAccessed (Bind vs Sync scoping) | MES `Get-MailItemsAccessed` | Complex AuditData parsing already solved |
| Message trace (mail flow) | MES `Get-MessageTraceLog` | Handles the 10-day / 90-day split |
| Session correlation | MES `Get-Sessions` | Session-to-mailbox activity mapping |
| Full auto-collection | MES `Start-EvidenceCollection` | One command collects everything |
| Case structure + hashing | TenantTriage | MES doesn't do case management |
| Inbox rule scoring | TenantTriage | MES collects rules but doesn't score them |
| OAuth risk flagging | TenantTriage | MES collects grants but doesn't risk-score |
| Hidden rule detection | TenantTriage | Graph + EXO diff approach |
| HTML triage report | TenantTriage | MES produces raw data, not reports |
| WAM-resilient auth | TenantTriage | Handles the 2025-2026 MSAL broker crashes |

MES output is copied into the TenantTriage case folder, SHA-256 hashed, and included in the manifest and triage report. One unified evidence bundle.

MES is **optional**. All native TenantTriage collectors work without it. The MES menu section auto-detects installation and grays out options if MES is not present.

```powershell
# Install MES (optional)
Install-Module Microsoft-Extractor-Suite -Scope CurrentUser
```

---

## Testing

```powershell
# Offline smoke test — validates plumbing, no network or dependencies needed
.\tests\Invoke-SmokeTest.ps1
```

The smoke test validates: file structure, library loading, all functions available, case creation, logging, artifact hashing, manifest integrity, and zip bundling. Run it after every edit.

---

## Known Issues & Troubleshooting

### MSAL / WAM Broker Errors

If you see errors mentioning `RuntimeBroker`, `IMsalSFHttpClientFactory`, or `Object reference not set to an instance of an object` during authentication, this is a known MSAL assembly conflict between Microsoft Graph, Exchange Online, and PnP.PowerShell modules. TenantTriage handles this automatically by falling back to Device Code auth when WAM fails, but if you want to fix the root cause:

```powershell
# Close ALL PowerShell sessions, then in a fresh one:
Uninstall-Module PnP.PowerShell -AllVersions -Force -ErrorAction SilentlyContinue
Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

### 403 Forbidden on Risky Users / Service Principals

Requires Entra ID P2 or Workload Identity Premium licensing. The tool warns and continues — non-P2 tenants still get full value from all other collectors.

### Inbox Rule Errors on Some Mailboxes

403 (Forbidden) on shared/resource mailboxes and 404 (NotFound) on group mailboxes is expected. The tool logs these to `InboxRules-Errors` for review and continues collecting from accessible mailboxes.

### Exchange Online Collectors Skipped

Ensure you answered **N** to "Skip Exchange Online?" during connection, and that `ExchangeOnlineManagement` is installed. Check option 3 (Show Context) to verify `EXO Connected: True`.

---

## Design Principles

1. **Read-only.** This tool collects evidence. It does not modify, disable, or remediate anything in the target tenant. Response actions belong in a separate tool with a dry-run default.
2. **Every artifact hashed.** SHA-256 manifest integrity is non-negotiable. The manifest itself is hashed.
3. **JSONL first, CSV for consumption.** JSONL preserves nested objects and streams cleanly. CSV flattens for analyst-friendly import into Timeline Explorer or Excel.
4. **Paging is not optional.** `Invoke-TTGraphRequest -All` is the default. No silent truncation at 1000 rows.
5. **Fail loud, log everything.** Errors and warnings are captured in the streaming action log. One collector failing doesn't abort the run.
6. **IR-phase discipline.** Every collector answers one of the six investigation questions.
7. **Dependencies are optional.** The tool loads with zero dependencies. Checks happen at runtime when a dependency is actually needed. The smoke test runs on a bare PowerShell install.

---

## Acknowledgments

- **[Microsoft-Extractor-Suite](https://github.com/invictus-ir/Microsoft-Extractor-Suite)** by Invictus IR (Joey Rentenaar, Korstiaan Stam) — the community standard for M365 evidence acquisition
- **[Microsoft-Analyzer-Suite](https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite)** by LETHAL-FORENSICS — analysis companion for MES output
- **[Microsoft Incident Response](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/welcome-to-the-microsoft-incident-response-ninja-hub/4243594)** — their one-page guides and published TTPs inform the artifact checklist
- The broader DFIR community whose published BEC investigation patterns and KQL queries shaped the detection logic

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Issues, feature requests, and pull requests are welcome. If adding a new collector, follow the existing pattern: one function per file in `collectors/`, auto-load header at the top, answer one of the six IR questions, and save output via `Save-TTArtifact`.
