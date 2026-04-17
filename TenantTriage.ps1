<#
.SYNOPSIS
    TenantTriage - Interactive M365/Entra incident response launcher.

.DESCRIPTION
    Run this script. It handles everything:
      - Case creation
      - Tenant authentication (Interactive, DeviceCode, or AppOnly)
      - Menu-driven collector selection
      - Case finalization and evidence bundling

    Each collector can also be run standalone by dot-sourcing it directly.

.EXAMPLE
    # Interactive menu mode (default)
    .\TenantTriage.ps1

.EXAMPLE
    # Quick single-user triage (non-interactive)
    .\TenantTriage.ps1 -QuickTriage -TenantId 'contoso.onmicrosoft.com' -FocusUpn 'cfo@contoso.com'

.EXAMPLE
    # Full sweep (non-interactive)
    .\TenantTriage.ps1 -FullTriage -TenantId 'contoso.onmicrosoft.com' -FocusUpn 'cfo@contoso.com','ap@contoso.com'
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    # Non-interactive: run full triage and exit
    [Parameter(ParameterSetName = 'FullTriage')]
    [switch]$FullTriage,

    # Non-interactive: quick single-user triage
    [Parameter(ParameterSetName = 'QuickTriage')]
    [switch]$QuickTriage,

    [Parameter(ParameterSetName = 'FullTriage', Mandatory)]
    [Parameter(ParameterSetName = 'QuickTriage', Mandatory)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'FullTriage')]
    [Parameter(ParameterSetName = 'QuickTriage')]
    [string[]]$FocusUpn,

    [Parameter(ParameterSetName = 'FullTriage')]
    [Parameter(ParameterSetName = 'QuickTriage')]
    [ValidateSet('Interactive','DeviceCode','AppOnly')]
    [string]$AuthMode = 'DeviceCode',

    [Parameter(ParameterSetName = 'FullTriage')]
    [Parameter(ParameterSetName = 'QuickTriage')]
    [int]$Days = 30,

    [Parameter(ParameterSetName = 'FullTriage')]
    [Parameter(ParameterSetName = 'QuickTriage')]
    [string]$CaseRoot = (Join-Path $env:USERPROFILE 'TenantTriage-Cases'),

    [Parameter(ParameterSetName = 'FullTriage')]
    [Parameter(ParameterSetName = 'QuickTriage')]
    [string]$ClientName,

    [Parameter(ParameterSetName = 'FullTriage')]
    [Parameter(ParameterSetName = 'QuickTriage')]
    [string]$IncidentRef
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------
# Load shared libraries
# ---------------------------------------------------------------
. (Join-Path $PSScriptRoot 'lib\Initialize-TT.ps1')

# Load all collectors
Get-ChildItem -Path (Join-Path $PSScriptRoot 'collectors') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

# ---------------------------------------------------------------
# Banner
# ---------------------------------------------------------------
function Show-Banner {
    $banner = @"

  _____ _____   _   _    _    _____ ____  ___    _    ____ _____ 
 |_   _|_   _| | | | |  / \  / ____|  _ \|_ _|  / \  / ___| ____|
   | |   | |   | |_| | / _ \| |  __| |_) || |  / _ \| |  _|  _|  
   | |   | |   |  _  |/ ___ \ | |_ |  _ < | | / ___ \ |_| | |___ 
   |_|   |_|   |_| |_/_/   \_\____|_| \_\___/_/   \_\____|_____|
                                                          v0.3.0
  M365 / Entra Incident Response Toolkit
  ─────────────────────────────────────────────────────────────────
"@
    Write-Host $banner -ForegroundColor Cyan
}

# ---------------------------------------------------------------
# Interactive menu system
# ---------------------------------------------------------------
function Show-MainMenu {
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │              CASE & CONNECTION                      │" -ForegroundColor DarkCyan
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │  1.  New Case                                      │" -ForegroundColor White
    Write-Host "  │  2.  Connect to Tenant                             │" -ForegroundColor White
    Write-Host "  │  3.  Show Current Context                          │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │              PRE-FLIGHT                             │" -ForegroundColor DarkCyan
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │  4.  Audit Readiness Check                         │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │       PHASE 1: How did they get in?                │" -ForegroundColor Yellow
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │  5.  Sign-In Logs (single user)                    │" -ForegroundColor White
    Write-Host "  │  6.  Sign-In Logs (all users)                      │" -ForegroundColor White
    Write-Host "  │  7.  Risky Users & Detections                      │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │       PHASE 3: What persistence did they leave?    │" -ForegroundColor Yellow
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │  8.  Inbox Rules (single user)                     │" -ForegroundColor White
    Write-Host "  │  9.  Inbox Rules (all users, tenant-wide)          │" -ForegroundColor White
    Write-Host "  │  10. Inbox Rules + Hidden Rules (single user)      │" -ForegroundColor White
    Write-Host "  │  11. Inbox Rules + Hidden Rules (ALL users)        │" -ForegroundColor White
    Write-Host "  │  12. Mailbox Forwarding (single user)              │" -ForegroundColor White
    Write-Host "  │  13. Mailbox Forwarding (all users)                │" -ForegroundColor White
    Write-Host "  │  14. Mailbox Delegations (single user)             │" -ForegroundColor White
    Write-Host "  │  15. Mailbox Delegations (all users)               │" -ForegroundColor White
    Write-Host "  │  16. Auth Method / MFA Changes (single user)       │" -ForegroundColor White
    Write-Host "  │  17. Auth Method / MFA Changes (all users)         │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │       PHASE 5: What privileges/apps did they add?  │" -ForegroundColor Yellow
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │  18. Admin Role Changes + Current Holders          │" -ForegroundColor White
    Write-Host "  │  19. OAuth Grants & Service Principals             │" -ForegroundColor White
    Write-Host "  │  20. OAuth Grants (single user)                    │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │              ORCHESTRATORS                         │" -ForegroundColor DarkCyan
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │  21. FULL TRIAGE (single user - all phases)        │" -ForegroundColor Green
    Write-Host "  │  22. FULL TRIAGE (tenant-wide - all phases)        │" -ForegroundColor Green
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │       EXTRACTOR SUITE (MES) INTEGRATION           │" -ForegroundColor DarkCyan
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan

    # Check MES availability and show status
    $mesStatus = Test-MESAvailable
    if ($mesStatus.Available) {
        Write-Host "  │  Status: INSTALLED ($($mesStatus.Version))                  │" -ForegroundColor Green
    } else {
        Write-Host "  │  Status: NOT INSTALLED                             │" -ForegroundColor DarkGray
    }

    Write-Host "  │  23. MES Full Evidence Collection (auto-all)       │" -ForegroundColor $(if($mesStatus.Available){'White'}else{'DarkGray'})
    Write-Host "  │  24. MES Unified Audit Log (Get-UALGraph)          │" -ForegroundColor $(if($mesStatus.Available){'White'}else{'DarkGray'})
    Write-Host "  │  25. MES MailItemsAccessed (what was read)         │" -ForegroundColor $(if($mesStatus.Available){'White'}else{'DarkGray'})
    Write-Host "  │  26. MES Message Trace (mail flow)                 │" -ForegroundColor $(if($mesStatus.Available){'White'}else{'DarkGray'})
    Write-Host "  │  27. MES Session Correlation                       │" -ForegroundColor $(if($mesStatus.Available){'White'}else{'DarkGray'})
    Write-Host "  │  28. MES Run Any Collector                         │" -ForegroundColor $(if($mesStatus.Available){'White'}else{'DarkGray'})
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │              REPORTING & CASE MGMT                 │" -ForegroundColor DarkCyan
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
    Write-Host "  │  29. Generate Triage Summary Report (HTML)         │" -ForegroundColor Magenta
    Write-Host "  │  30. Finalize Case (manifest + zip)                │" -ForegroundColor White
    Write-Host "  │  31. Disconnect & Exit                             │" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""
}

function Read-UserUpn {
    param([string]$Prompt = 'Enter UPN (e.g. user@contoso.com)')
    $upn = Read-Host "  $Prompt"
    if ([string]::IsNullOrWhiteSpace($upn)) { throw "UPN cannot be empty." }
    return $upn.Trim()
}

function Read-Days {
    param([int]$Default = 30)
    $input_val = Read-Host "  Lookback days [$Default]"
    if ([string]::IsNullOrWhiteSpace($input_val)) { return $Default }
    return [int]$input_val
}

function Invoke-MenuChoice {
    param([string]$Choice)

    switch ($Choice) {
        '1' {
            $client   = Read-Host '  Client name'
            $incident = Read-Host '  Incident reference (e.g. IR-2026-0417)'
            $analyst  = Read-Host "  Analyst name/email [$($env:USERNAME)]"
            if ([string]::IsNullOrWhiteSpace($analyst)) { $analyst = $env:USERNAME }
            $root     = Read-Host "  Case root folder [$($env:USERPROFILE)\TenantTriage-Cases]"
            if ([string]::IsNullOrWhiteSpace($root)) { $root = Join-Path $env:USERPROFILE 'TenantTriage-Cases' }
            New-TTCase -ClientName $client -IncidentRef $incident -Root $root -AnalystName $analyst
        }
        '2' {
            if (-not $script:TTContext.CaseId) { Write-Host '  [!] Create a case first (option 1).' -ForegroundColor Yellow; return }
            $tenant = Read-Host '  Tenant ID (e.g. contoso.onmicrosoft.com or GUID)'
            Write-Host '  Auth modes: [1] Interactive  [2] DeviceCode  [3] AppOnly'
            $authChoice = Read-Host '  Select auth mode [2]'
            $mode = switch ($authChoice) {
                '1' { 'Interactive' }
                '3' { 'AppOnly' }
                default { 'DeviceCode' }
            }
            $connectParams = @{ AuthMode = $mode; TenantId = $tenant }
            if ($mode -eq 'AppOnly') {
                $connectParams.ClientId = Read-Host '  App (Client) ID'
                $connectParams.CertificateThumbprint = Read-Host '  Certificate thumbprint'
            }
            $skipExo = Read-Host '  Skip Exchange Online? (y/N)'
            if ($skipExo -match '^[yY]') { $connectParams.SkipExchangeOnline = $true }
            Connect-TTTenant @connectParams
        }
        '3' {
            $ctx = Get-TTCaseContext
            Write-Host ""
            Write-Host "  Case ID:         $($ctx.CaseId)"         -ForegroundColor Cyan
            Write-Host "  Case Path:       $($ctx.CasePath)"       -ForegroundColor Cyan
            Write-Host "  Tenant ID:       $($ctx.TenantId)"       -ForegroundColor Cyan
            Write-Host "  Tenant Domain:   $($ctx.TenantDomain)"   -ForegroundColor Cyan
            Write-Host "  Analyst:         $($ctx.AnalystUpn)"     -ForegroundColor Cyan
            Write-Host "  Auth Method:     $($ctx.AuthMethod)"     -ForegroundColor Cyan
            Write-Host "  Graph Connected: $($ctx.GraphConnected)" -ForegroundColor $(if ($ctx.GraphConnected) {'Green'} else {'Red'})
            Write-Host "  EXO Connected:   $($ctx.ExoConnected)"   -ForegroundColor $(if ($ctx.ExoConnected) {'Green'} else {'Red'})
            Write-Host "  Artifacts:       $($ctx.ArtifactManifest.Count)" -ForegroundColor Cyan
            Write-Host ""
            $newAnalyst = Read-Host "  Change analyst? (enter new name/email, or press Enter to keep)"
            if (-not [string]::IsNullOrWhiteSpace($newAnalyst)) {
                $script:TTContext.AnalystUpn = $newAnalyst.Trim()
                Write-Host "  Analyst updated to: $($script:TTContext.AnalystUpn)" -ForegroundColor Green
            }
        }
        '4'  { Test-TTAuditReadiness | Format-Table Check, Status, Detail -AutoSize -Wrap }

        # Phase 1: How did they get in?
        '5'  { $u = Read-UserUpn; $d = Read-Days; Get-TTSignInLogs -Upn $u -Days $d | Format-Table -AutoSize }
        '6'  { $d = Read-Days; Get-TTSignInLogs -Days $d | Format-Table -AutoSize }
        '7'  { $d = Read-Days; Get-TTRiskyUsers -Days $d }

        # Phase 3: Persistence
        '8'  { $u = Read-UserUpn; Get-TTInboxRules -UserUpn $u }
        '9'  { Write-Host '  [!] Tenant-wide sweep — may take several minutes on large tenants.' -ForegroundColor Yellow; Get-TTInboxRules }
        '10' {
            $u = Read-UserUpn
            if (-not $script:TTContext.ExoConnected) {
                Write-Host '  [!] Hidden rule scan requires Exchange Online connection.' -ForegroundColor Yellow
            }
            Get-TTInboxRules -UserUpn $u -IncludeHiddenRules
        }
        '11' {
            Write-Host '  [!] Tenant-wide hidden rule sweep — this scans EVERY mailbox via both' -ForegroundColor Yellow
            Write-Host '      Graph AND EXO Get-InboxRule -IncludeHidden. May take a long time.' -ForegroundColor Yellow
            if (-not $script:TTContext.ExoConnected) {
                Write-Host '  [!] Hidden rule scan requires Exchange Online connection.' -ForegroundColor Yellow
                return
            }
            $confirm = Read-Host '  Proceed? (y/N)'
            if ($confirm -match '^[yY]') {
                Get-TTInboxRules -IncludeHiddenRules
            }
        }
        '12' { $u = Read-UserUpn; Get-TTMailboxForwarding -UserUpn $u }
        '13' { Get-TTMailboxForwarding }
        '14' { $u = Read-UserUpn; Get-TTMailboxDelegates -UserUpn $u }
        '15' { Write-Host '  [!] Tenant-wide sweep — may take several minutes.' -ForegroundColor Yellow; Get-TTMailboxDelegates }
        '16' { $u = Read-UserUpn; $d = Read-Days; Get-TTAuthMethodChanges -UserUpn $u -Days $d }
        '17' { $d = Read-Days; Get-TTAuthMethodChanges -Days $d }

        # Phase 5: Privileges/Apps
        '18' { $d = Read-Days; Get-TTAdminRoleChanges -Days $d }
        '19' { Get-TTOAuthGrants }
        '20' { $u = Read-UserUpn; Get-TTOAuthGrants -UserUpn $u }

        # Orchestrators
        '21' {
            $u = Read-UserUpn
            $d = Read-Days -Default 14
            $hidden = Read-Host '  Include hidden rule scan? (y/N)'
            $p = @{ FocusUpn = @($u); Days = $d; SkipTenantWide = $true }
            if ($hidden -match '^[yY]') { $p.IncludeHiddenRules = $true }
            Invoke-TTFullTriage @p
        }
        '22' {
            $u = Read-Host '  Focus UPN(s), comma-separated (or blank for none)'
            $d = Read-Days
            $p = @{ Days = $d }
            if (-not [string]::IsNullOrWhiteSpace($u)) {
                $p.FocusUpn = $u -split ',' | ForEach-Object { $_.Trim() }
            }
            Invoke-TTFullTriage @p
        }

        # Reporting & case management
        '23' {
            $mes = Test-MESAvailable
            if (-not $mes.Available) { Write-Host "  [!] $($mes.Message)" -ForegroundColor Yellow; return }
            $d = Read-Days
            Write-Host '  [!] Running MES Start-EvidenceCollection. This collects everything' -ForegroundColor Yellow
            Write-Host '      MES supports — UAL, sign-ins, audit logs, MFA, OAuth, devices,' -ForegroundColor Yellow
            Write-Host '      mailbox rules, transport rules, and more. May take 10-30 minutes.' -ForegroundColor Yellow
            $confirm = Read-Host '  Proceed? (y/N)'
            if ($confirm -match '^[yY]') { Invoke-MESEvidenceCollection -Days $d }
        }
        '24' {
            $mes = Test-MESAvailable
            if (-not $mes.Available) { Write-Host "  [!] $($mes.Message)" -ForegroundColor Yellow; return }
            $name = Read-Host '  Search name (label for this scan)'
            $u = Read-Host '  User UPN filter (blank for all)'
            $d = Read-Days
            $p = @{ SearchName = $name; Days = $d }
            if (-not [string]::IsNullOrWhiteSpace($u)) { $p.UserIds = @($u.Trim()) }
            $svc = Read-Host '  Service filter (Exchange/SharePoint/AzureActiveDirectory/blank for all)'
            if (-not [string]::IsNullOrWhiteSpace($svc)) { $p.Service = $svc.Trim() }
            Invoke-MESUALCollection @p
        }
        '25' {
            $mes = Test-MESAvailable
            if (-not $mes.Available) { Write-Host "  [!] $($mes.Message)" -ForegroundColor Yellow; return }
            $u = Read-UserUpn
            $d = Read-Days -Default 14
            Invoke-MESMailItemsAccessed -UserIds $u -Days $d
        }
        '26' {
            $mes = Test-MESAvailable
            if (-not $mes.Available) { Write-Host "  [!] $($mes.Message)" -ForegroundColor Yellow; return }
            $u = Read-UserUpn
            $d = Read-Days -Default 10
            Invoke-MESMessageTrace -UserIds $u -Days $d
        }
        '27' {
            $mes = Test-MESAvailable
            if (-not $mes.Available) { Write-Host "  [!] $($mes.Message)" -ForegroundColor Yellow; return }
            $u = Read-UserUpn
            $d = Read-Days
            Invoke-MESSessions -UserIds $u -Days $d
        }
        '28' {
            $mes = Test-MESAvailable
            if (-not $mes.Available) { Write-Host "  [!] $($mes.Message)" -ForegroundColor Yellow; return }
            Write-Host '  Available MES functions:' -ForegroundColor Cyan
            Write-Host '    Get-UAL, Get-UALGraph, Get-UALStatistics' -ForegroundColor Gray
            Write-Host '    Get-MailboxRules, Get-TransportRules' -ForegroundColor Gray
            Write-Host '    Get-MessageTraceLog, Get-MailItemsAccessed' -ForegroundColor Gray
            Write-Host '    Get-MFA, Get-MailboxAuditStatus, Get-MailboxPermissions' -ForegroundColor Gray
            Write-Host '    Get-OAuthPermissionsGraph, Get-Devices' -ForegroundColor Gray
            Write-Host '    Get-GraphEntraSignInLogs, Get-GraphEntraAuditLogs' -ForegroundColor Gray
            Write-Host '    Get-RiskyUsers, Get-RiskyDetections' -ForegroundColor Gray
            Write-Host '    Get-Sessions, Get-MessageIDs' -ForegroundColor Gray
            Write-Host '    Get-ConditionalAccessPolicies, Get-Users, Get-AdminUsers' -ForegroundColor Gray
            Write-Host '    Get-Groups, Get-GroupMembers, Get-Licenses' -ForegroundColor Gray
            $fn = Read-Host '  Function name'
            if ([string]::IsNullOrWhiteSpace($fn)) { return }
            $cat = Read-Host '  Category (Identity/Mail/Apps/Config/Devices) [Mail]'
            if ([string]::IsNullOrWhiteSpace($cat)) { $cat = 'Mail' }
            Invoke-MESCollector -Function $fn.Trim() -Category $cat -ArtifactName "MES-$($fn.Trim())"
        }

        # Reporting & case management
        '29' {
            $currentAnalyst = $script:TTContext.AnalystUpn
            $analyst = Read-Host "  Analyst name/email [$currentAnalyst]"
            $customTitle = Read-Host '  Report title [Incident Response Triage Report]'
            $p = @{}
            if (-not [string]::IsNullOrWhiteSpace($analyst)) { $p.AnalystName = $analyst.Trim() }
            if (-not [string]::IsNullOrWhiteSpace($customTitle)) { $p.Title = $customTitle }
            New-TTTriageReport @p
        }
        '30' {
            $doZip = Read-Host '  Create zip bundle? (Y/n)'
            $p = @{}
            if ($doZip -notmatch '^[nN]') { $p.Zip = $true }
            Complete-TTCase @p -KeepConnection
        }
        '31' {
            if ($script:TTContext.CaseId) {
                $save = Read-Host '  Active case detected. Finalize first? (Y/n)'
                if ($save -notmatch '^[nN]') {
                    Complete-TTCase -Zip
                }
            }
            Disconnect-TTTenant
            Write-Host "`n  Disconnected. Stay safe out there." -ForegroundColor Green
            return 'EXIT'
        }

        default { Write-Host "  [!] Invalid option: $Choice" -ForegroundColor Yellow }
    }
}

# ---------------------------------------------------------------
# Non-interactive modes
# ---------------------------------------------------------------
function Invoke-NonInteractiveTriage {
    param(
        [string]$Mode,  # 'Full' or 'Quick'
        [string]$Tenant,
        [string[]]$Users,
        [string]$Auth,
        [int]$LookbackDays,
        [string]$Root,
        [string]$Client,
        [string]$Ref
    )

    # Auto-generate case metadata if not provided
    if (-not $Client) { $Client = $Tenant.Split('.')[0] }
    if (-not $Ref)    { $Ref = "TRIAGE-$(Get-Date -Format 'yyyyMMdd-HHmmss')" }

    New-TTCase -ClientName $Client -IncidentRef $Ref -Root $Root
    Connect-TTTenant -AuthMode $Auth -TenantId $Tenant

    $triageParams = @{ Days = $LookbackDays }
    if ($Users) { $triageParams.FocusUpn = $Users }
    if ($Mode -eq 'Quick') { $triageParams.SkipTenantWide = $true }

    Invoke-TTFullTriage @triageParams

    Complete-TTCase -Zip
}

# ---------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------
Show-Banner

# Non-interactive dispatch
if ($FullTriage -or $QuickTriage) {
    $mode = if ($QuickTriage) { 'Quick' } else { 'Full' }
    Invoke-NonInteractiveTriage -Mode $mode -Tenant $TenantId -Users $FocusUpn `
        -Auth $AuthMode -LookbackDays $Days -Root $CaseRoot `
        -Client $ClientName -Ref $IncidentRef
    return
}

# Interactive loop
Write-Host "  Type a number to select an option. Start with 1 (New Case), then 2 (Connect)." -ForegroundColor Gray
while ($true) {
    Show-MainMenu
    $choice = Read-Host '  Select option'
    if ([string]::IsNullOrWhiteSpace($choice)) { continue }

    try {
        $result = Invoke-MenuChoice -Choice $choice.Trim()
        if ($result -eq 'EXIT') { break }
    }
    catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`n  Press Enter to continue..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}
