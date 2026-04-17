# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTMailItemsAccessed {
    <#
    .SYNOPSIS
        [SCAFFOLD - depends on Get-TTUnifiedAuditLog]
        Extracts MailItemsAccessed events to scope what mail was touched.

    .DESCRIPTION
        Answers: "What mail did they actually read/sync?"

        MailItemsAccessed is the gold-standard artifact for BEC scoping.
        Microsoft records it for Audit (Premium) tenants only (E5 or
        Audit add-on). It covers POP, IMAP, MAPI, EWS, ActiveSync, and
        REST access with both Sync and Bind event types:

          - Bind  - specific item accessed (can enumerate messageIds)
          - Sync  - mailbox/folder synced (item-level scoping is moot,
                    assume full exposure for that folder)

        IMPLEMENTATION (v0.3, after Get-TTUnifiedAuditLog):

        1. Pre-flight: confirm Audit (Premium) licensing present.
           Call Test-TTAuditReadiness and warn if E5/Audit Premium absent.

        2. Delegate to Get-TTUnifiedAuditLog with:
             -Operations @('MailItemsAccessed')
             -UserUpn    <targets>
             -StartUtc/-EndUtc <incident window>

        3. For each event, parse AuditData.Folders[].FolderItems[] to
           extract InternetMessageIds (Bind) or mark as Sync-level.

        4. Produce two artifacts:
             - MailItemsAccessed-Bind-MessageIds  (feedable into message trace)
             - MailItemsAccessed-Sync-Summary     (per-folder per-session)

        5. Correlate with MailboxAudit 'MailboxLogin' ClientInfoString
           to tie access to client type (Outlook, OWA, EWS app, etc.)

    .NOTES
        Throttling warning: MailItemsAccessed can be extremely high volume.
        Scope tightly with UserUpn and a narrow time window.
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartUtc,
        [datetime]$EndUtc,
        [string[]]$UserUpn
    )

    Write-TTLog -Level Warn -Message "Get-TTMailItemsAccessed is scaffolded. Requires Get-TTUnifiedAuditLog (v0.3)."
    return $null
}
