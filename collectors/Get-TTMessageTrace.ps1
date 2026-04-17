# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTMessageTrace {
    <#
    .SYNOPSIS
        [SCAFFOLD] Pulls message trace data for outbound BEC investigation.

    .DESCRIPTION
        Answers: "What mail did the compromised account send?"

        Get-MessageTrace (up to 10 days) and Get-HistoricalSearch (10-90
        days) are the two EXO cmdlets. Together they cover the full
        practical investigation window for BEC outbound abuse.

        IMPLEMENTATION (v0.3):

        1. Window-aware dispatcher:
           - <= 10 days back  -> Get-MessageTrace (sync, fast)
           - 10-90 days back  -> Start-HistoricalSearch + poll (async)

        2. For each compromised UPN, pull:
           - SenderAddress = $upn AND recent window  -> outbound abuse
           - RecipientAddress = $upn AND recent window -> phishing inbound

        3. Enrich each trace with ClientIP where available (via detail trace).

        4. Flag:
           - Bulk-external sends (same subject, many recipients outside tenant)
           - Bounces/NDRs indicating spray campaigns
           - Messages to lookalike domain recipients

        5. Cross-reference with MailItemsAccessed Bind events - for any
           message the attacker READ, is there a response sent shortly
           after? That's the classic thread-hijacking signature.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$UserUpn,

        [int]$Days = 7
    )

    Write-TTLog -Level Warn -Message "Get-TTMessageTrace is scaffolded. Slated for v0.3."
    return $null
}
