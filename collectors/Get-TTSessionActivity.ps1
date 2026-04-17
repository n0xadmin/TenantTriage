# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTSessionActivity {
    <#
    .SYNOPSIS
        [SCAFFOLD - depends on Get-TTUnifiedAuditLog]
        Correlates a session ID / UTI across every workload that saw it.

    .DESCRIPTION
        Answers: "What did this exact stolen session do after login?"

        This is the token-abuse pivot that most tools don't do well.
        Given a UTI (Unique Token Identifier) or SessionId from an Entra
        sign-in, find EVERY downstream action tagged with that same
        session across Exchange, SharePoint, OneDrive, Teams, and Graph.

        Microsoft explicitly documents UTI as a token-level investigation
        pivot - it's the authoritative way to answer "what did this one
        token do."

        WORKFLOW:

        1. Analyst runs Get-TTSignInLogs, identifies one or more suspicious
           sign-ins. Copies the 'uniqueTokenIdentifier' (UTI) value.

        2. Analyst runs:
             Get-TTSessionActivity -Uti 'xyz123==' -Days 7

        3. Tool queries UAL for any record where AuditData contains that
           UTI. Output is a unified timeline across workloads.

        IMPLEMENTATION (v0.3):

        - UAL search with free-text filter for UTI value (UAL supports
          FreeText but it's slow; better to pull UAL for the time window
          then filter client-side by RegEx on AuditData).
        - Also search by SessionId if provided (distinct from UTI;
          SessionId is the sign-in session, UTI is the token itself).
        - Normalize output across workloads into a single timeline:
            Timestamp | Workload | Operation | User | ClientIP | Details
        - Produce artifact 'SessionTimeline-{UTI}.csv' ordered by time.

    .PARAMETER Uti
        Unique Token Identifier from Entra sign-in log. Primary pivot.

    .PARAMETER SessionId
        Sign-in session ID. Secondary pivot; some workloads log this
        instead of (or alongside) UTI.

    .PARAMETER CorrelationId
        The Entra correlation ID - broader than SessionId but useful
        when UTI isn't present. Used to group sign-in events.

    .EXAMPLE
        Get-TTSessionActivity -Uti 'J7f8Kz9qUk2Qe1W6' -Days 7
    #>
    [CmdletBinding()]
    param(
        [string]$Uti,
        [string]$SessionId,
        [string]$CorrelationId,
        [int]$Days = 7
    )

    if (-not ($Uti -or $SessionId -or $CorrelationId)) {
        throw "Provide at least one of: -Uti, -SessionId, -CorrelationId"
    }

    Write-TTLog -Level Warn -Message "Get-TTSessionActivity is scaffolded. Depends on Get-TTUnifiedAuditLog (v0.3)."
    Write-TTLog -Level Info -Message "When built, this will be the highest-value collector for answering 'what did the stolen session do?'"
    return $null
}
