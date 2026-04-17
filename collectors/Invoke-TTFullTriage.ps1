# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Invoke-TTFullTriage {
    <#
    .SYNOPSIS
        Orchestrator that runs the full triage collection in IR-phase order.
    .DESCRIPTION
        Runs every currently-implemented collector against the active case
        and tenant, organized around the six IR questions:

          1. How did they get in?          (sign-ins, risky users)
          2. What session did they use?    (session activity [v0.3])
          3. What persistence?             (inbox rules, forwarding, delegates, auth methods)
          4. What data was accessed?       (MailItemsAccessed [v0.3])
          5. What privileges added?        (admin roles, OAuth grants)
          6. What other workloads?         (SharePoint/OneDrive [v0.3])

        Runs pre-flight audit readiness check first. Each collector's
        errors are caught and logged so one failure doesn't abort the
        whole run.

    .PARAMETER FocusUpn
        One or more suspected-compromised UPNs. Collectors that support
        user scoping will narrow to these; tenant-wide collectors
        (OAuth apps, admin roles, risky users) still run globally.

    .PARAMETER Days
        Default lookback window for time-scoped collectors. Default 30.

    .PARAMETER IncludeHiddenRules
        Pass through to Get-TTInboxRules.

    .PARAMETER SkipTenantWide
        Skip tenant-wide collectors (inbox rules, forwarding, delegates
        across all mailboxes). Useful for fast single-user triage.

    .EXAMPLE
        # Fast triage on a suspected compromise
        Invoke-TTFullTriage -FocusUpn 'cfo@contoso.com' -Days 14 -SkipTenantWide

    .EXAMPLE
        # Full sweep after declared incident
        Invoke-TTFullTriage -FocusUpn 'cfo@contoso.com','ap@contoso.com' -Days 30 -IncludeHiddenRules
    #>
    [CmdletBinding()]
    param(
        [string[]]$FocusUpn,

        [ValidateRange(1, 90)]
        [int]$Days = 30,

        [switch]$IncludeHiddenRules,

        [switch]$SkipTenantWide
    )

    if (-not $script:TTContext.CaseId) {
        throw "No active case. Run New-TTCase first."
    }
    if (-not $script:TTContext.GraphConnected) {
        throw "Not connected. Run Connect-TTTenant first."
    }

    $summary = [ordered]@{
        Started          = [datetime]::UtcNow.ToString('o')
        FocusUpn         = $FocusUpn
        Days             = $Days
        Steps            = [System.Collections.Generic.List[object]]::new()
    }

    function Invoke-Step {
        param([string]$Name, [scriptblock]$Block)
        Write-TTLog -Level Action -Message "== $Name =="
        $t0 = Get-Date
        try {
            $result = & $Block
            $summary.Steps.Add([pscustomobject]@{
                Step     = $Name
                Status   = 'OK'
                Duration = '{0:N1}s' -f ((Get-Date) - $t0).TotalSeconds
                Result   = $result
            }) | Out-Null
        }
        catch {
            Write-TTLog -Level Error -Message "[$Name] $($_.Exception.Message)"
            $summary.Steps.Add([pscustomobject]@{
                Step     = $Name
                Status   = 'FAIL'
                Duration = '{0:N1}s' -f ((Get-Date) - $t0).TotalSeconds
                Result   = $_.Exception.Message
            }) | Out-Null
        }
    }

    # --- Phase 0: Pre-flight ---
    Invoke-Step 'Audit Readiness'       { Test-TTAuditReadiness }

    # --- Phase 1: How did they get in? ---
    Invoke-Step 'Sign-In Logs'          {
        if ($FocusUpn) {
            foreach ($u in $FocusUpn) { Get-TTSignInLogs -Days $Days -Upn $u }
        } else {
            Get-TTSignInLogs -Days $Days
        }
    }
    Invoke-Step 'Risky Users'           { Get-TTRiskyUsers -Days $Days }

    # --- Phase 2: What session? ---
    # Get-TTSessionActivity is scaffolded; skip until v0.3
    Write-TTLog -Level Info -Message "Session correlation (Get-TTSessionActivity): scaffolded for v0.3; skipping."

    # --- Phase 3: What persistence? ---
    Invoke-Step 'Auth Method Changes'   {
        $p = @{ Days = $Days }
        if ($FocusUpn) { $p.UserUpn = $FocusUpn }
        Get-TTAuthMethodChanges @p
    }

    Invoke-Step 'Mailbox Forwarding'    {
        if ($script:TTContext.ExoConnected) {
            $p = @{}
            if ($FocusUpn -or $SkipTenantWide) {
                if ($FocusUpn) { $p.UserUpn = $FocusUpn }
                else { Write-TTLog -Level Info -Message "SkipTenantWide set but no FocusUpn; skipping forwarding sweep." ; return }
            }
            Get-TTMailboxForwarding @p
        } else {
            Write-TTLog -Level Warn -Message "EXO not connected; skipping mailbox forwarding."
        }
    }

    Invoke-Step 'Inbox Rules'           {
        $p = @{}
        if ($FocusUpn)            { $p.UserUpn = $FocusUpn }
        elseif ($SkipTenantWide)  { Write-TTLog -Level Info -Message "SkipTenantWide set but no FocusUpn; skipping inbox rules." ; return }
        if ($IncludeHiddenRules)  { $p.IncludeHiddenRules = $true }
        Get-TTInboxRules @p
    }

    Invoke-Step 'Mailbox Delegations'   {
        if ($script:TTContext.ExoConnected) {
            $p = @{}
            if ($FocusUpn)            { $p.UserUpn = $FocusUpn }
            elseif ($SkipTenantWide)  { Write-TTLog -Level Info -Message "SkipTenantWide set but no FocusUpn; skipping delegates." ; return }
            Get-TTMailboxDelegates @p
        } else {
            Write-TTLog -Level Warn -Message "EXO not connected; skipping delegations."
        }
    }

    # --- Phase 4: What data accessed? ---
    Write-TTLog -Level Info -Message "MailItemsAccessed (Get-TTMailItemsAccessed): scaffolded for v0.3; skipping."

    # --- Phase 5: What privileges added? ---
    Invoke-Step 'Admin Role Changes'    { Get-TTAdminRoleChanges -Days $Days }
    Invoke-Step 'OAuth Grants'          {
        $p = @{}
        if ($FocusUpn) { $p.UserUpn = $FocusUpn }
        Get-TTOAuthGrants @p
    }

    # --- Phase 6: Other workloads ---
    Write-TTLog -Level Info -Message "SharePoint/OneDrive activity: requires UAL collector; scaffolded for v0.3."
    Write-TTLog -Level Info -Message "Message trace (Get-TTMessageTrace): scaffolded for v0.3."

    # Summary
    $summary.Completed = [datetime]::UtcNow.ToString('o')
    $okCount   = @($summary.Steps | Where-Object Status -eq 'OK').Count
    $failCount = @($summary.Steps | Where-Object Status -eq 'FAIL').Count

    Write-TTLog -Level Success -Message "Triage complete. $okCount steps OK, $failCount failed."

    # Save the triage manifest
    $triageSummary = [pscustomobject]$summary
    Save-TTArtifact -InputObject @($summary.Steps) -ArtifactName 'TriageRunSummary' -Category 'Config' -Format JSONL | Out-Null

    return $triageSummary
}
