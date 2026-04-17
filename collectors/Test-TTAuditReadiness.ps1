# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Test-TTAuditReadiness {
    <#
    .SYNOPSIS
        Pre-flight check. Verifies the evidence you expect to exist actually does.
    .DESCRIPTION
        One of the highest-impact things you can do at the start of an
        engagement. Answers: "before I go hunting, is the audit coverage
        actually there?" Catches things like:
          - Unified Audit Log disabled
          - Mailbox auditing disabled tenant-wide
          - Retention ceilings (Standard vs Premium licensing)
          - Entra sign-in log retention (P1/P2 required for >7 days in some views)

        Output is a readiness report saved to Config\ plus a per-check
        summary returned to the caller.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:TTContext.GraphConnected) {
        throw "Not connected. Run Connect-TTTenant first."
    }

    Write-TTLog -Level Action -Message "Running audit readiness assessment..."

    $checks = [System.Collections.Generic.List[object]]::new()

    function Add-Check {
        param($Name, $Status, $Detail, $Remediation)
        $checks.Add([pscustomobject]@{
            Check       = $Name
            Status      = $Status    # 'OK' | 'WARN' | 'FAIL' | 'INFO'
            Detail      = $Detail
            Remediation = $Remediation
        }) | Out-Null
    }

    # --- Tenant licensing context ---
    try {
        $subs = Invoke-TTGraphRequest -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -All
        $skuNames = $subs.skuPartNumber -join ', '
        $hasP2 = $subs | Where-Object { $_.skuPartNumber -match 'AAD_PREMIUM_P2|ENTERPRISEPREMIUM|M365_E5|AAD_PREMIUM_P2_FACULTY' }
        $hasP1 = $subs | Where-Object { $_.skuPartNumber -match 'AAD_PREMIUM|ENTERPRISEPACK|M365_E3|SPE_E3|SPE_E5' }
        $hasE5Compliance = $subs | Where-Object { $_.skuPartNumber -match 'M365_E5_COMPLIANCE|INFORMATION_PROTECTION_COMPLIANCE|M365_E5' }

        if ($hasP2)      { Add-Check 'Entra ID P2'              'OK'   "Detected P2-class SKU: likely supports Identity Protection, PIM, risky users." '' }
        elseif ($hasP1)  { Add-Check 'Entra ID P1'              'WARN' "Only P1 detected. Identity Protection / riskyUsers endpoints may return limited data." 'Upgrade to P2 for full risk data, or plan for reduced telemetry.' }
        else             { Add-Check 'Entra ID Premium'         'FAIL' "No Premium SKU detected. Sign-in log retention and risk data will be severely limited." 'Free tier keeps interactive sign-ins only, 7-day retention.' }

        if ($hasE5Compliance) { Add-Check 'Audit Premium'       'OK'   "E5/E5 Compliance detected: MailItemsAccessed and 365-day retention likely available." '' }
        else                  { Add-Check 'Audit Premium'       'WARN' "No E5/Audit Premium SKU detected. MailItemsAccessed will not be available; UAL retention capped at 180 days." 'Scope expectations accordingly; MailItemsAccessed is Premium-only.' }

        Add-Check 'Subscribed SKUs' 'INFO' $skuNames ''
    }
    catch {
        Add-Check 'License inventory' 'FAIL' "Could not read subscribedSkus: $($_.Exception.Message)" 'Check Directory.Read.All scope.'
    }

    # --- Unified Audit Log status (requires EXO) ---
    if ($script:TTContext.ExoConnected) {
        try {
            $adminAuditCfg = Get-AdminAuditLogConfig -ErrorAction Stop
            if ($adminAuditCfg.UnifiedAuditLogIngestionEnabled) {
                Add-Check 'Unified Audit Log' 'OK' 'UAL ingestion enabled.' ''
            } else {
                Add-Check 'Unified Audit Log' 'FAIL' 'UAL ingestion DISABLED. Most historical evidence is not being captured.' 'Run: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'
            }
        } catch {
            Add-Check 'Unified Audit Log' 'WARN' "Could not query UAL state: $($_.Exception.Message)" 'Check Organization Management or View-Only Audit Logs role.'
        }

        try {
            $orgCfg = Get-OrganizationConfig -ErrorAction Stop
            if ($orgCfg.AuditDisabled) {
                Add-Check 'Mailbox auditing (tenant)' 'FAIL' 'AuditDisabled=True at org level. Individual mailbox audit entries not being captured.' 'Run: Set-OrganizationConfig -AuditDisabled $false'
            } else {
                Add-Check 'Mailbox auditing (tenant)' 'OK' 'Tenant-level mailbox auditing enabled.' ''
            }
        } catch {
            Add-Check 'Mailbox auditing (tenant)' 'WARN' "Could not read OrganizationConfig: $($_.Exception.Message)" ''
        }
    } else {
        Add-Check 'Exchange Online' 'WARN' 'Not connected. UAL and mailbox audit checks skipped.' 'Re-run Connect-TTTenant without -SkipExchangeOnline.'
    }

    # --- Diagnostic settings for Entra logs (does Sentinel or LA have a forwarder?) ---
    # This is a proxy for "do we have retention beyond the default 30 days?"
    try {
        $diag = Invoke-TTGraphRequest -Uri 'https://graph.microsoft.com/beta/auditLogs/directoryProvisioning?$top=1' -ErrorAction SilentlyContinue
        # Placeholder; proper diagnostic settings check requires Azure Monitor API (outside Graph scope)
        Add-Check 'Long-term log retention' 'INFO' 'Check manually whether Entra logs are shipped to Log Analytics/Sentinel for >30d retention.' 'Azure Portal > Entra > Monitoring > Diagnostic settings'
    } catch {}

    # Summary
    $failCount = @($checks | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($checks | Where-Object Status -eq 'WARN').Count
    $okCount   = @($checks | Where-Object Status -eq 'OK').Count

    Write-TTLog -Level Info -Message "Audit readiness: $okCount OK, $warnCount WARN, $failCount FAIL"
    if ($failCount -gt 0) {
        Write-TTLog -Level Warn -Message "CRITICAL audit gaps detected - expect reduced evidence quality."
    }

    Save-TTArtifact -InputObject $checks.ToArray() `
                    -ArtifactName 'AuditReadiness' `
                    -Category 'Config' `
                    -Format Both `
                    -CollectionMetadata @{ Summary = "$okCount OK, $warnCount WARN, $failCount FAIL" } | Out-Null

    return $checks.ToArray()
}
