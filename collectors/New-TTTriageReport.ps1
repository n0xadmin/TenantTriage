# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function New-TTTriageReport {
    <#
    .SYNOPSIS
        Generates an HTML triage summary report from collected artifacts.
    .DESCRIPTION
        Reads all collected artifacts in the active case and produces a
        single-page HTML report organized by IR phase. Designed to be
        the deliverable you hand to counsel, the carrier, or your client.

        Report sections:
          - Case metadata (analyst, tenant, timeline)
          - Audit readiness summary
          - Sign-in anomalies (suspicious IPs, apps, locations)
          - Risky users and detections
          - Inbox rules flagged as suspicious (score >= 3)
          - Mailbox forwarding (especially external)
          - Delegation changes
          - Auth method / MFA changes (self-registrations highlighted)
          - Admin role changes
          - OAuth grants with risky scopes
          - Artifact manifest with hashes

        Only includes sections where artifacts actually exist — if you
        only ran sign-in logs and inbox rules, you only get those sections.

    .PARAMETER Title
        Report title. Defaults to "Incident Response Triage Report".

    .EXAMPLE
        New-TTTriageReport

    .EXAMPLE
        New-TTTriageReport -Title 'Contoso BEC Investigation - CFO Account'
    #>
    [CmdletBinding()]
    param(
        [string]$Title = 'Incident Response Triage Report',

        # Override the analyst name/email shown on the report.
        # Defaults to whatever is in the case context (set during
        # New-TTCase or Connect-TTTenant).
        [string]$AnalystName
    )

    if (-not $script:TTContext.CasePath) {
        throw "No active case. Run New-TTCase first."
    }

    # Apply analyst override to context if provided
    if ($AnalystName) {
        $script:TTContext.AnalystUpn = $AnalystName
        Write-TTLog -Level Info -Message "Analyst set to: $AnalystName"
    }

    $casePath = $script:TTContext.CasePath
    Write-TTLog -Level Action -Message "Generating triage summary report..."

    # Helper: safely read the most recent artifact matching a name pattern
    function Read-Artifact {
        param([string]$Category, [string]$Pattern)
        $dir = Join-Path $casePath $Category
        if (-not (Test-Path $dir)) { return $null }
        $file = Get-ChildItem $dir -Filter "*$Pattern*.jsonl" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $file) { return $null }
        try {
            return Get-Content $file.FullName | ForEach-Object { $_ | ConvertFrom-Json }
        } catch { return $null }
    }

    # Helper: HTML-encode
    function HtmlEncode { param([string]$s) return [System.Net.WebUtility]::HtmlEncode("$s") }

    # Helper: build an HTML table from objects
    function ConvertTo-HtmlTable {
        param([object[]]$Data, [string[]]$Columns, [int]$MaxRows = 100)
        if (-not $Data -or $Data.Count -eq 0) { return '<p class="empty">No data collected.</p>' }

        $truncated = $Data.Count -gt $MaxRows
        $rows = $Data | Select-Object -First $MaxRows

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('<table><thead><tr>')
        foreach ($col in $Columns) { [void]$sb.Append("<th>$(HtmlEncode $col)</th>") }
        [void]$sb.Append('</tr></thead><tbody>')

        foreach ($row in $rows) {
            [void]$sb.Append('<tr>')
            foreach ($col in $Columns) {
                $val = "$($row.$col)"
                if ($val.Length -gt 120) { $val = $val.Substring(0, 117) + '...' }
                [void]$sb.Append("<td>$(HtmlEncode $val)</td>")
            }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table>')
        if ($truncated) { [void]$sb.Append("<p class='note'>Showing first $MaxRows of $($Data.Count) rows. See JSONL/CSV for full data.</p>") }
        return $sb.ToString()
    }

    # ---------------------------------------------------------------
    # Collect data from artifacts
    # ---------------------------------------------------------------
    $caseJson = $null
    $caseJsonPath = Join-Path $casePath '_meta\case.json'
    if (Test-Path $caseJsonPath) { $caseJson = Get-Content $caseJsonPath -Raw | ConvertFrom-Json }

    $auditReadiness       = Read-Artifact 'Config' 'AuditReadiness'
    $signInsInteractive   = Read-Artifact 'Identity' 'EntraSignInLogs-Interactive'
    $signInsNonInteractive= Read-Artifact 'Identity' 'EntraSignInLogs-NonInteractive'
    $signInsSP            = Read-Artifact 'Identity' 'EntraSignInLogs-ServicePrincipal'
    $riskyUsers           = Read-Artifact 'Identity' 'RiskyUsers'
    $riskDetections       = Read-Artifact 'Identity' 'RiskDetections'
    $authMethodChanges    = Read-Artifact 'Identity' 'AuthMethodChanges'
    $authSelfRegistered   = Read-Artifact 'Identity' 'AuthMethodChanges-SelfRegistered'
    $adminRoleChanges     = Read-Artifact 'Identity' 'AdminRoleChanges'
    $adminCurrentHolders  = Read-Artifact 'Identity' 'AdminRoles-CurrentHolders'
    $suspiciousRules      = Read-Artifact 'Mail' 'InboxRules-Suspicious'
    $allRules             = Read-Artifact 'Mail' 'InboxRules-All'
    $forwarding           = Read-Artifact 'Mail' 'MailboxForwarding'
    $forwardingExternal   = Read-Artifact 'Mail' 'MailboxForwarding-External'
    $fullAccess           = Read-Artifact 'Mail' 'MailboxPermissions-FullAccess'
    $sendAs               = Read-Artifact 'Mail' 'MailboxPermissions-SendAs'
    $sendOnBehalf         = Read-Artifact 'Mail' 'MailboxPermissions-SendOnBehalf'
    $oauthRisky           = Read-Artifact 'Apps' 'OAuthGrants-Risky'
    $oauthUnverified      = Read-Artifact 'Apps' 'OAuthGrants-UnverifiedExternal'

    # ---------------------------------------------------------------
    # Count sign-in anomalies
    # ---------------------------------------------------------------
    $failedSignIns = @()
    $suspiciousApps = @()
    $allSignIns = @($signInsInteractive) + @($signInsNonInteractive) + @($signInsSP) | Where-Object { $_ }
    if ($allSignIns) {
        $failedSignIns = @($allSignIns | Where-Object {
            $_.status -and $_.status.errorCode -ne 0
        })
        $suspiciousApps = @($allSignIns | Where-Object {
            $_.appDisplayName -and $_.appDisplayName -notmatch 'Office 365|Microsoft Office|Outlook|SharePoint|Teams|OneDrive|Azure Portal|My Signins|My Apps|My Profile'
        })
    }

    # ---------------------------------------------------------------
    # Build findings summary (the "executive summary" block)
    # ---------------------------------------------------------------
    $findings = [System.Collections.Generic.List[string]]::new()

    if ($auditReadiness) {
        $auditFails = @($auditReadiness | Where-Object Status -eq 'FAIL')
        if ($auditFails.Count -gt 0) {
            $findings.Add("CRITICAL: $($auditFails.Count) audit coverage gap(s) detected — evidence may be incomplete.") | Out-Null
        }
    }
    if ($suspiciousRules -and @($suspiciousRules).Count -gt 0) {
        $findings.Add("$(@($suspiciousRules).Count) suspicious inbox rule(s) found (score >= 3). Review immediately.") | Out-Null
    }
    if ($forwardingExternal -and @($forwardingExternal).Count -gt 0) {
        $findings.Add("$(@($forwardingExternal).Count) mailbox(es) forwarding externally.") | Out-Null
    }
    if ($authSelfRegistered -and @($authSelfRegistered).Count -gt 0) {
        $findings.Add("$(@($authSelfRegistered).Count) self-registered MFA/security-info change(s) — possible attacker-added auth method.") | Out-Null
    }
    if ($oauthRisky -and @($oauthRisky).Count -gt 0) {
        $findings.Add("$(@($oauthRisky).Count) OAuth grant(s) with high-risk scopes (Mail.*, Files.*, Directory.*).") | Out-Null
    }
    if ($oauthUnverified -and @($oauthUnverified).Count -gt 0) {
        $findings.Add("$(@($oauthUnverified).Count) OAuth grant(s) from unverified external publishers.") | Out-Null
    }
    if ($riskyUsers -and @($riskyUsers).Count -gt 0) {
        $findings.Add("$(@($riskyUsers).Count) user(s) flagged as risky by Entra Identity Protection.") | Out-Null
    }
    if ($adminRoleChanges -and @($adminRoleChanges).Count -gt 0) {
        $findings.Add("$(@($adminRoleChanges).Count) admin role assignment change(s) in the lookback window.") | Out-Null
    }
    if ($findings.Count -eq 0) {
        $findings.Add("No high-severity indicators detected across collected artifacts. Review detailed sections below for context.") | Out-Null
    }

    # ---------------------------------------------------------------
    # Generate HTML
    # ---------------------------------------------------------------
    $reportTime = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss UTC')
    $sections = [System.Text.StringBuilder]::new()

    # Executive summary
    [void]$sections.Append('<div class="section"><h2>Executive Summary</h2><div class="findings">')
    foreach ($f in $findings) {
        $cls = if ($f -match 'CRITICAL') { 'finding-critical' } elseif ($f -match 'No high-severity') { 'finding-ok' } else { 'finding-warn' }
        [void]$sections.Append("<div class='finding $cls'>$(HtmlEncode $f)</div>")
    }
    [void]$sections.Append('</div></div>')

    # Audit readiness
    if ($auditReadiness) {
        [void]$sections.Append('<div class="section"><h2>Audit Readiness</h2>')
        [void]$sections.Append((ConvertTo-HtmlTable -Data $auditReadiness -Columns 'Check','Status','Detail','Remediation'))
        [void]$sections.Append('</div>')
    }

    # Sign-in summary
    if ($allSignIns) {
        [void]$sections.Append('<div class="section"><h2>Phase 1: Sign-In Overview</h2>')
        [void]$sections.Append("<div class='stat-row'>")
        [void]$sections.Append("<div class='stat'><span class='stat-num'>$(@($signInsInteractive).Count)</span><span class='stat-label'>Interactive</span></div>")
        [void]$sections.Append("<div class='stat'><span class='stat-num'>$(@($signInsNonInteractive).Count)</span><span class='stat-label'>NonInteractive</span></div>")
        [void]$sections.Append("<div class='stat'><span class='stat-num'>$(@($signInsSP).Count)</span><span class='stat-label'>ServicePrincipal</span></div>")
        [void]$sections.Append("<div class='stat'><span class='stat-num'>$($failedSignIns.Count)</span><span class='stat-label'>Failed</span></div>")
        [void]$sections.Append("</div>")

        # Top IPs
        if ($signInsInteractive) {
            $topIps = @($signInsInteractive | Group-Object ipAddress | Sort-Object Count -Descending | Select-Object -First 10)
            if ($topIps) {
                [void]$sections.Append('<h3>Top 10 Source IPs (Interactive)</h3>')
                $ipData = $topIps | ForEach-Object { [pscustomobject]@{ IPAddress = $_.Name; Count = $_.Count } }
                [void]$sections.Append((ConvertTo-HtmlTable -Data $ipData -Columns 'IPAddress','Count'))
            }
            # Top apps
            $topApps = @($signInsInteractive | Group-Object appDisplayName | Sort-Object Count -Descending | Select-Object -First 10)
            if ($topApps) {
                [void]$sections.Append('<h3>Top 10 Applications (Interactive)</h3>')
                $appData = $topApps | ForEach-Object { [pscustomobject]@{ Application = $_.Name; Count = $_.Count } }
                [void]$sections.Append((ConvertTo-HtmlTable -Data $appData -Columns 'Application','Count'))
            }
        }
        [void]$sections.Append('</div>')
    }

    # Risky users
    if ($riskyUsers -or $riskDetections) {
        [void]$sections.Append('<div class="section"><h2>Phase 1: Risky Users & Detections</h2>')
        if ($riskyUsers) {
            [void]$sections.Append('<h3>Risky Users</h3>')
            [void]$sections.Append((ConvertTo-HtmlTable -Data $riskyUsers -Columns 'userPrincipalName','riskLevel','riskState','riskDetail','riskLastUpdatedDateTime'))
        }
        if ($riskDetections) {
            [void]$sections.Append('<h3>Risk Detections</h3>')
            [void]$sections.Append((ConvertTo-HtmlTable -Data $riskDetections -Columns 'detectedDateTime','userPrincipalName','riskEventType','riskLevel','ipAddress','location' -MaxRows 50))
        }
        [void]$sections.Append('</div>')
    }

    # Suspicious inbox rules
    if ($suspiciousRules -or $allRules) {
        [void]$sections.Append('<div class="section"><h2>Phase 3: Inbox Rules</h2>')
        $totalRules = if ($allRules) { @($allRules).Count } else { 0 }
        $suspCount  = if ($suspiciousRules) { @($suspiciousRules).Count } else { 0 }
        [void]$sections.Append("<p>Total rules: <strong>$totalRules</strong> | Suspicious (score &ge; 3): <strong class='highlight'>$suspCount</strong></p>")
        if ($suspiciousRules) {
            [void]$sections.Append((ConvertTo-HtmlTable -Data $suspiciousRules -Columns 'UserPrincipalName','RuleName','SuspicionScore','SuspicionReasons','Source','IsEnabled'))
        }
        [void]$sections.Append('</div>')
    }

    # Forwarding
    if ($forwarding -or $forwardingExternal) {
        [void]$sections.Append('<div class="section"><h2>Phase 3: Mailbox Forwarding</h2>')
        $extCount = if ($forwardingExternal) { @($forwardingExternal).Count } else { 0 }
        [void]$sections.Append("<p>External forwarders: <strong class='highlight'>$extCount</strong></p>")
        $fwdData = if ($forwardingExternal) { $forwardingExternal } elseif ($forwarding) { $forwarding } else { $null }
        if ($fwdData) {
            [void]$sections.Append((ConvertTo-HtmlTable -Data $fwdData -Columns 'UserPrincipalName','ForwardingSmtpAddress','ForwardingAddress','DeliverToMailboxAndForward','IsExternalForward'))
        }
        [void]$sections.Append('</div>')
    }

    # Delegations
    if ($fullAccess -or $sendAs -or $sendOnBehalf) {
        [void]$sections.Append('<div class="section"><h2>Phase 3: Mailbox Delegations</h2>')
        [void]$sections.Append("<div class='stat-row'>")
        [void]$sections.Append("<div class='stat'><span class='stat-num'>$(if($fullAccess){@($fullAccess).Count}else{0})</span><span class='stat-label'>FullAccess</span></div>")
        [void]$sections.Append("<div class='stat'><span class='stat-num'>$(if($sendAs){@($sendAs).Count}else{0})</span><span class='stat-label'>SendAs</span></div>")
        [void]$sections.Append("<div class='stat'><span class='stat-num'>$(if($sendOnBehalf){@($sendOnBehalf).Count}else{0})</span><span class='stat-label'>SendOnBehalf</span></div>")
        [void]$sections.Append("</div>")
        if ($fullAccess) { [void]$sections.Append('<h3>FullAccess Grants</h3>'); [void]$sections.Append((ConvertTo-HtmlTable -Data $fullAccess -Columns 'MailboxUpn','Grantee','AccessRights','Deny')) }
        if ($sendAs)     { [void]$sections.Append('<h3>SendAs Grants</h3>');     [void]$sections.Append((ConvertTo-HtmlTable -Data $sendAs -Columns 'MailboxUpn','Grantee','AccessRights')) }
        [void]$sections.Append('</div>')
    }

    # Auth method changes
    if ($authMethodChanges -or $authSelfRegistered) {
        [void]$sections.Append('<div class="section"><h2>Phase 3: Auth Method / MFA Changes</h2>')
        if ($authSelfRegistered -and @($authSelfRegistered).Count -gt 0) {
            [void]$sections.Append("<p class='highlight'>Self-registered changes (initiator = target): <strong>$(@($authSelfRegistered).Count)</strong></p>")
            [void]$sections.Append((ConvertTo-HtmlTable -Data $authSelfRegistered -Columns 'ActivityDateTime','Activity','TargetUpn','InitiatedByUpn','InitiatedByIp'))
        }
        if ($authMethodChanges) {
            [void]$sections.Append('<h3>All Auth Method Events</h3>')
            [void]$sections.Append((ConvertTo-HtmlTable -Data $authMethodChanges -Columns 'ActivityDateTime','Activity','TargetUpn','InitiatedByUpn','InitiatedByIp','Result' -MaxRows 50))
        }
        [void]$sections.Append('</div>')
    }

    # Admin roles
    if ($adminRoleChanges -or $adminCurrentHolders) {
        [void]$sections.Append('<div class="section"><h2>Phase 5: Admin Role Changes</h2>')
        if ($adminRoleChanges) {
            [void]$sections.Append('<h3>Role Assignment Events</h3>')
            [void]$sections.Append((ConvertTo-HtmlTable -Data $adminRoleChanges -Columns 'ActivityDateTime','Activity','TargetUpn','TargetDisplayName','RoleName','InitiatedByUpn','InitiatedByIp'))
        }
        if ($adminCurrentHolders) {
            [void]$sections.Append('<h3>Current Role Holders</h3>')
            [void]$sections.Append((ConvertTo-HtmlTable -Data $adminCurrentHolders -Columns 'RoleName','MemberUpn','MemberDisplayName','AccountEnabled' -MaxRows 200))
        }
        [void]$sections.Append('</div>')
    }

    # OAuth
    if ($oauthRisky -or $oauthUnverified) {
        [void]$sections.Append('<div class="section"><h2>Phase 5: OAuth / App Consent</h2>')
        if ($oauthRisky) {
            [void]$sections.Append('<h3>High-Risk Scope Grants</h3>')
            [void]$sections.Append((ConvertTo-HtmlTable -Data $oauthRisky -Columns 'ClientAppDisplayName','PublisherName','VerifiedPublisher','RiskyScopes','GrantType','ConsentType'))
        }
        if ($oauthUnverified) {
            [void]$sections.Append('<h3>Unverified External Publisher Grants</h3>')
            [void]$sections.Append((ConvertTo-HtmlTable -Data $oauthUnverified -Columns 'ClientAppDisplayName','PublisherName','AppOwnerTenantId','RiskyScopes','GrantType'))
        }
        [void]$sections.Append('</div>')
    }

    # Artifact manifest
    if ($script:TTContext.ArtifactManifest.Count -gt 0) {
        [void]$sections.Append('<div class="section"><h2>Artifact Manifest</h2>')
        [void]$sections.Append((ConvertTo-HtmlTable -Data $script:TTContext.ArtifactManifest.ToArray() -Columns 'ArtifactName','Category','Format','RowCount','SizeBytes','SHA256','CollectedUtc' -MaxRows 200))
        [void]$sections.Append('</div>')
    }

    # ---------------------------------------------------------------
    # Assemble full HTML
    # ---------------------------------------------------------------
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(HtmlEncode $Title)</title>
<style>
  :root { --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a; --text: #e0e0e0; --text-muted: #888; --accent: #4f9cf7; --red: #e74c3c; --orange: #e67e22; --green: #27ae60; --yellow: #f1c40f; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1400px; margin: 0 auto; }
  .header { border-bottom: 2px solid var(--accent); padding-bottom: 1.5rem; margin-bottom: 2rem; }
  .header h1 { font-size: 1.8rem; color: var(--accent); margin-bottom: 0.5rem; }
  .header-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 0.5rem; font-size: 0.9rem; color: var(--text-muted); }
  .header-meta span { } .header-meta strong { color: var(--text); }
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .section h2 { font-size: 1.3rem; color: var(--accent); margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .section h3 { font-size: 1.05rem; color: var(--text); margin: 1.2rem 0 0.5rem; }
  .findings { display: flex; flex-direction: column; gap: 0.5rem; }
  .finding { padding: 0.75rem 1rem; border-radius: 6px; font-size: 0.95rem; border-left: 4px solid; }
  .finding-critical { background: rgba(231,76,60,0.1); border-color: var(--red); color: var(--red); }
  .finding-warn { background: rgba(230,126,34,0.1); border-color: var(--orange); color: var(--orange); }
  .finding-ok { background: rgba(39,174,96,0.1); border-color: var(--green); color: var(--green); }
  .stat-row { display: flex; gap: 1.5rem; margin: 1rem 0; flex-wrap: wrap; }
  .stat { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; text-align: center; min-width: 120px; }
  .stat-num { display: block; font-size: 2rem; font-weight: 700; color: var(--accent); }
  .stat-label { display: block; font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
  table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; font-size: 0.85rem; }
  thead { background: var(--bg); }
  th { text-align: left; padding: 0.6rem 0.8rem; color: var(--accent); font-weight: 600; border-bottom: 2px solid var(--border); white-space: nowrap; }
  td { padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--border); word-break: break-word; max-width: 300px; }
  tr:hover td { background: rgba(79,156,247,0.05); }
  .highlight { color: var(--orange); }
  .empty { color: var(--text-muted); font-style: italic; }
  .note { color: var(--text-muted); font-size: 0.85rem; margin-top: 0.5rem; }
  .footer { text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }
  @media print { body { background: #fff; color: #000; } .section { border-color: #ccc; background: #fafafa; } th { color: #333; } td { border-color: #ddd; } .finding-warn { color: #b35900; } .finding-critical { color: #c0392b; } }
</style>
</head>
<body>
<div class="header">
  <h1>$(HtmlEncode $Title)</h1>
  <div class="header-meta">
    <span>Case ID: <strong>$(HtmlEncode $script:TTContext.CaseId)</strong></span>
    <span>Tenant: <strong>$(HtmlEncode $script:TTContext.TenantDomain) ($(HtmlEncode $script:TTContext.TenantId))</strong></span>
    <span>Analyst: <strong>$(HtmlEncode $script:TTContext.AnalystUpn)</strong></span>
    <span>Generated: <strong>$reportTime</strong></span>
    <span>Client: <strong>$(if($caseJson){HtmlEncode $caseJson.ClientName}else{'N/A'})</strong></span>
    <span>Incident Ref: <strong>$(if($caseJson){HtmlEncode $caseJson.IncidentRef}else{'N/A'})</strong></span>
  </div>
</div>

$($sections.ToString())

<div class="footer">
  Generated by TenantTriage v0.3.0 | $reportTime | $(HtmlEncode $script:TTContext.AnalystUpn)
</div>
</body>
</html>
"@

    # Save to case folder
    $reportPath = Join-Path $casePath "TriageReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $html | Set-Content -Path $reportPath -Encoding utf8

    # Also save to Config as a tracked artifact
    Save-TTArtifact -InputObject @([pscustomobject]@{
        ReportPath   = $reportPath
        GeneratedUtc = $reportTime
        FindingsCount = $findings.Count
        Sections     = $sections.Length
    }) -ArtifactName 'TriageReportMeta' -Category 'Config' -Format JSONL | Out-Null

    Write-TTLog -Level Success -Message "Triage report: $reportPath"
    Write-Host ""
    Write-Host "  Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "  Open in any browser to view." -ForegroundColor Gray

    # Try to open it automatically on Windows
    if ($IsWindows -or $env:OS -match 'Windows') {
        $openIt = Read-Host '  Open in browser? (Y/n)'
        if ($openIt -notmatch '^[nN]') {
            Start-Process $reportPath
        }
    }

    return [pscustomobject]@{
        ReportPath = $reportPath
        Findings   = $findings.Count
    }
}
