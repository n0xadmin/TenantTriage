function Connect-TTTenant {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph and Exchange Online for a target tenant.
    .DESCRIPTION
        Supports three auth modes to match the realities of IR work:

          Interactive  - Analyst opens a browser, signs in with their
                         delegated IR account. Use for in-person/VDI work.

          DeviceCode   - Emergency-grade auth. Analyst gets a code, the
                         client runs it in their browser. Use when brought
                         into a tenant at 3am with no app reg pre-staged.

          AppOnly      - Certificate-based app auth against a retainer-client
                         tenant. Use for standing IR clients where you've
                         pre-staged a multi-tenant app registration.

        Required Graph permissions (delegated or app):
          - AuditLog.Read.All
          - Directory.Read.All
          - SecurityEvents.Read.All       (for risky users/detections)
          - IdentityRiskEvent.Read.All
          - Policy.Read.All               (for conditional access)
          - Application.Read.All          (for OAuth/service principal review)

        Exchange Online adds:
          - View-Only Audit Logs role (min) for UAL
          - View-Only Recipients        for mailbox config
          - Global Reader              is the usual pragmatic minimum
    .EXAMPLE
        Connect-TTTenant -AuthMode Interactive -TenantId contoso.onmicrosoft.com
    .EXAMPLE
        Connect-TTTenant -AuthMode DeviceCode -TenantId 8a3b....-....-....-....-............
    .EXAMPLE
        Connect-TTTenant -AuthMode AppOnly -TenantId contoso.onmicrosoft.com `
            -ClientId 'aaaa-bbbb-cccc-dddd' -CertificateThumbprint '9F86D...'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Interactive','DeviceCode','AppOnly')]
        [string]$AuthMode,

        [Parameter(Mandatory)]
        [string]$TenantId,

        # Required for AppOnly
        [string]$ClientId,
        [string]$CertificateThumbprint,

        # Skip Exchange Online (faster if you only need Graph artifacts this pass)
        [switch]$SkipExchangeOnline
    )

    if (-not $script:TTContext.CaseId) {
        throw "No active case. Run New-TTCase first."
    }

    # Disconnect any existing sessions before reconnecting (avoids corrupted auth state)
    if ($script:TTContext.GraphConnected -or $script:TTContext.ExoConnected) {
        Write-TTLog -Level Info -Message "Disconnecting existing session before reconnecting..."
        Disconnect-TTTenant
    }

    # Runtime dependency checks (replaces RequiredModules in manifest)
    Assert-TTDependency -Requires Graph
    if (-not $SkipExchangeOnline) {
        Assert-TTDependency -Requires ExchangeOnline
    }

    # WAM / broker error detection pattern. Matches the exception type name,
    # the message text, and known class names from the stack trace.
    $script:WamErrorPattern = 'RuntimeBroker|Object reference|NullReferenceException|WAM|BrokerExtension|IMsalSFHttpClientFactory|BaseAbstractApplicationBuilder|Error Acquiring Token'

    # Default Graph scopes for IR work (delegated modes)
    $graphScopes = @(
        'AuditLog.Read.All'
        'Directory.Read.All'
        'SecurityEvents.Read.All'
        'IdentityRiskEvent.Read.All'
        'IdentityRiskyUser.Read.All'
        'Policy.Read.All'
        'Application.Read.All'
        'User.Read.All'
        'MailboxSettings.Read'
    )

    Write-TTLog -Level Action -Message "Connecting to Graph ($AuthMode) tenant=$TenantId"

    try {
        switch ($AuthMode) {
            'Interactive' {
                try {
                    Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -NoWelcome -ErrorAction Stop
                }
                catch {
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match $script:WamErrorPattern) {
                        Write-TTLog -Level Warn -Message "WAM broker failed for Graph. Falling back to Device Code auth..."
                        Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -UseDeviceCode -NoWelcome -ErrorAction Stop
                    }
                    else { throw }
                }
            }
            'DeviceCode' {
                Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -UseDeviceCode -NoWelcome -ErrorAction Stop
            }
            'AppOnly' {
                if (-not $ClientId -or -not $CertificateThumbprint) {
                    throw "AppOnly requires -ClientId and -CertificateThumbprint."
                }
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
                    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
            }
        }
    }
    catch {
        Write-TTLog -Level Error -Message "Graph connection failed: $($_.Exception.Message)"
        throw
    }

    # Record resolved context from the live connection
    $ctx = Get-MgContext
    $script:TTContext.AuthMethod     = $AuthMode
    $script:TTContext.TenantId       = $ctx.TenantId

    if ($ctx.Account) {
        $script:TTContext.AnalystUpn = $ctx.Account
    }

    # Validate the connection actually works with a real API call.
    # Connect-MgGraph can "succeed" but leave a broken token.
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization' -OutputType PSObject -ErrorAction Stop
        $script:TTContext.GraphConnected = $true

        if ($org.value -and $org.value.Count -gt 0) {
            $primary = $org.value[0].verifiedDomains | Where-Object { $_.isDefault }
            if ($primary) { $script:TTContext.TenantDomain = $primary.name }
        }
        Write-TTLog -Level Success -Message "Graph connected and validated. Tenant=$($script:TTContext.TenantDomain) ($($script:TTContext.TenantId))"
    }
    catch {
        $script:TTContext.GraphConnected = $false
        Write-TTLog -Level Error -Message "Graph connection appeared to succeed but API calls fail: $($_.Exception.Message)"
        Write-TTLog -Level Error -Message "This usually means the MSAL token is broken. Try: close ALL PowerShell sessions, reopen, run the tool fresh."
        throw "Graph connection validation failed. Cannot proceed."
    }

    if (-not $SkipExchangeOnline) {
        Write-TTLog -Level Action -Message "Connecting to Exchange Online..."

        $exoConnected = $false

        # Build base EXO params
        $exoParams = @{
            ShowBanner  = $false
            ErrorAction = 'Stop'
        }

        switch ($AuthMode) {
            'Interactive' {
                # Try Interactive first. If WAM broker crashes (common MSAL
                # conflict), fall back to Device Code automatically.
                $exoParams.UserPrincipalName = $script:TTContext.AnalystUpn
                try {
                    Connect-ExchangeOnline @exoParams
                    $exoConnected = $true
                }
                catch {
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match $script:WamErrorPattern) {
                        Write-TTLog -Level Warn -Message "WAM broker failed for EXO. Falling back to Device Code auth..."
                        $exoParams.Remove('UserPrincipalName')
                        $exoParams.Device = $true
                        try {
                            Connect-ExchangeOnline @exoParams
                            $exoConnected = $true
                        }
                        catch {
                            Write-TTLog -Level Warn -Message "EXO Device Code fallback also failed: $($_.Exception.Message)"
                        }
                    }
                    else {
                        Write-TTLog -Level Warn -Message "EXO connection failed: $errMsg"
                    }
                }
            }
            'DeviceCode' {
                $exoParams.Device = $true
                try {
                    Connect-ExchangeOnline @exoParams
                    $exoConnected = $true
                }
                catch {
                    Write-TTLog -Level Warn -Message "EXO Device Code failed: $($_.Exception.Message)"
                }
            }
            'AppOnly' {
                $exoParams.AppId                 = $ClientId
                $exoParams.CertificateThumbprint = $CertificateThumbprint
                $exoParams.Organization          = $script:TTContext.TenantDomain
                try {
                    Connect-ExchangeOnline @exoParams
                    $exoConnected = $true
                }
                catch {
                    Write-TTLog -Level Warn -Message "EXO AppOnly failed: $($_.Exception.Message)"
                }
            }
        }

        if ($exoConnected) {
            $script:TTContext.ExoConnected = $true
            Write-TTLog -Level Success -Message "Exchange Online connected."
        }
        else {
            Write-TTLog -Level Warn -Message "Exchange Online not connected. Mail-category collectors will be skipped."
        }
    }

    # Persist updated context into case metadata
    $caseJsonPath = Join-Path $script:TTContext.CasePath '_meta\case.json'
    if (Test-Path $caseJsonPath) {
        $caseMeta = Get-Content $caseJsonPath -Raw | ConvertFrom-Json -AsHashtable
        $caseMeta.TenantId      = $script:TTContext.TenantId
        $caseMeta.TenantDomain  = $script:TTContext.TenantDomain
        $caseMeta.AuthMethod    = $AuthMode
        $caseMeta.AnalystUpn    = $script:TTContext.AnalystUpn
        $caseMeta | ConvertTo-Json -Depth 10 | Set-Content -Path $caseJsonPath -Encoding utf8
    }

    return [pscustomobject]@{
        TenantId       = $script:TTContext.TenantId
        TenantDomain   = $script:TTContext.TenantDomain
        AuthMode       = $AuthMode
        GraphConnected = $script:TTContext.GraphConnected
        ExoConnected   = $script:TTContext.ExoConnected
    }
}

function Disconnect-TTTenant {
    <#
    .SYNOPSIS
        Disconnects from Graph and Exchange Online cleanly.
    #>
    [CmdletBinding()]
    param()

    if ($script:TTContext.GraphConnected) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        $script:TTContext.GraphConnected = $false
    }
    if ($script:TTContext.ExoConnected) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        $script:TTContext.ExoConnected = $false
    }
    Write-TTLog -Level Info -Message "Disconnected from tenant services."
}

function Get-TTCaseContext {
    <#
    .SYNOPSIS
        Returns the current module context (case, tenant, auth state).
    #>
    [CmdletBinding()]
    param()
    return [pscustomobject]$script:TTContext
}
