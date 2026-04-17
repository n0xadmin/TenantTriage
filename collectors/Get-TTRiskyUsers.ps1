# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTRiskyUsers {
    <#
    .SYNOPSIS
        Pulls Entra ID Protection risky users and risk detections.
    .DESCRIPTION
        Answers: "What does Identity Protection think about these sign-ins?"

        Pulls three risk surfaces:
          - /identityProtection/riskyUsers          (users flagged as risky)
          - /identityProtection/riskDetections      (individual risk events)
          - /identityProtection/riskyServicePrincipals (P2, app-level risk)

        Requires Entra ID P2 for full data. P1 gets a subset, free tier
        gets nothing. Test-TTAuditReadiness flags licensing state early.

    .EXAMPLE
        Get-TTRiskyUsers -Days 30
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 90)]
        [int]$Days = 30,

        [switch]$IncludeDismissed
    )

    if (-not $script:TTContext.GraphConnected) {
        throw "Not connected to Graph. Run Connect-TTTenant first."
    }

    $startIso = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    Write-TTLog -Level Action -Message "Collecting risky users..."

    # Risky users (state-based - current risk level, not historical events)
    $riskyUsers = @()
    try {
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=500"
        if (-not $IncludeDismissed) {
            $uri += "&`$filter=riskState ne 'dismissed' and riskState ne 'remediated'"
        }
        $riskyUsers = Invoke-TTGraphRequest -Uri $uri -All
        Write-TTLog -Level Info -Message "Risky users: $(@($riskyUsers).Count)"
        if (@($riskyUsers).Count -gt 0) {
            Save-TTArtifact -InputObject $riskyUsers -ArtifactName 'RiskyUsers' -Category 'Identity' -Format Both | Out-Null
        }
    }
    catch {
        Write-TTLog -Level Warn -Message "Risky users endpoint failed (P2 required?): $($_.Exception.Message)"
    }

    # Risk detections (event stream, filter by time)
    $detections = @()
    try {
        $filter = "detectedDateTime ge $startIso"
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=$([uri]::EscapeDataString($filter))&`$top=500"
        $detections = Invoke-TTGraphRequest -Uri $uri -All
        Write-TTLog -Level Info -Message "Risk detections (last $Days days): $(@($detections).Count)"
        if (@($detections).Count -gt 0) {
            Save-TTArtifact -InputObject $detections -ArtifactName 'RiskDetections' -Category 'Identity' -Format Both | Out-Null
        }
    }
    catch {
        Write-TTLog -Level Warn -Message "Risk detections endpoint failed: $($_.Exception.Message)"
    }

    # Risky service principals (P2 / workload identity premium)
    $riskySPs = @()
    try {
        $uri = 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals?$top=500'
        $riskySPs = Invoke-TTGraphRequest -Uri $uri -All
        Write-TTLog -Level Info -Message "Risky service principals: $(@($riskySPs).Count)"
        if (@($riskySPs).Count -gt 0) {
            Save-TTArtifact -InputObject $riskySPs -ArtifactName 'RiskyServicePrincipals' -Category 'Identity' -Format Both | Out-Null
        }
    }
    catch {
        Write-TTLog -Level Warn -Message "Risky service principals endpoint failed (Workload ID premium required): $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        RiskyUsers              = @($riskyUsers).Count
        RiskDetections          = @($detections).Count
        RiskyServicePrincipals  = @($riskySPs).Count
    }
}
