function New-TTCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClientName,

        [Parameter(Mandatory)]
        [string]$IncidentRef,

        [string]$Root = (Join-Path $env:USERPROFILE 'TenantTriage-Cases'),

        [string]$AnalystName = $env:USERNAME,

        [string]$Notes
    )

    $safeName     = ($ClientName -replace '[^a-zA-Z0-9_-]', '_')
    $safeIncident = ($IncidentRef -replace '[^a-zA-Z0-9_-]', '_')
    $timestamp    = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $caseId       = "$timestamp-$safeName-$safeIncident"
    $casePath     = Join-Path $Root $caseId

    if (Test-Path $casePath) { throw "Case path already exists: $casePath" }

    foreach ($sub in '_meta','Identity','Mail','Apps','Config','Devices') {
        New-Item -Path (Join-Path $casePath $sub) -ItemType Directory -Force | Out-Null
    }

    $script:TTContext.CaseId           = $caseId
    $script:TTContext.CasePath         = $casePath
    $script:TTContext.TenantId         = $null
    $script:TTContext.TenantDomain     = $null
    $script:TTContext.AnalystUpn       = $AnalystName
    $script:TTContext.AuthMethod       = $null
    $script:TTContext.StartedUtc       = [datetime]::UtcNow
    $script:TTContext.GraphConnected   = $false
    $script:TTContext.ExoConnected     = $false
    $script:TTContext.ArtifactManifest = [System.Collections.Generic.List[object]]::new()
    $script:TTContext.ActionLog        = [System.Collections.Generic.List[object]]::new()

    $caseMeta = [ordered]@{
        CaseId      = $caseId
        ClientName  = $ClientName
        IncidentRef = $IncidentRef
        AnalystName = $AnalystName
        MachineName = [System.Environment]::MachineName
        ToolVersion = '0.3.0'
        StartedUtc  = $script:TTContext.StartedUtc.ToString('o')
        Notes       = $Notes
    }
    $caseMeta | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $casePath '_meta\case.json') -Encoding utf8

    Write-TTLog -Level Success -Message "Case initialized: $caseId"
    Write-TTLog -Level Info    -Message "Case path: $casePath"

    return [pscustomobject]@{ CaseId = $caseId; CasePath = $casePath }
}

function Complete-TTCase {
    [CmdletBinding()]
    param(
        [switch]$Zip,
        [switch]$KeepConnection
    )

    if (-not $script:TTContext.CaseId) { throw "No active case." }

    $manifest = [ordered]@{
        CaseId        = $script:TTContext.CaseId
        TenantId      = $script:TTContext.TenantId
        TenantDomain  = $script:TTContext.TenantDomain
        AnalystUpn    = $script:TTContext.AnalystUpn
        AuthMethod    = $script:TTContext.AuthMethod
        StartedUtc    = $script:TTContext.StartedUtc.ToString('o')
        CompletedUtc  = [datetime]::UtcNow.ToString('o')
        MachineName   = [System.Environment]::MachineName
        ToolVersion   = '0.3.0'
        ArtifactCount = $script:TTContext.ArtifactManifest.Count
        ActionCount   = $script:TTContext.ActionLog.Count
        Artifacts     = $script:TTContext.ArtifactManifest.ToArray()
    }

    $manifestPath = Join-Path $script:TTContext.CasePath '_meta\manifest.json'
    $manifest | ConvertTo-Json -Depth 20 | Set-Content -Path $manifestPath -Encoding utf8

    $manifestHash = (Get-FileHash -Path $manifestPath -Algorithm SHA256).Hash
    $manifestHash | Set-Content -Path (Join-Path $script:TTContext.CasePath '_meta\manifest.sha256') -Encoding utf8

    Write-TTLog -Level Success -Message "Manifest written ($($manifest.ArtifactCount) artifacts)"
    Write-TTLog -Level Info    -Message "SHA-256: $manifestHash"

    $result = [pscustomobject]@{
        CaseId        = $script:TTContext.CaseId
        CasePath      = $script:TTContext.CasePath
        ManifestPath  = $manifestPath
        ManifestHash  = $manifestHash
        ArtifactCount = $manifest.ArtifactCount
        ZipPath       = $null
    }

    if ($Zip) {
        $zipPath = "$($script:TTContext.CasePath).zip"
        Write-TTLog -Level Action -Message "Zipping case bundle..."
        Compress-Archive -Path "$($script:TTContext.CasePath)\*" -DestinationPath $zipPath -Force
        $zipHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
        "$zipHash  $(Split-Path $zipPath -Leaf)" | Set-Content -Path "$zipPath.sha256" -Encoding utf8
        Write-TTLog -Level Success -Message "Bundle: $zipPath (SHA-256: $zipHash)"
        $result.ZipPath = $zipPath
    }

    if (-not $KeepConnection) { Disconnect-TTTenant }

    $script:TTContext.CaseId   = $null
    $script:TTContext.CasePath = $null

    return $result
}

function Get-TTCaseContext {
    [CmdletBinding()]
    param()
    return [pscustomobject]$script:TTContext
}
