function Save-TTArtifact {
    <#
    .SYNOPSIS
        Saves an artifact to the case folder with hashing and manifest entry.
    .DESCRIPTION
        Chain-of-custody helper. Every collector calls this to persist its
        output. Produces JSONL (full fidelity) by default, CSV optionally,
        records SHA-256 + row count + collection metadata into the manifest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$ArtifactName,         # e.g. 'EntraSignInLogs-Interactive'

        [Parameter(Mandatory)]
        [string]$Category,             # e.g. 'Identity' | 'Mail' | 'Config'

        [ValidateSet('JSONL','CSV','Both')]
        [string]$Format = 'Both',

        [hashtable]$CollectionMetadata
    )

    if (-not $script:TTContext.CasePath) {
        throw "No active case. Run New-TTCase first."
    }

    $categoryDir = Join-Path $script:TTContext.CasePath $Category
    if (-not (Test-Path $categoryDir)) { New-Item -Path $categoryDir -ItemType Directory -Force | Out-Null }

    $timestamp  = [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $basename   = "$ArtifactName-$timestamp"
    $rowCount   = if ($InputObject) { @($InputObject).Count } else { 0 }
    $files      = @()

    if ($Format -in 'JSONL','Both') {
        $jsonPath = Join-Path $categoryDir "$basename.jsonl"
        $sw = [System.IO.StreamWriter]::new($jsonPath, $false, [System.Text.Encoding]::UTF8)
        try {
            foreach ($obj in $InputObject) {
                $sw.WriteLine(($obj | ConvertTo-Json -Compress -Depth 20))
            }
        } finally { $sw.Dispose() }
        $files += $jsonPath
    }

    if ($Format -in 'CSV','Both' -and $rowCount -gt 0) {
        $csvPath = Join-Path $categoryDir "$basename.csv"
        # Flatten complex objects for CSV (one level deep)
        $InputObject | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        $files += $csvPath
    }

    # Hash and manifest
    foreach ($file in $files) {
        $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
        $entry = [ordered]@{
            ArtifactName       = $ArtifactName
            Category           = $Category
            FilePath           = (Resolve-Path $file -Relative -RelativeBasePath $script:TTContext.CasePath).Replace('.\', '')
            Format             = [System.IO.Path]::GetExtension($file).TrimStart('.').ToUpper()
            RowCount           = $rowCount
            SizeBytes          = (Get-Item $file).Length
            SHA256             = $hash
            CollectedUtc       = [datetime]::UtcNow.ToString('o')
            CollectedByAnalyst = $script:TTContext.AnalystUpn
            TenantId           = $script:TTContext.TenantId
        }
        if ($CollectionMetadata) { $entry.CollectionMetadata = $CollectionMetadata }

        $script:TTContext.ArtifactManifest.Add([pscustomobject]$entry) | Out-Null
    }

    Write-TTLog -Level Success -Message "Saved $ArtifactName ($rowCount rows)" -Data @{ files = $files }

    return [pscustomobject]@{
        ArtifactName = $ArtifactName
        RowCount     = $rowCount
        Files        = $files
    }
}
