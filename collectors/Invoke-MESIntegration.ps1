# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Test-MESAvailable {
    <#
    .SYNOPSIS
        Checks if Microsoft-Extractor-Suite is installed and importable.
    #>
    [CmdletBinding()]
    param()

    $installed = Get-Module Microsoft-Extractor-Suite -ListAvailable -ErrorAction SilentlyContinue
    if ($installed) {
        $version = $installed.Version | Sort-Object -Descending | Select-Object -First 1
        Import-Module Microsoft-Extractor-Suite -ErrorAction SilentlyContinue
        return [pscustomobject]@{
            Available = $true
            Version   = $version.ToString()
            Message   = "Microsoft-Extractor-Suite v$version loaded."
        }
    }

    return [pscustomobject]@{
        Available = $false
        Version   = $null
        Message   = "Not installed. Run: Install-Module Microsoft-Extractor-Suite -Scope CurrentUser"
    }
}

function Import-MESOutput {
    <#
    .SYNOPSIS
        Imports MES output files into the active TenantTriage case.
    .DESCRIPTION
        MES writes its own output files to its own directory structure.
        This function copies them into our case folder, hashes them,
        and adds them to our manifest so they're included in the
        triage report and case bundle.
    .PARAMETER SourcePath
        Path to the MES output directory (or specific file).
    .PARAMETER Category
        Which case subfolder to put them in (Identity, Mail, Apps, Config).
    .PARAMETER ArtifactName
        Name prefix for the manifest entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$ArtifactName
    )

    if (-not $script:TTContext.CasePath) {
        throw "No active case."
    }

    $destDir = Join-Path $script:TTContext.CasePath $Category
    if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }

    $files = if (Test-Path $SourcePath -PathType Container) {
        Get-ChildItem $SourcePath -File -Recurse
    } elseif (Test-Path $SourcePath) {
        Get-Item $SourcePath
    } else {
        Write-TTLog -Level Warn -Message "MES output path not found: $SourcePath"
        return
    }

    $imported = 0
    foreach ($file in $files) {
        $destFile = Join-Path $destDir $file.Name
        Copy-Item -Path $file.FullName -Destination $destFile -Force

        $hash = (Get-FileHash -Path $destFile -Algorithm SHA256).Hash
        $entry = [ordered]@{
            ArtifactName       = "$ArtifactName-$($file.BaseName)"
            Category           = $Category
            FilePath           = (Resolve-Path $destFile -Relative -RelativeBasePath $script:TTContext.CasePath).Replace('.\', '')
            Format             = $file.Extension.TrimStart('.').ToUpper()
            RowCount           = -1  # unknown for imported files
            SizeBytes          = $file.Length
            SHA256             = $hash
            CollectedUtc       = [datetime]::UtcNow.ToString('o')
            CollectedByAnalyst = $script:TTContext.AnalystUpn
            TenantId           = $script:TTContext.TenantId
            Source             = 'Microsoft-Extractor-Suite'
        }
        $script:TTContext.ArtifactManifest.Add([pscustomobject]$entry) | Out-Null
        $imported++
    }

    Write-TTLog -Level Success -Message "Imported $imported file(s) from MES -> $Category/$ArtifactName"
}

function Invoke-MESEvidenceCollection {
    <#
    .SYNOPSIS
        Runs MES Start-EvidenceCollection and imports results into our case.
    .DESCRIPTION
        This is the "big button" — MES's automated full collection that
        pulls UAL, sign-in logs, audit logs, MFA, OAuth, mailbox rules,
        devices, and more. Output is directed to a subdirectory within
        our case folder, then imported into our manifest.

        After collection, our scoring and analysis layers run on top
        of the imported data.
    #>
    [CmdletBinding()]
    param(
        [int]$Days = 30,
        [string[]]$UserIds
    )

    $mes = Test-MESAvailable
    if (-not $mes.Available) {
        Write-TTLog -Level Error -Message "MES not available. $($mes.Message)"
        return
    }

    if (-not $script:TTContext.CasePath) { throw "No active case." }

    $mesOutputDir = Join-Path $script:TTContext.CasePath '_mes_raw'
    if (-not (Test-Path $mesOutputDir)) { New-Item -Path $mesOutputDir -ItemType Directory -Force | Out-Null }

    $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-dd')
    $endDate   = (Get-Date).ToString('yyyy-MM-dd')

    Write-TTLog -Level Action -Message "Running MES Start-EvidenceCollection ($startDate to $endDate)..."
    Write-TTLog -Level Info -Message "MES output directory: $mesOutputDir"

    try {
        $mesParams = @{
            OutputDir = $mesOutputDir
        }
        Start-EvidenceCollection @mesParams
    }
    catch {
        Write-TTLog -Level Error -Message "MES evidence collection failed: $($_.Exception.Message)"
        return
    }

    # Import all MES output into our case structure
    Write-TTLog -Level Action -Message "Importing MES output into case..."

    $mappings = @(
        @{ Pattern = '*SignInLogs*';            Category = 'Identity'; Name = 'MES-SignInLogs' }
        @{ Pattern = '*AuditLogs*';             Category = 'Identity'; Name = 'MES-AuditLogs' }
        @{ Pattern = '*MFA*';                   Category = 'Identity'; Name = 'MES-MFA' }
        @{ Pattern = '*RiskyUsers*';            Category = 'Identity'; Name = 'MES-RiskyUsers' }
        @{ Pattern = '*RiskyDetections*';       Category = 'Identity'; Name = 'MES-RiskDetections' }
        @{ Pattern = '*ConditionalAccess*';     Category = 'Config';   Name = 'MES-ConditionalAccess' }
        @{ Pattern = '*UnifiedAuditLog*';       Category = 'Mail';     Name = 'MES-UAL' }
        @{ Pattern = '*UAL*';                   Category = 'Mail';     Name = 'MES-UAL' }
        @{ Pattern = '*MailboxRules*';          Category = 'Mail';     Name = 'MES-MailboxRules' }
        @{ Pattern = '*TransportRules*';        Category = 'Mail';     Name = 'MES-TransportRules' }
        @{ Pattern = '*MailboxPermissions*';    Category = 'Mail';     Name = 'MES-MailboxPermissions' }
        @{ Pattern = '*MailboxAudit*';          Category = 'Mail';     Name = 'MES-MailboxAudit' }
        @{ Pattern = '*MessageTrace*';          Category = 'Mail';     Name = 'MES-MessageTrace' }
        @{ Pattern = '*OAuth*';                 Category = 'Apps';     Name = 'MES-OAuth' }
        @{ Pattern = '*Devices*';               Category = 'Devices';  Name = 'MES-Devices' }
        @{ Pattern = '*License*';               Category = 'Config';   Name = 'MES-Licenses' }
        @{ Pattern = '*Users*';                 Category = 'Identity'; Name = 'MES-Users' }
        @{ Pattern = '*Groups*';                Category = 'Identity'; Name = 'MES-Groups' }
        @{ Pattern = '*Roles*';                 Category = 'Identity'; Name = 'MES-Roles' }
        @{ Pattern = '*SecurityDefaults*';      Category = 'Config';   Name = 'MES-SecurityDefaults' }
    )

    $allMesFiles = Get-ChildItem $mesOutputDir -File -Recurse -ErrorAction SilentlyContinue
    $mappedFiles = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($mapping in $mappings) {
        $matched = $allMesFiles | Where-Object { $_.Name -like $mapping.Pattern }
        foreach ($file in $matched) {
            if ($mappedFiles.Add($file.FullName)) {
                Import-MESOutput -SourcePath $file.FullName -Category $mapping.Category -ArtifactName $mapping.Name
            }
        }
    }

    # Catch any unmapped files
    $unmapped = $allMesFiles | Where-Object { $_.FullName -notin $mappedFiles }
    foreach ($file in $unmapped) {
        Import-MESOutput -SourcePath $file.FullName -Category 'Config' -ArtifactName 'MES-Other'
    }

    Write-TTLog -Level Success -Message "MES evidence collection complete. All output imported into case."
}

function Invoke-MESCollector {
    <#
    .SYNOPSIS
        Runs a specific MES function and imports results into our case.
    .DESCRIPTION
        Wrapper for running individual MES collectors with output
        directed into our case folder structure.

    .PARAMETER Function
        The MES function to call (e.g. 'Get-UALGraph', 'Get-MFA').

    .PARAMETER Parameters
        Hashtable of parameters to pass to the MES function.

    .PARAMETER Category
        Case subfolder for the output.

    .PARAMETER ArtifactName
        Name prefix for the manifest.

    .EXAMPLE
        Invoke-MESCollector -Function 'Get-UALGraph' -Parameters @{
            SearchName = 'BEC-Scan'
            StartDate  = '2026-04-01'
            EndDate    = '2026-04-16'
            UserIds    = 'cfo@contoso.com'
        } -Category 'Mail' -ArtifactName 'MES-UAL'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Function,

        [hashtable]$Parameters = @{},

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$ArtifactName
    )

    $mes = Test-MESAvailable
    if (-not $mes.Available) {
        Write-TTLog -Level Error -Message "MES not available. $($mes.Message)"
        return
    }

    if (-not $script:TTContext.CasePath) { throw "No active case." }

    # Create a temp output directory for this MES collector
    $mesOutputDir = Join-Path $script:TTContext.CasePath "_mes_raw\$Function"
    if (-not (Test-Path $mesOutputDir)) { New-Item -Path $mesOutputDir -ItemType Directory -Force | Out-Null }

    # Many MES functions accept -OutputDir
    if (-not $Parameters.ContainsKey('OutputDir')) {
        $Parameters.OutputDir = $mesOutputDir
    }

    Write-TTLog -Level Action -Message "Running MES $Function..."

    try {
        # Call the MES function dynamically
        & $Function @Parameters
    }
    catch {
        Write-TTLog -Level Error -Message "MES $Function failed: $($_.Exception.Message)"
        return
    }

    # Import any output files from the MES run
    $outputFiles = Get-ChildItem $mesOutputDir -File -Recurse -ErrorAction SilentlyContinue
    if ($outputFiles) {
        foreach ($file in $outputFiles) {
            Import-MESOutput -SourcePath $file.FullName -Category $Category -ArtifactName $ArtifactName
        }
        Write-TTLog -Level Success -Message "MES $Function complete. $($outputFiles.Count) file(s) imported."
    }
    else {
        Write-TTLog -Level Warn -Message "MES $Function produced no output files."
    }
}

function Invoke-MESUALCollection {
    <#
    .SYNOPSIS
        Runs MES Get-UALGraph for Unified Audit Log collection.
    .DESCRIPTION
        Replaces our scaffolded Get-TTUnifiedAuditLog with MES's
        battle-tested UAL collector that handles chunking, paging,
        and the 50k result limit properly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SearchName,

        [int]$Days = 30,
        [string[]]$UserIds,
        [string]$Service,
        [string]$Operations,
        [string]$IPAddress
    )

    $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-dd')
    $endDate   = (Get-Date).ToString('yyyy-MM-dd')

    $params = @{
        SearchName = $SearchName
        StartDate  = $startDate
        EndDate    = $endDate
    }
    if ($UserIds)    { $params.UserIds    = $UserIds -join ',' }
    if ($Service)    { $params.Service    = $Service }
    if ($Operations) { $params.Operations = $Operations }
    if ($IPAddress)  { $params.IPAddress  = $IPAddress }

    Invoke-MESCollector -Function 'Get-UALGraph' -Parameters $params -Category 'Mail' -ArtifactName 'MES-UAL'
}

function Invoke-MESMailItemsAccessed {
    <#
    .SYNOPSIS
        Runs MES Get-MailItemsAccessed for mail access scoping.
    .DESCRIPTION
        Replaces our scaffolded Get-TTMailItemsAccessed with MES's
        working implementation. Requires Audit Premium (E5).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserIds,

        [int]$Days = 30
    )

    $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-dd')
    $endDate   = (Get-Date).ToString('yyyy-MM-dd')

    Invoke-MESCollector -Function 'Get-MailItemsAccessed' -Parameters @{
        StartDate = $startDate
        EndDate   = $endDate
        UserIds   = $UserIds
        Output    = 'Yes'
    } -Category 'Mail' -ArtifactName 'MES-MailItemsAccessed'
}

function Invoke-MESMessageTrace {
    <#
    .SYNOPSIS
        Runs MES Get-MessageTraceLog for mail flow analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserIds,

        [int]$Days = 10
    )

    $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-dd')
    $endDate   = (Get-Date).ToString('yyyy-MM-dd')

    Invoke-MESCollector -Function 'Get-MessageTraceLog' -Parameters @{
        StartDate = $startDate
        EndDate   = $endDate
        UserIds   = $UserIds
    } -Category 'Mail' -ArtifactName 'MES-MessageTrace'
}

function Invoke-MESSessions {
    <#
    .SYNOPSIS
        Runs MES Get-Sessions for session-based correlation.
    .DESCRIPTION
        MES's session correlation — maps sign-in sessions to mailbox
        activity using session IDs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserIds,

        [int]$Days = 30
    )

    $startDate = (Get-Date).AddDays(-$Days).ToString('yyyy-MM-dd')
    $endDate   = (Get-Date).ToString('yyyy-MM-dd')

    Invoke-MESCollector -Function 'Get-Sessions' -Parameters @{
        StartDate = $startDate
        EndDate   = $endDate
        UserIds   = $UserIds
    } -Category 'Identity' -ArtifactName 'MES-Sessions'
}
