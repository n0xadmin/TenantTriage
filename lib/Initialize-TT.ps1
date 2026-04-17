<#
.SYNOPSIS
    Initializes the TenantTriage environment. Dot-source this from any script.
.DESCRIPTION
    Loads all shared helpers (logging, Graph wrapper, artifact save, auth)
    and initializes the script-scoped context object.

    Usage from the launcher:
        . "$PSScriptRoot\lib\Initialize-TT.ps1"

    Usage from a standalone collector:
        . "$PSScriptRoot\..\lib\Initialize-TT.ps1"

    Safe to call multiple times — skips if already loaded.
#>

if ($script:TTInitialized) { return }

# Resolve lib root regardless of where we're called from
$script:TTLibRoot = $PSScriptRoot
if (-not (Test-Path (Join-Path $script:TTLibRoot 'Write-TTLog.ps1'))) {
    # Called from outside lib/ — try parent
    $script:TTLibRoot = Join-Path $PSScriptRoot 'lib'
}
if (-not (Test-Path (Join-Path $script:TTLibRoot 'Write-TTLog.ps1'))) {
    throw "Cannot locate TenantTriage lib/ folder. Expected Write-TTLog.ps1 in: $($script:TTLibRoot)"
}

# Project root (one level above lib/)
$script:TTProjectRoot = Split-Path $script:TTLibRoot -Parent

# Module-scoped state — every collector reads from here
$script:TTContext = [ordered]@{
    CaseId           = $null
    CasePath         = $null
    TenantId         = $null
    TenantDomain     = $null
    AnalystUpn       = $null
    AuthMethod       = $null
    StartedUtc       = $null
    GraphConnected   = $false
    ExoConnected     = $false
    ArtifactManifest = [System.Collections.Generic.List[object]]::new()
    ActionLog        = [System.Collections.Generic.List[object]]::new()
}

# Dot-source all helpers in load order
. (Join-Path $script:TTLibRoot 'Assert-TTDependency.ps1')
. (Join-Path $script:TTLibRoot 'Write-TTLog.ps1')
. (Join-Path $script:TTLibRoot 'Invoke-TTGraphRequest.ps1')
. (Join-Path $script:TTLibRoot 'Save-TTArtifact.ps1')
. (Join-Path $script:TTLibRoot 'Case-Management.ps1')
. (Join-Path $script:TTLibRoot 'Connect-TTTenant.ps1')

$script:TTInitialized = $true
