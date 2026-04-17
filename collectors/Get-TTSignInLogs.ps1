# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTSignInLogs {
    <#
    .SYNOPSIS
        Collects Entra ID sign-in logs (Interactive, NonInteractive, ServicePrincipal).
    .DESCRIPTION
        Phase 1: "How did they get in?"

        Pulls all three sign-in log flavors from the Graph beta endpoint.
        Supports time-window and per-user filtering.

    .EXAMPLE
        # From the launcher menu, or standalone:
        Get-TTSignInLogs -Days 30 -Upn 'cfo@contoso.com'

    .EXAMPLE
        # Absolute time window
        Get-TTSignInLogs -StartUtc '2026-04-10T00:00:00Z' -EndUtc '2026-04-17T00:00:00Z'
    #>
    [CmdletBinding(DefaultParameterSetName='RelativeWindow')]
    param(
        [Parameter(ParameterSetName='RelativeWindow')]
        [ValidateRange(1, 30)]
        [int]$Days = 30,

        [Parameter(ParameterSetName='AbsoluteWindow', Mandatory)]
        [datetime]$StartUtc,

        [Parameter(ParameterSetName='AbsoluteWindow', Mandatory)]
        [datetime]$EndUtc,

        [string]$Upn,

        [ValidateSet('Interactive','NonInteractive','ServicePrincipal','ManagedIdentity','All')]
        [string[]]$Types = @('Interactive','NonInteractive','ServicePrincipal'),

        [switch]$IncludeManagedIdentity
    )

    if (-not $script:TTContext.GraphConnected) { throw "Not connected to Graph. Run Connect-TTTenant first." }

    if ($Types -contains 'All') { $Types = 'Interactive','NonInteractive','ServicePrincipal','ManagedIdentity' }
    if ($IncludeManagedIdentity -and $Types -notcontains 'ManagedIdentity') { $Types += 'ManagedIdentity' }

    if ($PSCmdlet.ParameterSetName -eq 'RelativeWindow') {
        $EndUtc   = [datetime]::UtcNow
        $StartUtc = $EndUtc.AddDays(-$Days)
    }
    $startIso = $StartUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endIso   = $EndUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    Write-TTLog -Level Action -Message "Collecting sign-in logs $startIso -> $endIso (types: $($Types -join ','))"

    $baseUri = 'https://graph.microsoft.com/beta/auditLogs/signIns'
    $typeFilterMap = @{
        'Interactive'      = "signInEventTypes/any(t:t eq 'interactiveUser')"
        'NonInteractive'   = "signInEventTypes/any(t:t eq 'nonInteractiveUser')"
        'ServicePrincipal' = "signInEventTypes/any(t:t eq 'servicePrincipal')"
        'ManagedIdentity'  = "signInEventTypes/any(t:t eq 'managedIdentity')"
    }

    $summary = [System.Collections.Generic.List[object]]::new()

    foreach ($type in $Types) {
        $filterParts = @(
            "createdDateTime ge $startIso and createdDateTime le $endIso",
            $typeFilterMap[$type]
        )
        if ($Upn) { $filterParts += "userPrincipalName eq '$($Upn.Replace("'","''"))'" }
        $filter = ($filterParts -join ' and ')
        $uri = "$baseUri`?`$filter=$([uri]::EscapeDataString($filter))&`$top=1000"

        Write-TTLog -Level Info -Message "  -> Pulling $type sign-ins..."
        try {
            $rows = Invoke-TTGraphRequest -Uri $uri -All
            Write-TTLog -Level Info -Message "     $(@($rows).Count) events"

            Save-TTArtifact -InputObject $rows -ArtifactName "EntraSignInLogs-$type" -Category 'Identity' -Format Both `
                -CollectionMetadata @{ SignInType = $type; WindowStart = $startIso; WindowEnd = $endIso; UpnFilter = $Upn } | Out-Null

            $summary.Add([pscustomobject]@{ Type = $type; Count = @($rows).Count }) | Out-Null
        }
        catch {
            Write-TTLog -Level Error -Message "Failed to collect $type sign-ins: $($_.Exception.Message)"
        }
    }

    return $summary.ToArray()
}
