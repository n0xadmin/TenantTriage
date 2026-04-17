function Assert-TTDependency {
    <#
    .SYNOPSIS
        Runtime dependency check. Called by commands that need Graph or EXO.
    .DESCRIPTION
        Replaces RequiredModules in the manifest so the module loads cleanly
        even when dependencies aren't installed. Checks happen at the point
        of actual need, not at import time.

        This means:
          - Smoke tests run with zero dependencies
          - Graph-only collectors work without EXO installed
          - EXO collectors give a clear error naming the missing module
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Graph','ExchangeOnline')]
        [string[]]$Requires
    )

    foreach ($dep in $Requires) {
        switch ($dep) {
            'Graph' {
                if (-not (Get-Module Microsoft.Graph.Authentication -ListAvailable)) {
                    throw "Microsoft.Graph.Authentication module not found. Install it:`n  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -MinimumVersion 2.15.0"
                }
            }
            'ExchangeOnline' {
                if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
                    throw "ExchangeOnlineManagement module not found. Install it:`n  Install-Module ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion 3.4.0"
                }
            }
        }
    }
}
