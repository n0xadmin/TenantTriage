# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTAuthMethodChanges {
    <#
    .SYNOPSIS
        Detects MFA / security-info tampering from Entra audit logs.
    .DESCRIPTION
        Answers: "Did they tamper with the user's authentication methods?"

        Filters the Entra directoryAudits feed to authentication method
        lifecycle events. Attackers routinely:
          - Register their own authenticator app as a new method
          - Delete the legitimate user's existing method
          - Change the default MFA method

        Also captures the current auth methods state for each target user
        so you can diff "what methods does this user have now?" against
        the change log.

        Time window defaults to 30 days (standard Entra audit retention
        ceiling without Log Analytics forwarding).

    .PARAMETER Days
        Lookback window. Default 30.

    .PARAMETER UserUpn
        Filter to specific user(s). Omit for tenant-wide.

    .EXAMPLE
        Get-TTAuthMethodChanges -Days 7

    .EXAMPLE
        Get-TTAuthMethodChanges -UserUpn 'cfo@contoso.com' -Days 30
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 90)]
        [int]$Days = 30,

        [string[]]$UserUpn
    )

    if (-not $script:TTContext.GraphConnected) {
        throw "Not connected to Graph. Run Connect-TTTenant first."
    }

    $startIso = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Auth-method-related operations in the Entra directoryAudits log.
    # These are the loggedByService='Authentication Methods' entries plus
    # User management entries that touch security info.
    $authCategory = "loggedByService eq 'Authentication Methods' or loggedByService eq 'Core Directory'"
    $authActivity = "activityDisplayName eq 'User registered security info' or " +
                    "activityDisplayName eq 'User deleted security info' or " +
                    "activityDisplayName eq 'User changed default security info' or " +
                    "activityDisplayName eq 'Admin registered security info' or " +
                    "activityDisplayName eq 'Admin deleted security info' or " +
                    "activityDisplayName eq 'Reset user password' or " +
                    "activityDisplayName eq 'Update user' or " +
                    "activityDisplayName eq 'Disable Strong Authentication' or " +
                    "activityDisplayName eq 'Enable Strong Authentication'"

    $filter = "activityDateTime ge $startIso and ($authActivity)"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($filter))&`$top=999"

    Write-TTLog -Level Action -Message "Collecting auth method / security-info changes for last $Days days..."

    $events = Invoke-TTGraphRequest -Uri $uri -All

    # Filter to target users if scoped
    if ($UserUpn) {
        $upnLower = $UserUpn | ForEach-Object { $_.ToLower() }
        $events = $events | Where-Object {
            $target = $_.targetResources | Where-Object { $_.type -eq 'User' } | Select-Object -First 1
            $target -and $target.userPrincipalName.ToLower() -in $upnLower
        }
    }

    # Flatten to a review-friendly shape
    $flat = foreach ($e in $events) {
        $target = $e.targetResources | Where-Object { $_.type -eq 'User' } | Select-Object -First 1
        [pscustomobject]@{
            ActivityDateTime      = $e.activityDateTime
            Activity              = $e.activityDisplayName
            LoggedByService       = $e.loggedByService
            Result                = $e.result
            ResultReason          = $e.resultReason
            InitiatedByUpn        = $e.initiatedBy.user.userPrincipalName
            InitiatedByAppId      = $e.initiatedBy.app.appId
            InitiatedByAppName    = $e.initiatedBy.app.displayName
            InitiatedByIp         = $e.initiatedBy.user.ipAddress
            TargetUpn             = $target.userPrincipalName
            TargetUserId          = $target.id
            TargetDisplayName     = $target.displayName
            ModifiedProperties    = ($e.targetResources.modifiedProperties | ConvertTo-Json -Compress -Depth 10)
            CorrelationId         = $e.correlationId
            AdditionalDetails     = ($e.additionalDetails | ConvertTo-Json -Compress -Depth 5)
        }
    }

    Write-TTLog -Level Info -Message "Found $(@($flat).Count) auth method / security-info events."

    # Highlight self-service method registrations (InitiatedBy == Target, most suspicious)
    $selfRegistrations = @($flat | Where-Object {
        $_.InitiatedByUpn -and $_.TargetUpn -and
        $_.InitiatedByUpn -eq $_.TargetUpn -and
        $_.Activity -match 'registered security info'
    })

    if (@($flat).Count -gt 0) {
        Save-TTArtifact -InputObject @($flat) -ArtifactName 'AuthMethodChanges' -Category 'Identity' -Format Both | Out-Null
    }
    if ($selfRegistrations.Count -gt 0) {
        Save-TTArtifact -InputObject $selfRegistrations -ArtifactName 'AuthMethodChanges-SelfRegistered' -Category 'Identity' -Format Both | Out-Null
    }

    # --- Current state snapshot for target users ---
    if ($UserUpn) {
        Write-TTLog -Level Action -Message "Snapshotting current auth methods for $(@($UserUpn).Count) users..."
        $currentMethods = [System.Collections.Generic.List[object]]::new()
        foreach ($upn in $UserUpn) {
            try {
                $methods = Invoke-TTGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$upn/authentication/methods" -All
                foreach ($m in $methods) {
                    $currentMethods.Add([pscustomobject]@{
                        UserPrincipalName = $upn
                        MethodType        = $m.'@odata.type'
                        Id                = $m.id
                        DisplayName       = $m.displayName
                        PhoneType         = $m.phoneType
                        PhoneNumber       = $m.phoneNumber
                        EmailAddress      = $m.emailAddress
                        CreatedDateTime   = $m.createdDateTime
                    }) | Out-Null
                }
            } catch {
                Write-TTLog -Level Warn -Message "Could not read auth methods for $upn`: $($_.Exception.Message)"
            }
        }
        if ($currentMethods.Count -gt 0) {
            Save-TTArtifact -InputObject $currentMethods.ToArray() -ArtifactName 'AuthMethods-Current' -Category 'Identity' -Format Both | Out-Null
        }
    }

    return [pscustomobject]@{
        TotalEvents          = @($flat).Count
        SelfRegistrations    = $selfRegistrations.Count
        WindowDays           = $Days
    }
}
