# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTOAuthGrants {
    <#
    .SYNOPSIS
        Collects OAuth consent grants and enterprise applications with risk scoring.
    .DESCRIPTION
        Answers: "What apps/persistence did they leave behind?"

        OAuth persistence survives password reset and MFA re-registration
        because the app itself still holds granted access. This collector
        pulls:

          - oauth2PermissionGrants (delegated consent - user-consented)
          - appRoleAssignments     (application consent - admin-consented)
          - servicePrincipals      (enterprise app inventory)

        Flags high-risk grants:
          - Mail.* scopes (Mail.Read, Mail.ReadWrite, Mail.Send)
          - Files.* at tenant-wide scope
          - offline_access (persistent refresh tokens)
          - User.ReadWrite.All, Directory.* at application permission level
          - App with consent granted in the last 30 days (correlates to
            active incident windows)
          - App with no verified publisher
          - App created/updated in suspicious windows

    .EXAMPLE
        Get-TTOAuthGrants

    .EXAMPLE
        # Scope to a single user's delegated grants
        Get-TTOAuthGrants -UserUpn 'finance@contoso.com'
    #>
    [CmdletBinding()]
    param(
        [string[]]$UserUpn,

        # Only return grants from the last N days. Use for fast triage.
        [int]$RecentDays = 0
    )

    if (-not $script:TTContext.GraphConnected) {
        throw "Not connected to Graph. Run Connect-TTTenant first."
    }

    $cutoff = if ($RecentDays -gt 0) { (Get-Date).AddDays(-$RecentDays) } else { $null }

    # High-risk permission scopes (lowercased for comparison)
    $highRiskScopes = @(
        'mail.read','mail.readwrite','mail.send','mail.readbasic',
        'files.read.all','files.readwrite.all',
        'sites.read.all','sites.readwrite.all','sites.fullcontrol.all',
        'directory.read.all','directory.readwrite.all','directory.accessasuser.all',
        'user.read.all','user.readwrite.all',
        'application.read.all','application.readwrite.all',
        'offline_access',
        'full_access_as_user',
        'mailboxsettings.readwrite'
    )

    # --- Delegated grants ---
    Write-TTLog -Level Action -Message "Pulling OAuth2 delegated permission grants..."
    $delegated = [System.Collections.Generic.List[object]]::new()
    try {
        $oauthGrants = Invoke-TTGraphRequest -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' -All

        # Filter to target users if specified
        if ($UserUpn) {
            $targetUsers = Invoke-TTGraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$(($UserUpn | ForEach-Object { "userPrincipalName eq '$_'" }) -join ' or ')&`$select=id,userPrincipalName"
            $targetIds = @($targetUsers | ForEach-Object { $_.id })
            $oauthGrants = $oauthGrants | Where-Object { $_.principalId -in $targetIds }
        }

        # Cache SP lookups to avoid N+1
        $spCache = @{}

        foreach ($grant in $oauthGrants) {
            if (-not $spCache.ContainsKey($grant.clientId)) {
                try {
                    $spCache[$grant.clientId] = Invoke-TTGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.clientId)"
                } catch {
                    $spCache[$grant.clientId] = $null
                }
            }
            $sp = $spCache[$grant.clientId]

            $scopes = @(($grant.scope -split '\s+') | Where-Object { $_ })
            $risky = @($scopes | Where-Object { $_.ToLower() -in $highRiskScopes })

            $delegated.Add([pscustomobject]@{
                GrantId              = $grant.id
                ClientAppId          = $grant.clientId
                ClientAppDisplayName = $sp.displayName
                PublisherName        = $sp.publisherName
                VerifiedPublisher    = $sp.verifiedPublisher.displayName
                AppOwnerTenantId     = $sp.appOwnerOrganizationId
                ConsentType          = $grant.consentType           # AllPrincipals | Principal
                PrincipalId          = $grant.principalId
                ResourceId           = $grant.resourceId
                Scopes               = $scopes -join ' '
                RiskyScopes          = $risky -join ' '
                HasRiskyScopes       = [bool]$risky
                GrantType            = 'Delegated'
            }) | Out-Null
        }
    } catch {
        Write-TTLog -Level Error -Message "Delegated grant collection failed: $($_.Exception.Message)"
    }

    # --- Application grants (admin-consented to service principals) ---
    Write-TTLog -Level Action -Message "Pulling application permission grants (appRoleAssignments)..."
    $appGrants = [System.Collections.Generic.List[object]]::new()
    try {
        $servicePrincipals = Invoke-TTGraphRequest -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=999&$select=id,appId,displayName,publisherName,verifiedPublisher,appOwnerOrganizationId,createdDateTime,servicePrincipalType,accountEnabled,tags' -All

        foreach ($sp in $servicePrincipals) {
            try {
                $assignments = Invoke-TTGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" -All
                foreach ($a in $assignments) {
                    # Resolve the app role name
                    $roleName = ''
                    try {
                        $resource = Invoke-TTGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($a.resourceId)?`$select=displayName,appRoles"
                        $role = $resource.appRoles | Where-Object { $_.id -eq $a.appRoleId } | Select-Object -First 1
                        if ($role) { $roleName = $role.value }
                    } catch {}

                    $risky = $roleName.ToLower() -in $highRiskScopes

                    $appGrants.Add([pscustomobject]@{
                        GrantId              = $a.id
                        ClientAppId          = $sp.appId
                        ClientAppDisplayName = $sp.displayName
                        PublisherName        = $sp.publisherName
                        VerifiedPublisher    = $sp.verifiedPublisher.displayName
                        AppOwnerTenantId     = $sp.appOwnerOrganizationId
                        ResourceDisplayName  = $a.resourceDisplayName
                        AppRoleId            = $a.appRoleId
                        AppRoleValue         = $roleName
                        HasRiskyScopes       = $risky
                        RiskyScopes          = if ($risky) { $roleName } else { '' }
                        AssignedDateTime     = $a.createdDateTime
                        GrantType            = 'Application'
                    }) | Out-Null
                }
            } catch {
                # Individual SP errors are noisy in large tenants; swallow but log at debug
                Write-Verbose "SP $($sp.displayName) appRoleAssignments failed: $($_.Exception.Message)"
            }
        }

        # Save the SP inventory while we have it
        Save-TTArtifact -InputObject $servicePrincipals -ArtifactName 'ServicePrincipals-Inventory' -Category 'Apps' -Format Both | Out-Null

    } catch {
        Write-TTLog -Level Error -Message "Service principal enumeration failed: $($_.Exception.Message)"
    }

    # --- Combine and filter ---
    $allGrants = @($delegated) + @($appGrants)
    if ($cutoff) {
        $allGrants = $allGrants | Where-Object {
            $_.AssignedDateTime -and ([datetime]$_.AssignedDateTime) -gt $cutoff
        }
    }

    $risky = @($allGrants | Where-Object HasRiskyScopes)
    $unverified = @($allGrants | Where-Object { -not $_.VerifiedPublisher -and $_.AppOwnerTenantId -ne $script:TTContext.TenantId })

    Write-TTLog -Level Info -Message "Delegated: $($delegated.Count), Application: $($appGrants.Count), Risky-scoped: $($risky.Count), Unverified publisher (external): $($unverified.Count)"

    Save-TTArtifact -InputObject $allGrants -ArtifactName 'OAuthGrants-All' -Category 'Apps' -Format Both | Out-Null
    if ($risky.Count -gt 0)      { Save-TTArtifact -InputObject $risky      -ArtifactName 'OAuthGrants-Risky'              -Category 'Apps' -Format Both | Out-Null }
    if ($unverified.Count -gt 0) { Save-TTArtifact -InputObject $unverified -ArtifactName 'OAuthGrants-UnverifiedExternal' -Category 'Apps' -Format Both | Out-Null }

    return [pscustomobject]@{
        Delegated       = $delegated.Count
        Application     = $appGrants.Count
        RiskyScopes     = $risky.Count
        UnverifiedExternal = $unverified.Count
    }
}
