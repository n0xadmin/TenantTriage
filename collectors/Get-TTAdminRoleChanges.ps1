# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTAdminRoleChanges {
    <#
    .SYNOPSIS
        Collects Entra / directory role assignment changes and current role state.
    .DESCRIPTION
        Answers: "Did they escalate privileges?"

        Two parts:
          1. Historical: directoryAudits events for role add/remove, group
             membership changes on privileged groups, admin unit changes.
          2. Current state: snapshot of every user currently holding a
             directory role, so you can diff against what the client says
             should be there.

        This does not cover Azure (ARM) role assignments - those require
        /providers/Microsoft.Authorization APIs and are a separate
        collector (scaffolded in Get-TTAzureRoleChanges, coming soon).

    .EXAMPLE
        Get-TTAdminRoleChanges -Days 30

    .EXAMPLE
        Get-TTAdminRoleChanges -Days 7 -SkipCurrentState
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 90)]
        [int]$Days = 30,

        [switch]$SkipCurrentState
    )

    if (-not $script:TTContext.GraphConnected) {
        throw "Not connected to Graph. Run Connect-TTTenant first."
    }

    $startIso = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Activities that represent privilege changes
    $activities = @(
        'Add member to role', 'Remove member from role',
        'Add eligible member (permanent)', 'Add eligible member to role completed (PIM activation)',
        'Add member to role completed (PIM activation)',
        'Add scoped member to role', 'Remove scoped member from role',
        'Add member to group', 'Remove member from group',       # relevant if the group is role-assignable
        'Update role',
        'Add app role assignment grant to user', 'Add app role assignment to service principal'
    )

    $activityFilter = ($activities | ForEach-Object { "activityDisplayName eq '$_'" }) -join ' or '
    $filter = "activityDateTime ge $startIso and ($activityFilter)"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($filter))&`$top=999"

    Write-TTLog -Level Action -Message "Collecting role assignment changes for last $Days days..."

    $events = Invoke-TTGraphRequest -Uri $uri -All

    $flat = foreach ($e in $events) {
        $target    = $e.targetResources | Where-Object { $_.type -eq 'User' -or $_.type -eq 'ServicePrincipal' } | Select-Object -First 1
        $roleRes   = $e.targetResources | Where-Object { $_.type -eq 'Role' } | Select-Object -First 1
        $groupRes  = $e.targetResources | Where-Object { $_.type -eq 'Group' } | Select-Object -First 1

        [pscustomobject]@{
            ActivityDateTime   = $e.activityDateTime
            Activity           = $e.activityDisplayName
            Category           = $e.category
            Result             = $e.result
            ResultReason       = $e.resultReason
            InitiatedByUpn     = $e.initiatedBy.user.userPrincipalName
            InitiatedByAppId   = $e.initiatedBy.app.appId
            InitiatedByAppName = $e.initiatedBy.app.displayName
            InitiatedByIp      = $e.initiatedBy.user.ipAddress
            TargetType         = $target.type
            TargetUpn          = $target.userPrincipalName
            TargetDisplayName  = $target.displayName
            TargetId           = $target.id
            RoleName           = $roleRes.displayName
            GroupName          = $groupRes.displayName
            ModifiedProperties = ($e.targetResources.modifiedProperties | ConvertTo-Json -Compress -Depth 10)
            CorrelationId      = $e.correlationId
        }
    }

    Write-TTLog -Level Info -Message "Found $(@($flat).Count) role/group assignment events."

    if (@($flat).Count -gt 0) {
        Save-TTArtifact -InputObject @($flat) -ArtifactName 'AdminRoleChanges' -Category 'Identity' -Format Both | Out-Null
    }

    # Current directory role holders snapshot
    if (-not $SkipCurrentState) {
        Write-TTLog -Level Action -Message "Snapshotting current directory role assignments..."
        try {
            $roles = Invoke-TTGraphRequest -Uri 'https://graph.microsoft.com/v1.0/directoryRoles' -All
            $currentHolders = [System.Collections.Generic.List[object]]::new()

            foreach ($role in $roles) {
                try {
                    $members = Invoke-TTGraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -All
                    foreach ($m in $members) {
                        $currentHolders.Add([pscustomobject]@{
                            RoleName           = $role.displayName
                            RoleTemplateId     = $role.roleTemplateId
                            MemberType         = $m.'@odata.type'
                            MemberId           = $m.id
                            MemberUpn          = $m.userPrincipalName
                            MemberDisplayName  = $m.displayName
                            AccountEnabled     = $m.accountEnabled
                        }) | Out-Null
                    }
                } catch {
                    Write-TTLog -Level Warn -Message "Could not read members of role $($role.displayName): $($_.Exception.Message)"
                }
            }

            if ($currentHolders.Count -gt 0) {
                Save-TTArtifact -InputObject $currentHolders.ToArray() -ArtifactName 'AdminRoles-CurrentHolders' -Category 'Identity' -Format Both | Out-Null
            }

            Write-TTLog -Level Info -Message "Current role holders: $($currentHolders.Count) assignments across $($roles.Count) active roles."
        }
        catch {
            Write-TTLog -Level Error -Message "Current role state snapshot failed: $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        HistoricalEvents = @($flat).Count
        WindowDays       = $Days
    }
}
