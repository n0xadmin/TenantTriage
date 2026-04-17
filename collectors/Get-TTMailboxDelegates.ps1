# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTMailboxDelegates {
    <#
    .SYNOPSIS
        Collects mailbox delegation, SendAs, SendOnBehalf, and calendar permissions.
    .DESCRIPTION
        Answers: "What privileges/delegations did they add?"

        Captures the four delegation vectors that BEC actors abuse to
        impersonate users or stage data access:

          - FullAccess        (Get-MailboxPermission)
          - SendAs            (Get-RecipientPermission)
          - SendOnBehalf      (mailbox GrantSendOnBehalfTo property)
          - Calendar delegate (Get-MailboxFolderPermission on Calendar)

        Skips built-in/system entries (NT AUTHORITY\SELF, etc.) which are
        noise, not signal.

    .EXAMPLE
        Get-TTMailboxDelegates

    .EXAMPLE
        Get-TTMailboxDelegates -UserUpn 'ceo@contoso.com','cfo@contoso.com'
    #>
    [CmdletBinding()]
    param(
        [string[]]$UserUpn,

        [switch]$SkipCalendar
    )

    if (-not $script:TTContext.ExoConnected) {
        throw "Exchange Online not connected. Re-run Connect-TTTenant without -SkipExchangeOnline."
    }

    Write-TTLog -Level Action -Message "Collecting mailbox delegations (FullAccess, SendAs, SendOnBehalf, Calendar)..."

    # Build the mailbox list
    $mailboxes = if ($UserUpn) {
        $UserUpn | ForEach-Object {
            try { Get-Mailbox -Identity $_ -ErrorAction Stop } catch {
                Write-TTLog -Level Warn -Message "Could not find mailbox: $_"
            }
        }
    } else {
        Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
    }

    $fullAccess    = [System.Collections.Generic.List[object]]::new()
    $sendAs        = [System.Collections.Generic.List[object]]::new()
    $sendOnBehalf  = [System.Collections.Generic.List[object]]::new()
    $calendarPerms = [System.Collections.Generic.List[object]]::new()

    # System entries to filter out
    $systemPrincipals = @(
        'NT AUTHORITY\SELF', 'S-1-5-10', 'Default', 'Anonymous',
        'NT AUTHORITY\SYSTEM', 'NT AUTHORITY\NETWORK SERVICE'
    )

    $counter = 0; $total = $mailboxes.Count

    foreach ($mbx in $mailboxes) {
        $counter++
        if ($counter % 25 -eq 0 -or $counter -eq $total) {
            Write-Progress -Activity 'Collecting delegations' -Status "$counter of $total" -PercentComplete (($counter / $total) * 100)
        }

        # FullAccess
        try {
            $faPerms = Get-MailboxPermission -Identity $mbx.Identity -ErrorAction Stop |
                       Where-Object {
                           $_.User -notin $systemPrincipals -and
                           -not $_.IsInherited -and
                           $_.AccessRights -contains 'FullAccess'
                       }
            foreach ($p in $faPerms) {
                $fullAccess.Add([pscustomobject]@{
                    MailboxUpn   = $mbx.UserPrincipalName
                    Grantee      = "$($p.User)"
                    AccessRights = ($p.AccessRights -join ',')
                    Deny         = $p.Deny
                    InheritanceType = $p.InheritanceType
                }) | Out-Null
            }
        } catch {
            Write-TTLog -Level Warn -Message "FullAccess read failed for $($mbx.UserPrincipalName): $($_.Exception.Message)"
        }

        # SendAs
        try {
            $saPerms = Get-RecipientPermission -Identity $mbx.Identity -ErrorAction Stop |
                       Where-Object {
                           $_.Trustee -notin $systemPrincipals -and
                           $_.AccessControlType -eq 'Allow'
                       }
            foreach ($p in $saPerms) {
                $sendAs.Add([pscustomobject]@{
                    MailboxUpn   = $mbx.UserPrincipalName
                    Grantee      = "$($p.Trustee)"
                    AccessRights = ($p.AccessRights -join ',')
                }) | Out-Null
            }
        } catch {
            Write-TTLog -Level Warn -Message "SendAs read failed for $($mbx.UserPrincipalName): $($_.Exception.Message)"
        }

        # SendOnBehalf - property on the mailbox itself
        if ($mbx.GrantSendOnBehalfTo -and $mbx.GrantSendOnBehalfTo.Count -gt 0) {
            foreach ($grantee in $mbx.GrantSendOnBehalfTo) {
                $sendOnBehalf.Add([pscustomobject]@{
                    MailboxUpn = $mbx.UserPrincipalName
                    Grantee    = "$grantee"
                }) | Out-Null
            }
        }

        # Calendar delegation
        if (-not $SkipCalendar) {
            try {
                $calPath = "$($mbx.PrimarySmtpAddress):\Calendar"
                $calPerms = Get-MailboxFolderPermission -Identity $calPath -ErrorAction Stop |
                            Where-Object {
                                $_.User.DisplayName -notin $systemPrincipals -and
                                $_.User.DisplayName -notin 'Default','Anonymous' -and
                                $_.AccessRights -notcontains 'None'
                            }
                foreach ($p in $calPerms) {
                    $calendarPerms.Add([pscustomobject]@{
                        MailboxUpn      = $mbx.UserPrincipalName
                        Grantee         = "$($p.User.DisplayName)"
                        AccessRights    = ($p.AccessRights -join ',')
                        SharingPermissionFlags = "$($p.SharingPermissionFlags)"
                    }) | Out-Null
                }
            } catch {
                # Calendar may not exist or not be accessible; suppress noisy log
            }
        }
    }

    Write-Progress -Activity 'Collecting delegations' -Completed

    Write-TTLog -Level Info -Message "FullAccess: $($fullAccess.Count), SendAs: $($sendAs.Count), SendOnBehalf: $($sendOnBehalf.Count), Calendar: $($calendarPerms.Count)"

    if ($fullAccess.Count    -gt 0) { Save-TTArtifact -InputObject $fullAccess.ToArray()    -ArtifactName 'MailboxPermissions-FullAccess'   -Category 'Mail' -Format Both | Out-Null }
    if ($sendAs.Count        -gt 0) { Save-TTArtifact -InputObject $sendAs.ToArray()        -ArtifactName 'MailboxPermissions-SendAs'       -Category 'Mail' -Format Both | Out-Null }
    if ($sendOnBehalf.Count  -gt 0) { Save-TTArtifact -InputObject $sendOnBehalf.ToArray()  -ArtifactName 'MailboxPermissions-SendOnBehalf' -Category 'Mail' -Format Both | Out-Null }
    if ($calendarPerms.Count -gt 0) { Save-TTArtifact -InputObject $calendarPerms.ToArray() -ArtifactName 'MailboxPermissions-Calendar'     -Category 'Mail' -Format Both | Out-Null }

    return [pscustomobject]@{
        FullAccess    = $fullAccess.Count
        SendAs        = $sendAs.Count
        SendOnBehalf  = $sendOnBehalf.Count
        Calendar      = $calendarPerms.Count
    }
}
