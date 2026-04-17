# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTMailboxForwarding {
    <#
    .SYNOPSIS
        Tenant-wide sweep for mailbox-level forwarding (distinct from inbox rules).
    .DESCRIPTION
        Answers: "What persistence did they leave?" - specifically the
        forwarding paths that LIVE OUTSIDE inbox rules and are commonly
        missed:

          - ForwardingSmtpAddress (user-settable via OWA/Graph)
          - ForwardingAddress     (admin-settable, internal recipient)
          - DeliverToMailboxAndForward flag

        Uses Exchange Online cmdlets. Flags external forwarding against
        verified tenant domains.

    .EXAMPLE
        Get-TTMailboxForwarding

    .EXAMPLE
        Get-TTMailboxForwarding -UserUpn 'finance@contoso.com'
    #>
    [CmdletBinding()]
    param(
        [string[]]$UserUpn
    )

    if (-not $script:TTContext.ExoConnected) {
        throw "Exchange Online not connected. Re-run Connect-TTTenant without -SkipExchangeOnline."
    }

    # Verified domains for external detection
    $verifiedDomains = @()
    if ($script:TTContext.GraphConnected) {
        try {
            $org = Invoke-TTGraphRequest -Uri 'https://graph.microsoft.com/v1.0/organization'
            $verifiedDomains = @($org[0].verifiedDomains | ForEach-Object { $_.name.ToLower() })
        } catch {}
    }

    Write-TTLog -Level Action -Message "Collecting mailbox forwarding configuration..."

    # EXO v3+ returns forwarding properties by default — no -Properties param needed
    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $mailboxes = if ($UserUpn) {
            $UserUpn | ForEach-Object {
                try { Get-Mailbox -Identity $_ -ErrorAction Stop } catch {
                    Write-TTLog -Level Warn -Message "Failed for $_`: $($_.Exception.Message)"
                }
            }
        } else {
            Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        }

        foreach ($mbx in $mailboxes) {
            $hasForwarding = $mbx.ForwardingAddress -or $mbx.ForwardingSmtpAddress
            if (-not $hasForwarding) { continue }  # Only record mailboxes with forwarding set

            $forwardTarget = if ($mbx.ForwardingSmtpAddress) { $mbx.ForwardingSmtpAddress } else { $mbx.ForwardingAddress }
            $isExternal = $false
            if ($forwardTarget -and $forwardTarget.Contains('@')) {
                $targetDomain = $forwardTarget.Split('@')[-1].Split(':')[-1].ToLower().Trim('>')
                if ($verifiedDomains.Count -gt 0 -and $targetDomain -notin $verifiedDomains) {
                    $isExternal = $true
                }
            }

            $results.Add([pscustomobject]@{
                UserPrincipalName          = $mbx.UserPrincipalName
                PrimarySmtpAddress         = $mbx.PrimarySmtpAddress
                RecipientType              = $mbx.RecipientTypeDetails
                ForwardingAddress          = $mbx.ForwardingAddress
                ForwardingSmtpAddress      = $mbx.ForwardingSmtpAddress
                DeliverToMailboxAndForward = $mbx.DeliverToMailboxAndForward
                IsExternalForward          = $isExternal
                WhenChangedUTC             = $mbx.WhenChangedUTC
                WhenCreatedUTC             = $mbx.WhenCreatedUTC
            }) | Out-Null
        }
    }
    catch {
        Write-TTLog -Level Error -Message "Forwarding collection failed: $($_.Exception.Message)"
        throw
    }

    $external = @($results | Where-Object IsExternalForward)
    Write-TTLog -Level Info -Message "Found $($results.Count) mailboxes with forwarding set. $($external.Count) forward externally."

    if ($results.Count -gt 0) {
        Save-TTArtifact -InputObject $results.ToArray() -ArtifactName 'MailboxForwarding' -Category 'Mail' -Format Both | Out-Null
    }
    if ($external.Count -gt 0) {
        Save-TTArtifact -InputObject $external -ArtifactName 'MailboxForwarding-External' -Category 'Mail' -Format Both | Out-Null
    }

    return [pscustomobject]@{
        TotalWithForwarding = $results.Count
        ExternalForwarders  = $external.Count
    }
}
