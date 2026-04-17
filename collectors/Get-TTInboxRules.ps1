# Auto-load shared libraries if not already loaded (enables standalone execution)
if (-not $script:TTInitialized) { . (Join-Path $PSScriptRoot '..\lib\Initialize-TT.ps1') }

function Get-TTInboxRules {
    <#
    .SYNOPSIS
        Tenant-wide collection of inbox rules with hidden-rule detection and
        suspicious-pattern scoring.
    .DESCRIPTION
        Answers: "What persistence did they leave in mailboxes?"

        Collects inbox rules via Microsoft Graph (clean, parallelizable, no
        per-thread EXO session needed). For each rule, scores suspicion
        based on patterns seen in real BEC cases:

          - Moves mail to RSS Feeds, Conversation History, Notes, Archive,
            Junk Email, or Deleted Items (classic hiding spots)
          - Deletes mail matching sensitive keywords (invoice, payment,
            wire, bank, routing, account)
          - Forwards externally (outside verified tenant domains)
          - Rule name is empty, single-char, or a punctuation glyph
            (., ., .., -, space) - a hallmark of BEC persistence
          - Marks mail as read before filing (common attacker pattern)

        Hidden rule detection: pulls rules via Graph AND (when EXO is
        connected) via Get-InboxRule -IncludeHidden to catch rules set via
        MAPI with PR_RULE_MSG_STATE flag ST_HIDDEN, which don't appear in
        the normal Graph API results.

    .PARAMETER UserUpn
        One or more UPNs to scope collection. Omit for tenant-wide sweep.

    .PARAMETER IncludeHiddenRules
        Additionally query EXO Get-InboxRule -IncludeHidden. Requires EXO
        connection. Slower (per-mailbox EXO call) but catches custom-forms
        injection and hidden-rule persistence.

    .PARAMETER ThrottleLimit
        Parallel mailbox queries. Default 8. Raise cautiously - Graph
        throttles aggressively on large tenants.

    .EXAMPLE
        # Fast tenant-wide triage, Graph only
        Get-TTInboxRules

    .EXAMPLE
        # Deep scan including hidden rules for known-compromised users
        Get-TTInboxRules -UserUpn 'cfo@contoso.com','ap@contoso.com' -IncludeHiddenRules
    #>
    [CmdletBinding()]
    param(
        [string[]]$UserUpn,

        [switch]$IncludeHiddenRules,

        [ValidateRange(1, 20)]
        [int]$ThrottleLimit = 8
    )

    if (-not $script:TTContext.GraphConnected) {
        throw "Not connected to Graph. Run Connect-TTTenant first."
    }

    # Build the user list
    if ($UserUpn) {
        $users = $UserUpn | ForEach-Object {
            [pscustomobject]@{ userPrincipalName = $_; id = $_ }
        }
    } else {
        Write-TTLog -Level Action -Message "Enumerating mailbox-enabled users..."
        $users = Invoke-TTGraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,mail,accountEnabled&`$top=999" -All |
                 Where-Object { $_.mail -and $_.accountEnabled }
        Write-TTLog -Level Info -Message "Found $($users.Count) mailbox-enabled users"
    }

    # Get verified tenant domains for external-forwarding detection
    $verifiedDomains = @()
    try {
        $org = Invoke-TTGraphRequest -Uri 'https://graph.microsoft.com/v1.0/organization'
        $verifiedDomains = @($org[0].verifiedDomains | ForEach-Object { $_.name.ToLower() })
    } catch {
        Write-TTLog -Level Warn -Message "Could not resolve verified domains - external forwarding detection disabled."
    }

    $allRules = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $errors   = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $counter  = 0
    $total    = $users.Count

    Write-TTLog -Level Action -Message "Collecting inbox rules from $total mailboxes..."

    # Sequential path with progress. Parallel is planned for v0.3 - see README.
    foreach ($user in $users) {
        $counter++
        if ($counter % 25 -eq 0 -or $counter -eq $total) {
            Write-Progress -Activity 'Collecting inbox rules' -Status "$counter of $total" -PercentComplete (($counter / $total) * 100)
        }

        try {
            $uri = "https://graph.microsoft.com/v1.0/users/$($user.id)/mailFolders/inbox/messageRules"
            $rules = Invoke-TTGraphRequest -Uri $uri -All

            foreach ($rule in $rules) {
                $scored = Get-TTRuleSuspicionScore -Rule $rule -VerifiedDomains $verifiedDomains

                $enriched = [pscustomobject]@{
                    UserPrincipalName = $user.userPrincipalName
                    UserId            = $user.id
                    RuleId            = $rule.id
                    RuleName          = $rule.displayName
                    IsEnabled         = $rule.isEnabled
                    Sequence          = $rule.sequence
                    Conditions        = $rule.conditions
                    Actions           = $rule.actions
                    Exceptions        = $rule.exceptions
                    Source            = 'Graph'
                    SuspicionScore    = $scored.Score
                    SuspicionReasons  = $scored.Reasons -join ' | '
                }
                $allRules.Add($enriched) | Out-Null
            }
        }
        catch {
            $errors.Add([pscustomobject]@{
                UserPrincipalName = $user.userPrincipalName
                Error             = $_.Exception.Message
            }) | Out-Null
        }
    }

    Write-Progress -Activity 'Collecting inbox rules' -Completed

    # Hidden rule pass via EXO (if requested and connected)
    if ($IncludeHiddenRules) {
        if (-not $script:TTContext.ExoConnected) {
            Write-TTLog -Level Warn -Message "IncludeHiddenRules requested but EXO not connected; skipping hidden rule sweep."
        } else {
            Write-TTLog -Level Action -Message "Scanning for hidden rules via EXO Get-InboxRule -IncludeHidden..."
            $hiddenCounter = 0
            foreach ($user in $users) {
                $hiddenCounter++
                if ($hiddenCounter % 25 -eq 0 -or $hiddenCounter -eq $total) {
                    Write-Progress -Activity 'Hidden rule scan' -Status "$hiddenCounter of $total" -PercentComplete (($hiddenCounter / $total) * 100)
                }
                try {
                    $hiddenRules = Get-InboxRule -Mailbox $user.userPrincipalName -IncludeHidden -ErrorAction Stop
                    foreach ($rule in $hiddenRules) {
                        # Match against Graph results to flag rules that appear in EXO but not Graph = truly hidden
                        $existsInGraph = $allRules | Where-Object {
                            $_.UserPrincipalName -eq $user.userPrincipalName -and $_.RuleName -eq $rule.Name
                        }
                        if (-not $existsInGraph) {
                            $allRules.Add([pscustomobject]@{
                                UserPrincipalName = $user.userPrincipalName
                                UserId            = $user.id
                                RuleId            = $rule.Identity
                                RuleName          = $rule.Name
                                IsEnabled         = $rule.Enabled
                                Sequence          = $rule.Priority
                                Conditions        = $rule.Description
                                Actions           = "DeleteMessage=$($rule.DeleteMessage), ForwardTo=$($rule.ForwardTo -join ','), MoveToFolder=$($rule.MoveToFolder)"
                                Exceptions        = $null
                                Source            = 'EXO-Hidden'
                                SuspicionScore    = 10   # Hidden by definition = maximum suspicion
                                SuspicionReasons  = 'HIDDEN_RULE: Present in EXO but not Graph - classic MAPI-set persistence'
                            }) | Out-Null
                        }
                    }
                } catch {
                    $errors.Add([pscustomobject]@{
                        UserPrincipalName = $user.userPrincipalName
                        Error             = "Hidden rule scan: $($_.Exception.Message)"
                    }) | Out-Null
                }
            }
            Write-Progress -Activity 'Hidden rule scan' -Completed
        }
    }

    $rulesArray = $allRules.ToArray()
    $suspicious = @($rulesArray | Where-Object { $_.SuspicionScore -ge 3 })

    Write-TTLog -Level Info -Message "Collected $($rulesArray.Count) rules total. $($suspicious.Count) flagged as suspicious (score >= 3)."
    if ($errors.Count -gt 0) {
        Write-TTLog -Level Warn -Message "$($errors.Count) mailboxes errored during collection - see errors artifact."
    }

    Save-TTArtifact -InputObject $rulesArray -ArtifactName 'InboxRules-All' -Category 'Mail' -Format Both | Out-Null

    if ($suspicious.Count -gt 0) {
        Save-TTArtifact -InputObject $suspicious -ArtifactName 'InboxRules-Suspicious' -Category 'Mail' -Format Both | Out-Null
    }

    if ($errors.Count -gt 0) {
        Save-TTArtifact -InputObject $errors.ToArray() -ArtifactName 'InboxRules-Errors' -Category 'Mail' -Format JSONL | Out-Null
    }

    return [pscustomobject]@{
        TotalRules      = $rulesArray.Count
        SuspiciousRules = $suspicious.Count
        UsersScanned    = $total
        Errors          = $errors.Count
    }
}

function Get-TTRuleSuspicionScore {
    <#
    .SYNOPSIS
        Private scorer for inbox rules. Returns score (0-10) + reason codes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [string[]]$VerifiedDomains = @()
    )

    $score = 0
    $reasons = [System.Collections.Generic.List[string]]::new()

    $ruleName = "$($Rule.displayName)".Trim()
    $actionsJson = $Rule.actions | ConvertTo-Json -Compress -Depth 10 -ErrorAction SilentlyContinue
    $conditionsJson = $Rule.conditions | ConvertTo-Json -Compress -Depth 10 -ErrorAction SilentlyContinue

    # Suspicious rule names
    if ([string]::IsNullOrWhiteSpace($ruleName) -or $ruleName.Length -le 2) {
        $score += 3
        $reasons.Add("SHORT_OR_EMPTY_NAME: '$ruleName'") | Out-Null
    }
    if ($ruleName -match '^[\s\.\-_,]+$') {
        $score += 3
        $reasons.Add('PUNCTUATION_ONLY_NAME') | Out-Null
    }

    # Classic hiding folders
    $hidingFolders = 'RSS Feeds','RSS Subscriptions','Conversation History','Notes','Archive','Junk Email','Junk E-mail','Deleted Items'
    if ($Rule.actions.moveToFolder -or $actionsJson -match 'moveToFolder') {
        foreach ($folder in $hidingFolders) {
            if ($actionsJson -match [regex]::Escape($folder)) {
                $score += 4
                $reasons.Add("HIDE_IN_FOLDER: $folder") | Out-Null
                break
            }
        }
    }

    # Direct delete
    if ($Rule.actions.delete -eq $true -or $Rule.actions.permanentDelete -eq $true) {
        $score += 3
        $reasons.Add('DELETE_ACTION') | Out-Null
    }

    # Mark-as-read without other action (silencing inbox)
    if ($Rule.actions.markAsRead -eq $true) {
        $score += 1
        $reasons.Add('MARK_AS_READ') | Out-Null
    }

    # Financial-keyword conditions (BEC fingerprint)
    $becKeywords = 'invoice','payment','wire','bank','routing','account','transfer','ACH','IBAN','swift','remittance','receipt'
    foreach ($kw in $becKeywords) {
        if ($conditionsJson -match "(?i)\b$kw\b") {
            $score += 4
            $reasons.Add("BEC_KEYWORD: $kw") | Out-Null
            break  # Don't double-score for multiple keywords
        }
    }

    # External forwarding
    $forwardTargets = @()
    if ($Rule.actions.forwardTo)           { $forwardTargets += $Rule.actions.forwardTo.emailAddress.address }
    if ($Rule.actions.forwardAsAttachmentTo){ $forwardTargets += $Rule.actions.forwardAsAttachmentTo.emailAddress.address }
    if ($Rule.actions.redirectTo)          { $forwardTargets += $Rule.actions.redirectTo.emailAddress.address }

    foreach ($target in $forwardTargets) {
        if ($target -and $target.Contains('@')) {
            $domain = $target.Split('@')[-1].ToLower()
            if ($VerifiedDomains -and $domain -notin $VerifiedDomains) {
                $score += 5
                $reasons.Add("EXTERNAL_FORWARD: $target") | Out-Null
            }
        }
    }

    return @{ Score = [math]::Min($score, 10); Reasons = $reasons }
}
