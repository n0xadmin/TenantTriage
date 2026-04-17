function Write-TTLog {
    <#
    .SYNOPSIS
        Consistent logger that writes to both console and the case action log.
    .DESCRIPTION
        Every meaningful action in the module funnels through here so we get
        a single audit trail per case. The action log is serialized on
        Complete-TTCase.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [ValidateSet('Info','Warn','Error','Action','Success')]
        [string]$Level = 'Info',

        [hashtable]$Data
    )

    $timestamp = [datetime]::UtcNow
    $entry = [ordered]@{
        TimestampUtc = $timestamp.ToString('o')
        Level        = $Level
        Message      = $Message
        CaseId       = $script:TTContext.CaseId
        TenantId     = $script:TTContext.TenantId
        AnalystUpn   = $script:TTContext.AnalystUpn
    }
    if ($PSBoundParameters.ContainsKey('Data')) { $entry.Data = $Data }

    # Always capture to the in-memory action log if a case is open
    if ($script:TTContext.CaseId) {
        $script:TTContext.ActionLog.Add([pscustomobject]$entry) | Out-Null
    }

    # Console output - color-coded, timestamped
    $color = switch ($Level) {
        'Info'    { 'Gray' }
        'Warn'    { 'Yellow' }
        'Error'   { 'Red' }
        'Action'  { 'Cyan' }
        'Success' { 'Green' }
    }
    $stamp = $timestamp.ToString('HH:mm:ss')
    Write-Host ("[{0}] [{1,-7}] {2}" -f $stamp, $Level.ToUpper(), $Message) -ForegroundColor $color

    # Persist streaming to disk if case is open (survives crashes)
    if ($script:TTContext.CasePath) {
        $logPath = Join-Path $script:TTContext.CasePath '_meta\action.log.jsonl'
        $logDir  = Split-Path $logPath -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        ($entry | ConvertTo-Json -Compress -Depth 10) | Add-Content -Path $logPath -Encoding utf8
    }
}
