function Invoke-TTGraphRequest {
    <#
    .SYNOPSIS
        Graph API wrapper that handles paging, throttling, and transient errors.
    .DESCRIPTION
        Most homegrown IR tools fail silently on Graph's @odata.nextLink paging
        (they grab the first 100 or 1000 results and miss everything else).
        They also fail under 429 throttling during large pulls. This wrapper
        solves both.

        Uses Invoke-MgGraphRequest under the hood so auth token handling is
        delegated to the Graph SDK, but we retain control over paging,
        backoff, and response shaping.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET','POST','PATCH','DELETE')]
        [string]$Method = 'GET',

        [hashtable]$Body,

        # Follow @odata.nextLink until exhausted. Default for IR work.
        [switch]$All,

        # Safety cap - don't loop forever on a broken endpoint
        [int]$MaxPages = 10000,

        # Initial backoff seconds for 429/503
        [int]$InitialBackoffSec = 2,

        [int]$MaxRetries = 6
    )

    $results  = [System.Collections.Generic.List[object]]::new()
    $page     = 0
    $nextLink = $Uri

    while ($nextLink -and $page -lt $MaxPages) {
        $attempt = 0
        $success = $false

        while (-not $success -and $attempt -le $MaxRetries) {
            try {
                $params = @{
                    Method = $Method
                    Uri    = $nextLink
                }
                if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20) ; $params.ContentType = 'application/json' }

                $response = Invoke-MgGraphRequest @params -OutputType PSObject -ErrorAction Stop
                $success  = $true
            }
            catch {
                $attempt++
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                # Non-retryable errors: fail immediately, don't waste time
                if ($statusCode -in 400, 401, 403, 404, 405) {
                    Write-TTLog -Level Error -Message "Graph request failed ($statusCode): $($_.Exception.Message)" -Data @{ uri = $nextLink }
                    throw
                }

                # Retryable: throttling or server-side transient errors
                if ($statusCode -in 429, 500, 502, 503, 504) {
                    $retryAfter = $InitialBackoffSec * [math]::Pow(2, $attempt - 1)
                    # Honor Retry-After header if present
                    if ($_.Exception.Response -and $_.Exception.Response.Headers.RetryAfter.Delta) {
                        $retryAfter = [int]$_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                    }
                    Write-TTLog -Level Warn -Message "Graph throttled ($statusCode) on page $page attempt $attempt. Sleeping $retryAfter s." -Data @{ uri = $nextLink }
                    Start-Sleep -Seconds $retryAfter
                }
                elseif ($attempt -gt $MaxRetries) {
                    Write-TTLog -Level Error -Message "Graph request failed after $MaxRetries retries: $($_.Exception.Message)" -Data @{ uri = $nextLink }
                    throw
                }
                else {
                    # Unknown error — retry with backoff but don't loop forever
                    Start-Sleep -Seconds $InitialBackoffSec
                }
            }
        }

        if ($response.value) {
            foreach ($item in $response.value) { $results.Add($item) | Out-Null }
        }
        elseif ($response) {
            # Single-object response (not a collection)
            $results.Add($response) | Out-Null
        }

        if ($All -and $response.'@odata.nextLink') {
            $nextLink = $response.'@odata.nextLink'
            $page++
        }
        else {
            $nextLink = $null
        }
    }

    return ,$results.ToArray()
}
