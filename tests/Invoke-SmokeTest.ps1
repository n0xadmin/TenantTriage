<#
.SYNOPSIS
    Offline smoke test for TenantTriage restructured layout.
    Requires no tenant connection, no dependencies.
.EXAMPLE
    .\tests\Invoke-SmokeTest.ps1
#>
[CmdletBinding()]
param([switch]$KeepArtifacts)

$ErrorActionPreference = 'Stop'

$results = [System.Collections.Generic.List[pscustomobject]]::new()
function Assert-Step {
    param([string]$Name, [scriptblock]$Test)
    try {
        $t0  = Get-Date
        $out = . $Test
        $dur = (Get-Date) - $t0
        $results.Add([pscustomobject]@{ Step = $Name; Status = 'PASS'; Duration = '{0:N2}s' -f $dur.TotalSeconds; Detail = '' }) | Out-Null
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        return $out
    }
    catch {
        $results.Add([pscustomobject]@{ Step = $Name; Status = 'FAIL'; Duration = '-'; Detail = $_.Exception.Message }) | Out-Null
        Write-Host "  [FAIL] $Name :: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

Write-Host "`n=== TenantTriage Offline Smoke Test ===" -ForegroundColor Cyan
Write-Host "PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Write-Host "Host OS:    $($PSVersionTable.OS)`n"

$projectRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------
# Step 1: File structure
# ---------------------------------------------------------------
Write-Host "[1/9] File structure" -ForegroundColor Yellow

Assert-Step 'Launcher exists' {
    if (-not (Test-Path (Join-Path $projectRoot 'TenantTriage.ps1'))) { throw 'TenantTriage.ps1 not found' }
}

Assert-Step 'lib/ folder with all helpers' {
    $required = 'Initialize-TT.ps1','Write-TTLog.ps1','Invoke-TTGraphRequest.ps1',
                'Save-TTArtifact.ps1','Assert-TTDependency.ps1','Case-Management.ps1','Connect-TTTenant.ps1'
    foreach ($f in $required) {
        $p = Join-Path $projectRoot "lib\$f"
        if (-not (Test-Path $p)) { throw "Missing lib/$f" }
    }
}

Assert-Step 'collectors/ folder with all collectors' {
    $required = 'Get-TTSignInLogs.ps1','Get-TTInboxRules.ps1','Get-TTMailboxForwarding.ps1',
                'Get-TTMailboxDelegates.ps1','Get-TTOAuthGrants.ps1','Get-TTAuthMethodChanges.ps1',
                'Get-TTAdminRoleChanges.ps1','Get-TTRiskyUsers.ps1','Test-TTAuditReadiness.ps1',
                'Invoke-TTFullTriage.ps1','Get-TTUnifiedAuditLog.ps1','Get-TTMailItemsAccessed.ps1',
                'Get-TTSessionActivity.ps1','Get-TTMessageTrace.ps1'
    foreach ($f in $required) {
        $p = Join-Path $projectRoot "collectors\$f"
        if (-not (Test-Path $p)) { throw "Missing collectors/$f" }
    }
}

# ---------------------------------------------------------------
# Step 2: Shared lib loads cleanly (no external deps needed)
# ---------------------------------------------------------------
Write-Host "`n[2/9] Shared lib initialization" -ForegroundColor Yellow

# Dot-source at SCRIPT scope (NOT inside Assert-Step — functions defined
# inside a function's scope die when the function returns).
try {
    $script:TTInitialized = $false
    . (Join-Path $projectRoot 'lib\Initialize-TT.ps1')
    $results.Add([pscustomobject]@{ Step = 'Initialize-TT loads without errors'; Status = 'PASS'; Duration = '-'; Detail = '' }) | Out-Null
    Write-Host "  [PASS] Initialize-TT loads without errors" -ForegroundColor Green
} catch {
    $results.Add([pscustomobject]@{ Step = 'Initialize-TT loads without errors'; Status = 'FAIL'; Duration = '-'; Detail = $_.Exception.Message }) | Out-Null
    Write-Host "  [FAIL] Initialize-TT loads without errors :: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Assert-Step 'PowerShell version >= 7.2' {
    if ($PSVersionTable.PSVersion -lt [version]'7.2') {
        throw "Requires PS 7.2+, have $($PSVersionTable.PSVersion)"
    }
}

# ---------------------------------------------------------------
# Step 3: All collectors load cleanly
# ---------------------------------------------------------------
Write-Host "`n[3/9] Collector loading" -ForegroundColor Yellow

# Again, dot-source at SCRIPT scope so functions persist
try {
    Get-ChildItem -Path (Join-Path $projectRoot 'collectors') -Filter '*.ps1' | ForEach-Object {
        . $_.FullName
    }
    $results.Add([pscustomobject]@{ Step = 'All collectors dot-source without errors'; Status = 'PASS'; Duration = '-'; Detail = '' }) | Out-Null
    Write-Host "  [PASS] All collectors dot-source without errors" -ForegroundColor Green
} catch {
    $results.Add([pscustomobject]@{ Step = 'All collectors dot-source without errors'; Status = 'FAIL'; Duration = '-'; Detail = $_.Exception.Message }) | Out-Null
    Write-Host "  [FAIL] All collectors dot-source without errors :: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Assert-Step 'Expected functions available' {
    $expected = @(
        'New-TTCase','Complete-TTCase','Get-TTCaseContext',
        'Connect-TTTenant','Disconnect-TTTenant',
        'Test-TTAuditReadiness',
        'Get-TTSignInLogs','Get-TTRiskyUsers',
        'Get-TTInboxRules','Get-TTMailboxForwarding','Get-TTMailboxDelegates','Get-TTAuthMethodChanges',
        'Get-TTAdminRoleChanges','Get-TTOAuthGrants',
        'Invoke-TTFullTriage',
        'New-TTTriageReport',
        'Test-MESAvailable','Import-MESOutput','Invoke-MESEvidenceCollection',
        'Invoke-MESCollector','Invoke-MESUALCollection','Invoke-MESMailItemsAccessed',
        'Invoke-MESMessageTrace','Invoke-MESSessions',
        'Get-TTUnifiedAuditLog','Get-TTMailItemsAccessed','Get-TTSessionActivity','Get-TTMessageTrace'
    )
    $missing = $expected | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
    if ($missing) { throw "Missing functions: $($missing -join ', ')" }
}

# ---------------------------------------------------------------
# Step 4: Case creation
# ---------------------------------------------------------------
Write-Host "`n[4/9] Case scaffolding" -ForegroundColor Yellow

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "TT-SmokeTest-$(Get-Random)"

$caseInfo = Assert-Step 'New-TTCase creates folder tree' {
    New-TTCase -ClientName 'TestClient' -IncidentRef 'SMOKE-001' `
               -Root $testRoot -AnalystName 'smoketest@example.com'
}

Assert-Step 'Required subfolders exist' {
    foreach ($sub in '_meta','Identity','Mail','Apps','Config','Devices') {
        if (-not (Test-Path (Join-Path $caseInfo.CasePath $sub))) { throw "Missing: $sub" }
    }
}

Assert-Step 'case.json valid' {
    $cj = Get-Content (Join-Path $caseInfo.CasePath '_meta\case.json') -Raw | ConvertFrom-Json
    foreach ($f in 'CaseId','ClientName','IncidentRef','StartedUtc') {
        if (-not $cj.$f) { throw "Missing field: $f" }
    }
}

# ---------------------------------------------------------------
# Step 5: Context
# ---------------------------------------------------------------
Write-Host "`n[5/9] Context state" -ForegroundColor Yellow

Assert-Step 'Get-TTCaseContext reflects active case' {
    $ctx = Get-TTCaseContext
    if ($ctx.CaseId -ne $caseInfo.CaseId) { throw "Mismatch: $($ctx.CaseId)" }
    if ($ctx.GraphConnected) { throw "GraphConnected should be false" }
}

# ---------------------------------------------------------------
# Step 6: Logging
# ---------------------------------------------------------------
Write-Host "`n[6/9] Logging pipeline" -ForegroundColor Yellow

Assert-Step 'Write-TTLog streams to JSONL' {
    Write-TTLog -Level Info -Message 'smoke-test-probe' -Data @{ test = $true }
    $logPath = Join-Path $caseInfo.CasePath '_meta\action.log.jsonl'
    $found = Get-Content $logPath | Where-Object { $_ -like '*smoke-test-probe*' }
    if (-not $found) { throw "Probe not found in action log" }
    $parsed = $found | ConvertFrom-Json
    if ($parsed.Level -ne 'Info') { throw "Level mismatch" }
}

# ---------------------------------------------------------------
# Step 7: Artifact save + hash
# ---------------------------------------------------------------
Write-Host "`n[7/9] Artifact save + hash" -ForegroundColor Yellow

$fakeData = 1..25 | ForEach-Object {
    [pscustomobject]@{
        id                = [guid]::NewGuid().ToString()
        createdDateTime   = (Get-Date).AddMinutes(-$_).ToString('o')
        userPrincipalName = "user$($_ % 5)@test.example"
        ipAddress         = "203.0.113.$_"
    }
}

Assert-Step 'Save-TTArtifact writes JSONL + CSV with manifest entries' {
    $r = Save-TTArtifact -InputObject $fakeData -ArtifactName 'TestArtifact' -Category 'Identity' -Format Both
    if ($r.RowCount -ne 25) { throw "Row count: $($r.RowCount)" }
    if ($r.Files.Count -ne 2) { throw "File count: $($r.Files.Count)" }
}

Assert-Step 'JSONL round-trips' {
    $jsonl = Get-ChildItem (Join-Path $caseInfo.CasePath 'Identity') -Filter '*.jsonl' | Select-Object -First 1
    $rows = Get-Content $jsonl.FullName | ForEach-Object { $_ | ConvertFrom-Json }
    if ($rows.Count -ne 25) { throw "JSONL rows: $($rows.Count)" }
}

# ---------------------------------------------------------------
# Step 8: Case finalization
# ---------------------------------------------------------------
Write-Host "`n[8/9] Case finalization" -ForegroundColor Yellow

$completion = Assert-Step 'Complete-TTCase writes manifest + zip' {
    Complete-TTCase -Zip -KeepConnection
}

Assert-Step 'Manifest hashes verify' {
    $mf = Get-Content $completion.ManifestPath -Raw | ConvertFrom-Json
    foreach ($art in $mf.Artifacts) {
        $fp = Join-Path $caseInfo.CasePath $art.FilePath
        $actual = (Get-FileHash -Path $fp -Algorithm SHA256).Hash
        if ($actual -ne $art.SHA256) { throw "Hash mismatch: $($art.FilePath)" }
    }
}

Assert-Step 'manifest.sha256 matches manifest.json' {
    $declared = (Get-Content (Join-Path $caseInfo.CasePath '_meta\manifest.sha256')).Trim()
    $actual   = (Get-FileHash -Path $completion.ManifestPath -Algorithm SHA256).Hash
    if ($declared -ne $actual) { throw "manifest.sha256 mismatch" }
}

Assert-Step 'Zip + sidecar exist' {
    if (-not (Test-Path $completion.ZipPath)) { throw "Zip missing" }
    if (-not (Test-Path "$($completion.ZipPath).sha256")) { throw "Zip hash missing" }
}

# ---------------------------------------------------------------
# Step 9: Cleanup
# ---------------------------------------------------------------
Write-Host "`n[9/9] Cleanup" -ForegroundColor Yellow

if ($KeepArtifacts) {
    Write-Host "  [SKIP] Artifacts at: $testRoot" -ForegroundColor Gray
} else {
    Assert-Step 'Remove test artifacts' {
        Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$($caseInfo.CasePath).zip" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$($caseInfo.CasePath).zip.sha256" -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------
# Results
# ---------------------------------------------------------------
Write-Host "`n=== Results ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$failCount = @($results | Where-Object Status -eq 'FAIL').Count
if ($failCount -gt 0) {
    Write-Host "`n$failCount step(s) FAILED." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll $($results.Count) checks passed." -ForegroundColor Green
    exit 0
}
