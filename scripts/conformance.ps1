# AWSP -- A2A Webhook Security Profile
# Local conformance runner (Windows PowerShell / pwsh).
# Mirrors scripts/conformance.sh: runs every reference impl's native test
# suite in sequence, then prints a one-screen matrix and exits non-zero
# if any port failed. Missing toolchains are SKIPped, not failed.
#
# Tested against Windows PowerShell 5.1 and PowerShell 7.x.

[CmdletBinding()]
param()

# Don't auto-throw on native command non-zero; we capture $LASTEXITCODE
# for each port. We also intentionally do not Set-StrictMode so this
# stays portable to 5.1 quirks.
$ErrorActionPreference = 'Continue'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir

# ---- Color setup --------------------------------------------------------
# Use ANSI escapes when we're attached to a console host that supports
# them (PS 7+ on any OS, Windows Terminal, modern conhost). NO_COLOR and
# a non-TTY stdout disable color.
$UseColor = $true
if ($env:NO_COLOR) { $UseColor = $false }
try {
    if (-not [Console]::IsOutputRedirected) {
        # Console output is interactive -- color is fine.
    } else {
        $UseColor = $false
    }
} catch {
    $UseColor = $false
}

if ($UseColor) {
    $ESC      = [char]27
    $C_GREEN  = "$ESC[32m"
    $C_RED    = "$ESC[31m"
    $C_YELLOW = "$ESC[33m"
    $C_BOLD   = "$ESC[1m"
    $C_RESET  = "$ESC[0m"
} else {
    $C_GREEN = ''; $C_RED = ''; $C_YELLOW = ''; $C_BOLD = ''; $C_RESET = ''
}

# ---- Helpers ------------------------------------------------------------
function Test-Tool($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Write-Section($title) {
    Write-Host ''
    Write-Host "$C_BOLD==> $title$C_RESET"
}

# Captures a PASS/FAIL/SKIP result + optional note for each language.
$results = [ordered]@{
    typescript = @{ Result = $null; Note = '' }
    python     = @{ Result = $null; Note = '' }
    go         = @{ Result = $null; Note = '' }
    java       = @{ Result = $null; Note = '' }
    dotnet     = @{ Result = $null; Note = '' }
}

function Set-Result($lang, $result, $note = '') {
    $results[$lang].Result = $result
    $results[$lang].Note   = $note
}

# Run a scriptblock inside Push-Location/Pop-Location, capture exit.
function Invoke-Suite($lang, $dir, $scriptblock) {
    Push-Location $dir
    try {
        & $scriptblock
        if ($LASTEXITCODE -eq 0) {
            Set-Result $lang 'PASS'
        } else {
            Set-Result $lang 'FAIL'
        }
    } finally {
        Pop-Location
    }
}

# ---- typescript ---------------------------------------------------------
Write-Section 'typescript'
if (-not (Test-Tool 'node') -or -not (Test-Tool 'npm')) {
    Write-Host '  node/npm not found -- skipping'
    Set-Result 'typescript' 'SKIP' 'node/npm not installed'
} else {
    Invoke-Suite 'typescript' (Join-Path $RepoRoot 'reference/typescript') {
        npm ci
        if ($LASTEXITCODE -ne 0) { return }
        npm test
    }
}

# ---- python -------------------------------------------------------------
Write-Section 'python'
$pyCmd = $null
if (Test-Tool 'python')  { $pyCmd = 'python'  }
elseif (Test-Tool 'python3') { $pyCmd = 'python3' }
if (-not $pyCmd) {
    Write-Host '  python not found -- skipping'
    Set-Result 'python' 'SKIP' 'python not installed'
} else {
    Invoke-Suite 'python' (Join-Path $RepoRoot 'reference/python') {
        & $pyCmd -m pip install -e '.[dev]'
        if ($LASTEXITCODE -ne 0) { return }
        & $pyCmd -m pytest
    }
}

# ---- go -----------------------------------------------------------------
Write-Section 'go'
if (-not (Test-Tool 'go')) {
    Write-Host '  go not found -- skipping'
    Set-Result 'go' 'SKIP' 'go not installed'
} else {
    Invoke-Suite 'go' (Join-Path $RepoRoot 'reference/go') {
        go test ./...
    }
}

# ---- java ---------------------------------------------------------------
Write-Section 'java'
# Maven on Windows ships as mvn.cmd; Get-Command picks it up either way.
if (-not (Test-Tool 'mvn')) {
    Write-Host '  mvn not found -- skipping'
    Set-Result 'java' 'SKIP' 'maven not installed'
} else {
    Invoke-Suite 'java' (Join-Path $RepoRoot 'reference/java') {
        mvn -B test
    }
}

# ---- dotnet -------------------------------------------------------------
Write-Section 'dotnet'
if (-not (Test-Tool 'dotnet')) {
    Write-Host '  dotnet not found -- skipping'
    Set-Result 'dotnet' 'SKIP' 'dotnet sdk not installed'
} else {
    Invoke-Suite 'dotnet' (Join-Path $RepoRoot 'reference/dotnet') {
        dotnet test --configuration Release
    }
}

# ---- Final matrix -------------------------------------------------------
Write-Host ''
Write-Host "${C_BOLD}Conformance matrix:${C_RESET}"

# "typescript" is the longest label at 10 chars; pad to 11 to leave room
# for the colon and a trailing space.
$padTo = 11

$overall = 0
foreach ($lang in $results.Keys) {
    $entry  = $results[$lang]
    $result = $entry.Result
    $note   = $entry.Note

    switch ($result) {
        'PASS' { $color = $C_GREEN }
        'FAIL' { $color = $C_RED;    $overall = 1 }
        'SKIP' { $color = $C_YELLOW }
        default { $color = '' }
    }

    $label = ($lang + ':').PadRight($padTo)
    $line  = "  $label $color$result$C_RESET"
    if ($note) { $line += "   ($note)" }
    Write-Host $line
}

Write-Host ''
exit $overall
