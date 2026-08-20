# Assemble a Defender-safe release directory: executable plus sealed bundle.
param(
    [string]$OutDir = "release"
)
$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outPath = if ([IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $repo $OutDir }
$outPath = [IO.Path]::GetFullPath($outPath)
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $repo "release"))
if ($outPath.TrimEnd('\', '/') -ne $releaseRoot.TrimEnd('\', '/') -and
    -not $outPath.StartsWith($releaseRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "release output must be under the dedicated release directory: $releaseRoot"
}
if (Test-Path -LiteralPath $releaseRoot) {
    $rootItem = Get-Item -LiteralPath $releaseRoot -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "refusing to use reparse-point release root: $releaseRoot"
    }
}
function Assert-NoReparsePath([string]$Root, [string]$Target) {
    $relative = $Target.Substring($Root.Length).TrimStart('\', '/')
    $current = $Root
    foreach ($part in ($relative -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "refusing reparse-point path component: $current"
            }
        }
    }
}
Assert-NoReparsePath $releaseRoot $outPath
if (Test-Path -LiteralPath $outPath) {
    $existing = Get-Item -LiteralPath $outPath -Force
    if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "refusing to delete reparse-point release output: $outPath"
    }
}
$sigDir = Join-Path $repo "signatures"
$exe = Join-Path $repo "target\release\powerscanner.exe"
$stagedSig = Join-Path $outPath "signatures"
$rulesPath = Join-Path $sigDir "rules"

Push-Location $repo
try {
    cargo build --release -p powerscanner-gui
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    $sources = @()
    if (Test-Path -LiteralPath $rulesPath -PathType Container) {
        $sources = @(Get-ChildItem -LiteralPath $rulesPath -File -Force -ErrorAction Stop |
            Where-Object { $_.Extension -in @(".yar", ".yara") })
    }
    if ($sources) {
        if ($sources.Count -ne 1 -or $sources[0].Name -ne "bundled.yar") {
            throw "only the canonical generated signatures/rules/bundled.yar may be packaged"
        }
        $manifestPath = Join-Path $sigDir "MANIFEST.json"
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "missing signatures/MANIFEST.json for plaintext bundle"
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $actualHash = (Get-FileHash -LiteralPath $sources[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($manifest.artifacts.'bundled.yar'.sha256 -ne $actualHash) {
            throw "bundled.yar does not match signatures/MANIFEST.json"
        }
        cargo run -p seal-bundle -- $sigDir
        if ($LASTEXITCODE -ne 0) { throw "bundle sealing failed with exit code $LASTEXITCODE" }
    } elseif (-not (Test-Path -LiteralPath (Join-Path $sigDir "bundle.psenc") -PathType Leaf)) {
        throw "no plaintext rule sources or pre-sealed bundle found under $sigDir"
    } else {
        Write-Host "Using tracked pre-sealed bundle; no plaintext sources present."
    }
    cargo run -p seal-bundle -- --verify $sigDir
    if ($LASTEXITCODE -ne 0) { throw "sealed bundle verification failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "release executable not found: $exe"
}
$bundle = Join-Path $sigDir "bundle.psenc"
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) {
    throw "sealed bundle not found: $bundle"
}
$requiredFiles = @("NOTICE.md", "MANIFEST.json")
foreach ($name in $requiredFiles) {
    $path = Join-Path $sigDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -eq 0) {
        throw "missing required release attribution file: $path"
    }
}
$licenseNames = @("LICENSE.bartblaze.txt", "LICENSE.reversinglabs.txt", "LICENSE.yara-rules.txt")
$licenses = Join-Path $sigDir "licenses"
if (-not (Test-Path -LiteralPath $licenses -PathType Container)) {
    throw "missing required license directory: $licenses"
}
foreach ($name in $licenseNames) {
    $path = Join-Path $licenses $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -eq 0) {
        throw "missing or empty required license file: $path"
    }
}

if (Test-Path -LiteralPath $outPath) {
    Remove-Item -LiteralPath $outPath -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stagedSig | Out-Null
Copy-Item -LiteralPath $exe -Destination $outPath
Copy-Item -LiteralPath $bundle -Destination $stagedSig
foreach ($name in @("NOTICE.md", "MANIFEST.json")) {
    $source = Join-Path $sigDir $name
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination $stagedSig
    }
}
Copy-Item -LiteralPath $licenses -Destination (Join-Path $stagedSig "licenses") -Recurse
foreach ($name in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $stagedSig $name) -PathType Leaf)) {
        throw "required release file was not staged: $name"
    }
}
foreach ($name in $licenseNames) {
    if (-not (Test-Path -LiteralPath (Join-Path $stagedSig "licenses\$name") -PathType Leaf)) {
        throw "required release license was not staged: $name"
    }
}

$leak = Get-ChildItem -LiteralPath $outPath -Recurse -File -ErrorAction Stop |
    Where-Object { $_.Extension -in @(".yar", ".yara", ".yarc") }
if ($leak) {
    throw "plaintext rules leaked into release: $($leak.FullName -join ', ')"
}
Write-Host "Release staged in $outPath (powerscanner.exe + bundle.psenc, no plaintext rules)."
