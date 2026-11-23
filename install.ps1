# Install t3fleet on Windows from GitHub Releases.
#
# Usage:
#   irm https://raw.githubusercontent.com/abaudhuin/t3fleet/main/install.ps1 | iex
$ErrorActionPreference = "Stop"

$Repo = if ($env:T3FLEET_REPO) { $env:T3FLEET_REPO } else { "abaudhuin/t3fleet" }
$Version = if ($env:T3FLEET_VERSION) { $env:T3FLEET_VERSION } else { "latest" }
$InstallDir = if ($env:T3FLEET_INSTALL_DIR) { $env:T3FLEET_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "t3fleet\bin" }

$Target = "x86_64-pc-windows-msvc"
$Archive = "t3fleet-$Target.zip"
$BaseUrl = if ($Version -eq "latest") {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("t3fleet-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $ArchivePath = Join-Path $TempDir $Archive
    $SumsPath = Join-Path $TempDir "SHA256SUMS.txt"

    Write-Host "Downloading $Archive from $Repo ($Version)..."
    Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ArchivePath -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $SumsPath -UseBasicParsing

    $Expected = $null
    foreach ($Line in Get-Content $SumsPath) {
        $Parts = $Line.Trim() -split "\s+"
        if ($Parts.Length -ge 2 -and ($Parts[1] -eq $Archive -or $Parts[1] -eq "*$Archive")) {
            $Expected = $Parts[0].ToLowerInvariant()
            break
        }
    }
    if (-not $Expected) {
        throw "Checksum entry for $Archive not found in SHA256SUMS.txt"
    }

    $Actual = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) {
        throw "Checksum mismatch for $Archive (expected $Expected, got $Actual)"
    }

    Expand-Archive -Path $ArchivePath -DestinationPath $TempDir -Force
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path (Join-Path $TempDir "t3fleet.exe") -Destination (Join-Path $InstallDir "t3fleet.exe") -Force
    Write-Host "Installed t3fleet.exe to $InstallDir\t3fleet.exe"

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathEntries = if ($UserPath) { $UserPath -split ";" } else { @() }
    if ($PathEntries -notcontains $InstallDir) {
        $NewPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "Added $InstallDir to your user PATH. Open a new terminal if needed."
    }
} finally {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
