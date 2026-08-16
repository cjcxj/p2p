# Builds the P2P server/client for Windows and Linux, and the Android AAR.
# Requires: Go, gomobile, Android SDK/NDK (for the AAR only).

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $Root "bin"
$AarDir = Join-Path $Root "android"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $AarDir | Out-Null

function Build-Go([string]$Name, [string]$Pkg, [string]$GOOS, [string]$GOARCH, [string]$Ext) {
    Write-Host "==> building $Name ($GOOS/$GOARCH)"
    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH
    $env:CGO_ENABLED = "0"
    $out = Join-Path $OutDir "$Name$Ext"
    & go build -trimpath -ldflags "-s -w" -o $out ./cmd/$Pkg
    if ($LASTEXITCODE -ne 0) { throw "build $Name failed" }
    Write-Host "    -> $out"
}

Build-Go "p2p-server" "server" "windows" "amd64" ".exe"
Build-Go "p2p-client" "client" "windows" "amd64" ".exe"
Build-Go "p2p-client" "client" "linux"   "amd64" "-linux"
Build-Go "p2p-server" "server" "linux"   "amd64" "-linux"

# Restore host env
Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

# ---- Android AAR ---------------------------------------------------------
if ($env:ANDROID_HOME -and $env:ANDROID_NDK_HOME) {
    Write-Host "==> building Android AAR"
    $aar = Join-Path $AarDir "p2p.aar"
    # -androidapi must be within the NDK's supported range; NDK r27+ is 21..35
    & gomobile bind -target=android -androidapi 21 -o $aar ./sdk
    if ($LASTEXITCODE -ne 0) { throw "gomobile bind failed" }
    Write-Host "    -> $aar"
} else {
    Write-Host "==> SKIPPING Android AAR (set ANDROID_HOME and ANDROID_NDK_HOME)"
}

# ---- wintun.dll (Windows TUN driver) ------------------------------------
$wintun = Join-Path $OutDir "wintun.dll"
if (-not (Test-Path $wintun)) {
    Write-Host "==> downloading wintun.dll (needed by p2p-client mesh --tun)"
    try {
        $zip = Join-Path $env:TEMP "wintun.zip"
        Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $env:TEMP "wintun") -Force
        Copy-Item (Join-Path $env:TEMP "wintun\wintun\bin\amd64\wintun.dll") $wintun -Force
        Write-Host "    -> $wintun"
    } catch {
        Write-Host "    !! could not download wintun.dll: $_"
    }
}

Write-Host "==> done"
