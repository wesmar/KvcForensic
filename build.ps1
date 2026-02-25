$projectName = "KvcForensic"
$binDir = Join-Path $PSScriptRoot "bin"

Write-Host "--- Localizing latest Visual Studio Build Tools ---" -ForegroundColor Cyan

# Find the newest installed Visual Studio instance (including Preview/Next)
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = &$vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath

if (-not $vsPath) {
    Write-Error "Latest Visual Studio installation was not found. Check your setup."
    exit 1
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"

Write-Host "Using MSBuild from: $vsPath" -ForegroundColor Gray

# 1. Prepare a clean bin directory
if (Test-Path $binDir) { Remove-Item $binDir -Recurse -Force }
New-Item -ItemType Directory -Path $binDir | Out-Null

# 2. Build (Release | x64)
# Build with optimized settings and minimal output
$msBuildArgs = @(
    "$projectName.vcxproj",
    "/t:Rebuild",
    "/p:Configuration=Release",
    "/p:Platform=x64",
    "/p:DebugSymbols=false",      # Disable debug symbols generation in MSBuild (optional)
    "/p:DebugType=none",          # No debug info
    "/m",                         # Multicore build
    "/nologo",
    "/v:m"                        # Minimal output
)

&$msbuild $msBuildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "!!! BUILD FAILED !!!" -ForegroundColor Red
    exit $LASTEXITCODE
}

# 3. Cleanup and final output
Write-Host "--- Finalizing binary (Stripping PDBs/Logs) ---" -ForegroundColor Yellow

$outExe = Join-Path $PSScriptRoot "x64\Release\$projectName.exe"

if (Test-Path $outExe) {
    # Keep only the final EXE
    Move-Item -Path $outExe -Destination "$binDir\$projectName.exe" -Force
    $templateJson = Join-Path $PSScriptRoot "KvcForensic.json"
    if (-not (Test-Path $templateJson)) {
        Write-Host "Error: Template file KvcForensic.json was not found." -ForegroundColor Red
        exit 1
    }
    Copy-Item -Path $templateJson -Destination (Join-Path $binDir "KvcForensic.json") -Force
    
    # Remove build artifacts (x64, obj, ipch)
    if (Test-Path (Join-Path $PSScriptRoot "x64")) { Remove-Item "x64" -Recurse -Force }
    if (Test-Path (Join-Path $PSScriptRoot "obj")) { Remove-Item "obj" -Recurse -Force }
    
    # Set file timestamps to 2030-01-01 00:00:00
    $targetFile = "$binDir\$projectName.exe"
    $futureDate = Get-Date "2030-01-01 00:00:00"
    (Get-Item $targetFile).CreationTime = $futureDate
    (Get-Item $targetFile).LastWriteTime = $futureDate
    Write-Host "Timestamp set to 2030-01-01 00:00:00"

    Write-Host "Done. Final binary: $binDir\$projectName.exe" -ForegroundColor Green
} else {
    Write-Host "Error: Output file was not found." -ForegroundColor Red
}
