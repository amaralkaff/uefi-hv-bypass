#
# build_probe.ps1 - build vgk_probe.exe (user-mode) + VgkProbeDrv.sys (kernel)
#
# Run from "x64 Native Tools Command Prompt for VS" or have CMake able to
# locate cl.exe on PATH (vcvars64.bat).
#
param(
    [switch]$Drv,         # also build kernel companion (requires WDK)
    [switch]$Clean,
    [switch]$Install      # copy outputs to .\bin
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Clean) {
    Remove-Item -Recurse -Force "$root\build" -ErrorAction SilentlyContinue
    Write-Host "cleaned $root\build"
    if (-not $Install) { return }
}

New-Item -ItemType Directory -Force "$root\build" | Out-Null

# User-mode probe via CMake/Ninja or MSVC generator.
Push-Location "$root\build"
try {
    cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release ..
    if ($LASTEXITCODE -ne 0) {
        # fallback to MSVC generator
        Remove-Item -Recurse -Force "$root\build\*"
        cmake -A x64 ..
    }
    cmake --build . --config Release
    if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }
} finally {
    Pop-Location
}

if ($Drv) {
    $msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
    if (-not (Test-Path $msbuild)) {
        $msbuild = (Get-ChildItem -Path "C:\Program Files\Microsoft Visual Studio" -Recurse -Filter MSBuild.exe -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    }
    if (-not (Test-Path $msbuild)) {
        throw "MSBuild not found; install VS + WDK"
    }
    & $msbuild "$root\probe_drv\probe_drv.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /v:minimal
    if ($LASTEXITCODE -ne 0) { throw "WDK build failed" }
}

if ($Install) {
    New-Item -ItemType Directory -Force "$root\bin" | Out-Null
    Get-ChildItem -Recurse "$root\build" -Filter "vgk_probe.exe" | ForEach-Object {
        Copy-Item $_.FullName "$root\bin\vgk_probe.exe" -Force
        Write-Host "installed: $root\bin\vgk_probe.exe"
    }
    Get-ChildItem -Recurse "$root\build" -Filter "VgkProbeDrv.sys" | ForEach-Object {
        Copy-Item $_.FullName "$root\bin\VgkProbeDrv.sys" -Force
        Write-Host "installed: $root\bin\VgkProbeDrv.sys"
    }
}

Write-Host "build complete"
