#
# build.ps1 - build MongilLoader.efi + OphionDxe.efi via EDK2
#
# Requires:
#   - EDK2 cloned at $env:LEARNING_ROOT\edk2 (or override via -Edk2Path)
#   - VS 2022 + Windows SDK (cl.exe on PATH from vcvars64)
#
# Phase 1: builds combined Loader (chains to Windows) + empty OphionDxe.
# Phase 2-5: incremental; pass -Phase to control which sources are wired in.
#
param(
    [string]$Edk2Path = "$PSScriptRoot\..\..\edk2",
    [int]$Phase = 1,
    [switch]$Clean,
    [string]$Toolchain = "VS2019"   # VS2019 / VS2022 depending on EDK2 build
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$buildOut = "$root\build"

if (-not (Test-Path $Edk2Path)) {
    throw "EDK2 not found at '$Edk2Path'. Clone tianocore/edk2 there, or pass -Edk2Path."
}

if ($Clean) {
    Remove-Item -Recurse -Force $buildOut -ErrorAction SilentlyContinue
    Write-Host "cleaned $buildOut"
}

New-Item -ItemType Directory -Force $buildOut | Out-Null

# Stage MongilLoader sources into EDK2 workspace under a package dir.
$pkgDir = Join-Path $Edk2Path "MongilLoaderPkg"
Remove-Item -Recurse -Force $pkgDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $pkgDir | Out-Null

Copy-Item "$root\Loader"     -Destination "$pkgDir\Loader"     -Recurse
Copy-Item "$root\OphionDxe"  -Destination "$pkgDir\OphionDxe"  -Recurse
Copy-Item "$root\include"    -Destination "$pkgDir\include"    -Recurse

# Generate package DSC/DEC referencing both INFs.
$dsc = @"
[Defines]
  PLATFORM_NAME                  = MongilLoaderPkg
  PLATFORM_GUID                  = 0C5E2F1D-3A4B-4C5D-9E0F-A1B2C3D4E5F6
  PLATFORM_VERSION               = 0.10
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/MongilLoaderPkg
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

[Components]
  MongilLoaderPkg/Loader/Loader.inf
  MongilLoaderPkg/OphionDxe/OphionDxe.inf
"@
Set-Content -Path "$pkgDir\MongilLoaderPkg.dsc" -Value $dsc

# Empty DEC so EDK2's parser is happy.
@"
[Defines]
  DEC_SPECIFICATION              = 0x00010005
  PACKAGE_NAME                   = MongilLoaderPkg
  PACKAGE_GUID                   = 0C5E2F1E-3A4B-4C5D-9E0F-A1B2C3D4E5F6
  PACKAGE_VERSION                = 0.10

[Includes]
  include
"@ | Set-Content -Path "$pkgDir\MongilLoaderPkg.dec"

# Invoke EDK2 build via cmd.exe shim (edksetup is a .bat file).
$buildCmd = @"
@echo off
cd /d "$Edk2Path"
call edksetup.bat
build -p MongilLoaderPkg/MongilLoaderPkg.dsc -t $Toolchain -a X64 -b RELEASE
exit /b %ERRORLEVEL%
"@
$shim = "$buildOut\edk2_build.cmd"
Set-Content -Path $shim -Value $buildCmd
& cmd.exe /c $shim
if ($LASTEXITCODE -ne 0) { throw "EDK2 build failed (exit $LASTEXITCODE)" }

$outBin = "$Edk2Path\Build\MongilLoaderPkg\RELEASE_$Toolchain\X64"
Copy-Item "$outBin\Loader.efi"     "$buildOut\Loader.efi"     -Force
Copy-Item "$outBin\OphionDxe.efi"  "$buildOut\OphionDxe.efi"  -Force

Write-Host ""
Write-Host "Build complete (phase $Phase):"
Get-ChildItem "$buildOut\*.efi" | ForEach-Object {
    Write-Host "  $($_.FullName)  $($_.Length) bytes"
}
