#
# install_efi.ps1 - install MongilLoader on test bench EFI System Partition
#
# Action:
#   1. Mount ESP as drive letter (S: by default).
#   2. Back up existing \EFI\EfiGuard\Loader.efi -> Loader.original.efi.
#   3. Copy build\Loader.efi to \EFI\EfiGuard\Loader.efi (same NVRAM entry).
#   4. Copy build\OphionDxe.efi to \EFI\Ophion\OphionDxe.efi (new dir).
#   5. Verify NVRAM entry still resolves to Loader.efi.
#   6. Print fallback (safe mode) instructions.
#
# RUN AS ADMIN on test bench.
#
param(
    [string]$EspDrive = "S:",
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path

if (-not (Test-Path "$root\build\Loader.efi")) {
    throw "build\Loader.efi missing; run .\scripts\build.ps1 first"
}
if (-not (Test-Path "$root\build\OphionDxe.efi")) {
    throw "build\OphionDxe.efi missing; run .\scripts\build.ps1 first"
}

# Mount ESP if not already
if (-not (Test-Path "$EspDrive\")) {
    Write-Host "mounting ESP at $EspDrive ..."
    & mountvol $EspDrive /S
}

$efiGuardDir = "$EspDrive\EFI\EfiGuard"
$ophionDir   = "$EspDrive\EFI\Ophion"

if (-not (Test-Path $efiGuardDir)) {
    if (-not $Force) {
        throw "$efiGuardDir not found; vanilla EfiGuard must be installed first. Pass -Force to create."
    }
    New-Item -ItemType Directory -Force $efiGuardDir | Out-Null
}
New-Item -ItemType Directory -Force $ophionDir | Out-Null

# Back up original Loader.efi -> Loader.original.efi (only if not already done).
$origLoader = "$efiGuardDir\Loader.efi"
$savedOriginal = "$efiGuardDir\Loader.original.efi"
if ((Test-Path $origLoader) -and (-not (Test-Path $savedOriginal))) {
    Copy-Item $origLoader $savedOriginal -Force
    Write-Host "backed up existing Loader.efi -> Loader.original.efi"
}

# Install combined loader + OphionDxe.
Copy-Item "$root\build\Loader.efi"    "$origLoader" -Force
Copy-Item "$root\build\OphionDxe.efi" "$ophionDir\OphionDxe.efi" -Force
Write-Host "installed:"
Write-Host "  $origLoader"
Write-Host "  $ophionDir\OphionDxe.efi"

Write-Host ""
Write-Host "----- NEXT STEPS -----"
Write-Host "1. Run .\scripts\add_safe_mode_nvram.ps1 to add fallback NVRAM entry."
Write-Host "2. Reboot. F12 boot menu should show:"
Write-Host "     [1] MongilLoader (default)"
Write-Host "     [2] EfiGuard Safe Mode (fallback)"
Write-Host "     [3] Windows Boot Manager"
Write-Host "3. Boot 'EfiGuard Safe Mode' first to confirm fallback works."
Write-Host "4. Default-boot MongilLoader after."
