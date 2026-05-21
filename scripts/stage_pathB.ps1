# stage_pathB.ps1 - Stage MongilLoader integration with NOVA spoofer (Path B)
#
# Run AFTER VS BuildTools workload installed + MongilLoader.efi rebuilt.
#
# Action:
#   1. Backup current ESP files
#   2. Copy MongilLoader.efi + EfiGuardDxe.efi + OphionDxe.efi to ESP
#   3. Edit startup.nsh: chain spoofer's mp.efi -> Mongil/Loader.efi -> boot.efi
#
# Recovery: if boot fails, F12 Windows installer USB shell:
#   mountvol X: /S
#   move X:\EFI\Boot\startup.nsh.spoofer-only X:\EFI\Boot\startup.nsh
#

$ErrorActionPreference = 'Stop'
mountvol S: /S 2>&1 | Out-Null

$build = "C:\Users\Administrator\Documents\learning\MongilLoader\build"
$efiguard = "C:\Users\Administrator\Documents\learning\.tools\EfiGuard\EfiGuard-v1.4\EFI\Boot\EfiGuardDxe.efi"

# Sanity
if (-not (Test-Path "$build\Loader.efi")) { throw "MongilLoader Loader.efi missing - build it first" }
if (-not (Test-Path "$build\OphionDxe.efi")) { throw "MongilLoader OphionDxe.efi missing - build it first" }
if (-not (Test-Path $efiguard)) { throw "EfiGuardDxe.efi missing at $efiguard" }
if (-not (Test-Path "S:\EFI\Boot\startup.nsh")) { throw "Spoofer startup.nsh missing - wrong ESP state?" }
if (-not (Test-Path "S:\EFI\Boot\bootx64.efi")) { throw "Spoofer bootx64.efi missing" }
if (-not (Test-Path "S:\EFI\Boot\mp.efi")) { throw "Spoofer mp.efi missing" }
if (-not (Test-Path "S:\EFI\Microsoft\Boot\boot.efi")) { throw "Renamed bootmgfw (boot.efi) missing" }

# 1. Backup originals (idempotent)
if (-not (Test-Path "S:\EFI\Boot\startup.nsh.spoofer-only")) {
    Copy-Item "S:\EFI\Boot\startup.nsh" "S:\EFI\Boot\startup.nsh.spoofer-only" -Force
    Write-Host "BACKUP_CREATED: startup.nsh.spoofer-only"
}

# 2. Stage Ophion
New-Item -ItemType Directory -Force "S:\EFI\Mongil"   | Out-Null
New-Item -ItemType Directory -Force "S:\EFI\EfiGuard" | Out-Null
New-Item -ItemType Directory -Force "S:\EFI\Ophion"   | Out-Null
Copy-Item "$build\Loader.efi"     "S:\EFI\Mongil\Loader.efi"          -Force
Copy-Item $efiguard               "S:\EFI\EfiGuard\EfiGuardDxe.efi"   -Force
Copy-Item "$build\OphionDxe.efi"  "S:\EFI\Ophion\OphionDxe.efi"       -Force
Write-Host ""
Write-Host "Staged:"
Write-Host "  S:\EFI\Mongil\Loader.efi    = $((Get-FileHash 'S:\EFI\Mongil\Loader.efi' -Algorithm SHA256).Hash.Substring(0,16))"
Write-Host "  S:\EFI\EfiGuard\EfiGuardDxe = $((Get-FileHash 'S:\EFI\EfiGuard\EfiGuardDxe.efi' -Algorithm SHA256).Hash.Substring(0,16))"
Write-Host "  S:\EFI\Ophion\OphionDxe     = $((Get-FileHash 'S:\EFI\Ophion\OphionDxe.efi' -Algorithm SHA256).Hash.Substring(0,16))"

# 3. New startup.nsh (chain via Mongil before fallback to boot.efi)
$newScript = @'
load -nc fs0:\EFI\Boot\bpg.efi
load -nc fs0:\EFI\Boot\mp.efi
cls
fs0:\EFI\Mongil\Loader.efi
fs0:\EFI\Microsoft\Boot\boot.efi

load -nc fs1:\EFI\Boot\bpg.efi
load -nc fs1:\EFI\Boot\mp.efi
cls
fs1:\EFI\Mongil\Loader.efi
fs1:\EFI\Microsoft\Boot\boot.efi

load -nc fs2:\EFI\Boot\bpg.efi
load -nc fs2:\EFI\Boot\mp.efi
cls
fs2:\EFI\Mongil\Loader.efi
fs2:\EFI\Microsoft\Boot\boot.efi

load -nc fs3:\EFI\Boot\bpg.efi
load -nc fs3:\EFI\Boot\mp.efi
cls
fs3:\EFI\Mongil\Loader.efi
fs3:\EFI\Microsoft\Boot\boot.efi

load -nc fs4:\EFI\Boot\bpg.efi
load -nc fs4:\EFI\Boot\mp.efi
cls
fs4:\EFI\Mongil\Loader.efi
fs4:\EFI\Microsoft\Boot\boot.efi

load -nc fs5:\EFI\Boot\bpg.efi
load -nc fs5:\EFI\Boot\mp.efi
cls
fs5:\EFI\Mongil\Loader.efi
fs5:\EFI\Microsoft\Boot\boot.efi

load -nc fs6:\EFI\Boot\bpg.efi
load -nc fs6:\EFI\Boot\mp.efi
cls
fs6:\EFI\Mongil\Loader.efi
fs6:\EFI\Microsoft\Boot\boot.efi

load -nc fs7:\EFI\Boot\bpg.efi
load -nc fs7:\EFI\Boot\mp.efi
cls
fs7:\EFI\Mongil\Loader.efi
fs7:\EFI\Microsoft\Boot\boot.efi
exit
'@

# Write ASCII (UEFI shell expects 8-bit)
[IO.File]::WriteAllText("S:\EFI\Boot\startup.nsh", $newScript, [Text.Encoding]::ASCII)
Write-Host ""
Write-Host "Updated startup.nsh - Mongil/Loader.efi inserted before boot.efi fallback"

Write-Host ""
Write-Host "----- NEXT -----"
Write-Host "Reboot. Spoofer will run, then MongilLoader chains EfiGuardDxe + OphionDxe + boot.efi."
Write-Host "Verify:"
Write-Host "  - HWID still spoofed (Get-CimInstance Win32_BIOS | SerialNumber)"
Write-Host "  - VMM alive (read_ophn_log.ps1 -> OphnLastErr=VMLAUNCH_SUCCESS)"
Write-Host ""
Write-Host "Recovery if hang/freeze:"
Write-Host "  Boot Windows installer USB -> Shift+F10 cmd:"
Write-Host "    diskpart"
Write-Host "    list vol"
Write-Host "    sel vol N (the EFI partition)"
Write-Host "    assign letter=X"
Write-Host "    exit"
Write-Host "    move X:\EFI\Boot\startup.nsh.spoofer-only X:\EFI\Boot\startup.nsh"
