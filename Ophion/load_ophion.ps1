#requires -RunAsAdministrator
# load_ophion.ps1 - Disable DSE via EfiDSEFix, start Ophion service.
#
# Prereq: system was booted with EfiGuard (USB or ESP). See:
#   .tools\EfiGuard\setup_efiguard_usb.ps1
#
# Workflow:
#   1. EfiDSEFix.exe -d   (DSE off until next reboot, no PatchGuard conflict)
#   2. Create Ophion service if missing
#   3. sc start Ophion
#
# Why no DSE restore: EfiGuard disabled PG at boot, and DSE-off persists
# until reboot anyway. Restoring is unnecessary and adds complexity.

$ErrorActionPreference = 'Stop'

$EfiDSEFix = "C:\Users\AmangLy\Documents\learning\.tools\EfiGuard\EfiGuard-v1.4\EfiDSEFix.exe"
$OphionSys = "C:\Users\AmangLy\Documents\learning\Ophion\build\bin\Release\Ophion.sys"
$ServiceName = "Ophion"

if (-not (Test-Path $EfiDSEFix)) { throw "EfiDSEFix not found: $EfiDSEFix" }
if (-not (Test-Path $OphionSys)) { throw "Ophion.sys not found: $OphionSys (build first)" }

# Quick already-running check
$state = (sc.exe query $ServiceName 2>&1 | Select-String 'STATE') -join ''
if ($state -match 'RUNNING') {
    Write-Host "[i] $ServiceName already RUNNING. Nothing to do."
    exit 0
}

Write-Host "[*] Disabling DSE via EfiDSEFix..."
$out = & $EfiDSEFix -d 2>&1 | Out-String
Write-Host $out

if ($LASTEXITCODE -ne 0) {
    Write-Warning "EfiDSEFix exit=$LASTEXITCODE. Did you boot with EfiGuard?"
    Write-Warning "If not, reboot via the EfiGuard USB and rerun this script."
    exit 1
}
if ($out -notmatch 'success' -and $out -notmatch 'patched' -and $out -notmatch 'disabled') {
    Write-Warning "EfiDSEFix output did not confirm success. Inspect output above."
}

# Create service if missing
$qc = sc.exe query $ServiceName 2>&1 | Out-String
if ($qc -match 'service does not exist|specified service does not exist|FAILED 1060') {
    Write-Host "[*] Creating service $ServiceName"
    & sc.exe create $ServiceName type= kernel binPath= $OphionSys | Out-Null
}

Write-Host "[*] Starting $ServiceName"
& sc.exe start $ServiceName | Out-Null
Start-Sleep -Milliseconds 800

$state = (sc.exe query $ServiceName 2>&1 | Select-String 'STATE') -join ''
Write-Host "[*] $ServiceName state: $state"
if ($state -match 'RUNNING') {
    Write-Host "[+] Ophion loaded. DSE remains disabled until next reboot."
} else {
    Write-Warning "Ophion did not reach RUNNING. Check Event Viewer / get-log.ps1."
    exit 1
}
