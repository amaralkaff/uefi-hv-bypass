#
# nvram_restore_efiguard.ps1 - restore EfiGuard-first NVRAM displayorder
#
# Run this AFTER:
#   1. Recovery boot via {bootmgr} succeeded
#   2. Windows fully booted (login + desktop reached)
#   3. CBS finished Hyper-V removal cleanup
#   4. post_reboot_verify.ps1 reports PASS
#
# Action: flips displayorder back to EfiGuard first, {bootmgr} second.
# Firmware will then boot EfiGuard by default (matches pre-recovery state).
#
# RUN AS ADMIN.
#
[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'

$EfiGuardGuid = '{311ec363-3c3b-11f1-b1ec-00e04c6a389d}'

Write-Host "=== Current displayorder ==="
bcdedit /enum '{fwbootmgr}' 2>&1 | Select-String "displayorder|^\s+\{"

if ($DryRun) {
    Write-Host "`nDry run; would set: bcdedit /set '{fwbootmgr}' displayorder $EfiGuardGuid '{bootmgr}'" -ForegroundColor Yellow
    return
}

Write-Host "`n=== Restoring EfiGuard-first ==="
& bcdedit /set '{fwbootmgr}' displayorder $EfiGuardGuid '{bootmgr}' 2>&1

Write-Host "`n=== After restore ==="
bcdedit /enum '{fwbootmgr}' 2>&1 | Select-String "displayorder|^\s+\{"

Write-Host "`n=== Reboot to test ==="
Write-Host "EfiGuard should now hand off to bootmgfw cleanly because CBS finished."
Write-Host "If hang recurs at HookedLoadImage of bootmgfw.efi: EfiGuard v1.4 is incompatible with"
Write-Host "current ntoskrnl build; rebuild from Mattiwatti/EfiGuard master."
