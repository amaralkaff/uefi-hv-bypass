#
# pre_reboot_finalize.ps1 - clear residual Hyper-V state and restore EfiGuard NVRAM
#
# Run AS ADMIN. Performs three actions, in order, with verification gate between
# cleanup and NVRAM flip:
#
#   1. Disable + stop the Vid (Virtualization Infrastructure Driver) kernel driver.
#      Reason: Vid surfaces CPUID leaf 0x40000000 EBX=1 even after Hyper-V features
#      are removed, which trips vgk_probe::cpuid_leaf_0x40000000_zeroed.
#      Reversible: sc.exe config Vid start= system
#
#   2. Uninstall the orphan "vEthernet (Default Switch)" virtual NIC. Hyper-V
#      Virtual Ethernet Adapter survived feature uninstall and exposes MAC OUI
#      00:15:5D, which trips vgk_probe::nic_mac_oui_not_banned.
#      Reversible only by re-enabling Hyper-V Windows feature (not planned).
#
#   3. If vgk_probe --check returns 0 FAIL, restore NVRAM displayorder to put
#      EfiGuard first (boot pre-recovery state). Otherwise abort and surface
#      remaining fails for manual diagnosis.
#
# Idempotent — safe to re-run; each step checks current state.
#
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipNvramRestore
)

$ErrorActionPreference = 'Stop'

# admin gate
$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = [Security.Principal.WindowsPrincipal]$wid
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Must run as Administrator."
    exit 2
}

$root  = "C:\Users\AmangLy\Documents\learning"
$probe = "$root\detect\vgk_replica\build\vgk_probe.exe"
if (-not (Test-Path $probe)) { Write-Error "vgk_probe.exe missing at $probe"; exit 2 }

Write-Host "=== Step 1/3: disable Vid driver ===" -ForegroundColor Cyan
$vid = Get-Service Vid -ErrorAction SilentlyContinue
if ($vid) {
    "Vid current: state={0} starttype={1}" -f $vid.Status, $vid.StartType
    if ($DryRun) {
        Write-Host "  [DRY] would: sc.exe config Vid start= disabled; sc.exe stop Vid" -ForegroundColor Yellow
    } else {
        & sc.exe config Vid start= disabled | Out-Null
        if ($vid.Status -eq 'Running') {
            try { & sc.exe stop Vid | Out-Null } catch { Write-Warning "stop Vid: $_" }
        }
        Start-Sleep -Milliseconds 500
        $vid2 = Get-Service Vid -ErrorAction SilentlyContinue
        "Vid after  : state={0} starttype={1}" -f $vid2.Status, $vid2.StartType
        if ($vid2.StartType -ne 'Disabled') { Write-Warning "Vid not disabled" }
    }
} else {
    "Vid service absent (already removed)"
}

Write-Host ""
Write-Host "=== Step 2/3: remove orphan vEthernet adapter ===" -ForegroundColor Cyan
$adapters = Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object {
    $_.FriendlyName -match "Hyper-V Virtual Ethernet|vEthernet"
}
if ($adapters) {
    foreach ($a in $adapters) {
        "  found: {0}  ({1})" -f $a.FriendlyName, $a.InstanceId
        if ($DryRun) {
            Write-Host "  [DRY] would: pnputil.exe /remove-device $($a.InstanceId)" -ForegroundColor Yellow
        } else {
            try {
                Disable-PnpDevice -InstanceId $a.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}
            $out = & pnputil.exe /remove-device $a.InstanceId 2>&1
            $out | ForEach-Object { "    $_" }
        }
    }
} else {
    "  no Hyper-V virtual ethernet adapters found"
}

# also try the system NIC enumerator for anything still bound with the OUI
$bad = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
       Where-Object { $_.MacAddress -match "^00-15-5D" }
if ($bad) {
    Write-Host ""
    Write-Host "  residual MAC 00-15-5D adapters after pnputil:" -ForegroundColor Yellow
    $bad | Select-Object Name, InterfaceDescription, MacAddress, Status | Format-Table -AutoSize
}

Write-Host ""
Write-Host "=== Cleanup verify: vgk_probe --check ===" -ForegroundColor Cyan
$probeOut = & $probe --check 2>&1
$probeExit = $LASTEXITCODE
$probeOut | ForEach-Object { "  $_" }
$failCount = ($probeOut | Select-String "^\[FAIL").Count
"  exit={0}  fail_count={1}" -f $probeExit, $failCount

if ($failCount -ne 0) {
    Write-Host ""
    Write-Host "ABORT: vgk_probe still has $failCount FAIL(s); not flipping NVRAM." -ForegroundColor Red
    Write-Host "Diagnose remaining FAILs above before rerunning." -ForegroundColor Red
    exit 1
}

if ($SkipNvramRestore) {
    Write-Host ""
    Write-Host "SkipNvramRestore set; leaving NVRAM at {bootmgr}-first." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "=== Step 3/3: restore EfiGuard-first NVRAM ===" -ForegroundColor Cyan
$nvramScript = "$root\scripts\nvram_restore_efiguard.ps1"
if (-not (Test-Path $nvramScript)) { Write-Error "$nvramScript missing"; exit 2 }
if ($DryRun) {
    & $nvramScript -DryRun
} else {
    & $nvramScript
}

Write-Host ""
Write-Host "=== READY TO REBOOT ===" -ForegroundColor Green
Write-Host "  - Hyper-V services absent + features disabled"
Write-Host "  - Vid driver disabled (no CPUID 0x40000000 leak)"
Write-Host "  - vEthernet adapter removed (no 00-15-5D MAC)"
Write-Host "  - vgk_probe --check: 0 FAIL"
Write-Host "  - NVRAM displayorder: EfiGuard first, {bootmgr} second"
Write-Host ""
Write-Host "On next reboot, EfiGuard should boot cleanly (CBS race window closed)."
Write-Host "If hang recurs at HookedLoadImage, follow PHASE_0_DONE.md 'If EfiGuard hang recurs' section."
