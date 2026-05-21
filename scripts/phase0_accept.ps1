#
# phase0_accept.ps1 - Phase 0 acceptance gate for Ophion-vs-VGK bring-up
#
# Verifies test bench is ready before MongilLoader development starts.
# Run on bench-vanilla.vhdx after fresh ReviOS install + vanilla EfiGuard.
#
# Acceptance criteria (per Grill 17 + 18 + 19):
#   1. ReviOS 10 build 19045 installed
#   2. EfiGuard NVRAM entry first in firmware boot order
#   3. Secure Boot OFF
#   4. hypervisorlaunchtype OFF
#   5. testsigning OFF
#   6. Hyper-V NOT installed (no `vmcompute` / `vmms` services)
#   7. CrashControl enabled (dev VHD only) -- kdump captures BSOD minidumps
#   8. DebugView NOT running (test bench discipline)
#   9. vgk_probe baseline calibrated
#  10. vgk_probe --check reports 0 FAIL (bare-metal posture clean)
#  11. bench-vanilla.vhdx snapshot exists
#
# Run with --post-bsod after a forced NotMyFault BSOD to verify kdump path.
#
[CmdletBinding()]
param(
    [switch]$PostBsod,
    [string]$SnapshotPath = "D:\snapshots\bench-vanilla.vhdx",
    [string]$VgkProbePath = "C:\Users\AmangLy\Documents\learning\detect\vgk_replica\bin\vgk_probe.exe",
    [switch]$Json
)

$ErrorActionPreference = 'Continue'
$results = [ordered]@{}
$details = [ordered]@{}

# 1. OS version
$ver = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$results.OS_19045    = ($ver -eq "19045")
$details.OS_19045    = "BuildNumber=$ver"

# 2. EfiGuard NVRAM entry present
$boot = bcdedit /enum firmware 2>&1
$efiGuardGuid = "311ec363-3c3b-11f1-b1ec-00e04c6a389d"
$hasEfiGuard = ($boot | Select-String -SimpleMatch $efiGuardGuid) -ne $null
$results.EfiGuard_NVRAM = $hasEfiGuard
$details.EfiGuard_NVRAM = if ($hasEfiGuard) { "$efiGuardGuid found" } else { "EfiGuard NVRAM entry missing" }

# 3. Secure Boot OFF
try {
    $sb = Confirm-SecureBootUEFI
    $results.SecureBoot_OFF = ($sb -eq $false)
    $details.SecureBoot_OFF = "Confirm-SecureBootUEFI=$sb"
} catch {
    $results.SecureBoot_OFF = $false
    $details.SecureBoot_OFF = "Confirm-SecureBootUEFI threw (likely not in UEFI mode): $($_.Exception.Message)"
}

# 4. hypervisorlaunchtype OFF
$hvlt = bcdedit /enum '{current}' 2>&1 | Select-String "hypervisorlaunchtype"
$results.HV_LaunchType_OFF = ($hvlt -match "off")
$details.HV_LaunchType_OFF = if ($hvlt) { ($hvlt | Out-String).Trim() } else { "hypervisorlaunchtype not set (= default auto, FAIL)" }

# 5. testsigning OFF
$ts = bcdedit /enum '{current}' 2>&1 | Select-String "testsigning"
$results.TestSigning_OFF = (-not ($ts -match "Yes"))
$details.TestSigning_OFF = if ($ts) { ($ts | Out-String).Trim() } else { "testsigning not present (= No, OK)" }

# 6. Hyper-V not installed
$vmcompute = Get-Service vmcompute -ErrorAction SilentlyContinue
$vmms      = Get-Service vmms      -ErrorAction SilentlyContinue
$results.HyperV_Absent = (-not $vmcompute) -and (-not $vmms)
$details.HyperV_Absent = "vmcompute=$($vmcompute.Status) vmms=$($vmms.Status)"

# 7. CrashControl enabled (dev VHD only; flip expectation for test VHD)
$cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
$results.CrashControl_Enabled = ($cc.CrashDumpEnabled -in 1, 2, 3, 7)
$details.CrashControl_Enabled = "CrashDumpEnabled=$($cc.CrashDumpEnabled)"

# 8. DebugView not running
$dbg = Get-Process dbgview, Dbgview, DebugView -ErrorAction SilentlyContinue
$results.NoDebugView = ($null -eq $dbg)
$details.NoDebugView = if ($dbg) { "DebugView running (PID $($dbg.Id)) -- KILL before Vanguard tests" } else { "not running" }

# 9. vgk_probe baseline calibrated
$baselinePath = "$env:LOCALAPPDATA\vgk_probe\baseline.json"
$results.VgkProbe_Calibrated = (Test-Path $baselinePath)
$details.VgkProbe_Calibrated = if (Test-Path $baselinePath) { $baselinePath } else { "$baselinePath missing -- run vgk_probe.exe --calibrate" }

# 10. vgk_probe --check passes
if ((Test-Path $VgkProbePath) -and $results.VgkProbe_Calibrated) {
    $probeOut = & $VgkProbePath --check --json 2>&1
    $exit = $LASTEXITCODE
    # exit 0 = all PASS, 2 = at least one SKIP (probe_drv not loaded) but no FAILs.
    # Either is acceptable for Phase 0 — kernel-companion probes are optional.
    $results.VgkProbe_AllPass = ($exit -eq 0 -or $exit -eq 2)
    $details.VgkProbe_AllPass = "exit=$exit"
    if (-not $Json) {
        Write-Host "----- vgk_probe.exe --check output -----"
        & $VgkProbePath --check
        Write-Host "----------------------------------------"
    }
} else {
    $results.VgkProbe_AllPass = $false
    $details.VgkProbe_AllPass = if (-not (Test-Path $VgkProbePath)) { "$VgkProbePath missing -- build it first" } else { "calibration missing" }
}

# 11. Snapshot exists
$results.Snapshot_Exists = Test-Path $SnapshotPath
$details.Snapshot_Exists = $SnapshotPath

# Optional: post-BSOD verification path
if ($PostBsod) {
    $dump = Test-Path "$env:SystemRoot\MEMORY.DMP"
    $results.PostBsod_DumpWritten = $dump
    $details.PostBsod_DumpWritten = if ($dump) { "$env:SystemRoot\MEMORY.DMP exists" } else { "MEMORY.DMP missing -- kdump not working" }
}

# Emit
if ($Json) {
    $obj = @{ results = $results; details = $details }
    $obj | ConvertTo-Json -Depth 4
} else {
    Write-Host ""
    Write-Host "===== PHASE 0 ACCEPTANCE =====" -ForegroundColor Cyan
    foreach ($k in $results.Keys) {
        $v = $results.$k
        $color = if ($v) { "Green" } else { "Red" }
        $tag   = if ($v) { "PASS" } else { "FAIL" }
        Write-Host ("  [{0}] {1,-28} {2}" -f $tag, $k, $details.$k) -ForegroundColor $color
    }
    Write-Host ""
    if ($results.Values -contains $false) {
        Write-Host "PHASE 0 GATE: FAIL -- address red items before proceeding to Phase 1" -ForegroundColor Red
        exit 1
    }
    Write-Host "PHASE 0 GATE: PASS -- proceed to Phase 1 (MongilLoader empty scaffold)" -ForegroundColor Green
    exit 0
}
