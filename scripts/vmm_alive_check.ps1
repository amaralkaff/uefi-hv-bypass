#
# vmm_alive_check.ps1 - verify VMM still intercepting CPUID on BSP
#
# Spawns vgk_probe pinned to core 0 (BSP). VMM is BSP-only in Phase 2.7.
# Without VMM: CPUID = ~1527 cycles (baseline)
# With VMM:    CPUID = vmexit + handler + vmresume = expect 3000+ cycles
#
[CmdletBinding()]
param(
    [int]$Core = 0,
    [int]$Iters = 5
)

$probe = "C:\Users\AmangLy\Documents\learning\detect\vgk_replica\build\vgk_probe.exe"

if (-not (Test-Path $probe)) {
    Write-Error "vgk_probe.exe missing"
    exit 1
}

$mask = [int64]1 -shl $Core
Write-Host "Pinning to core $Core (mask=0x$([Convert]::ToString($mask,16)))" -ForegroundColor Cyan
Write-Host "Baseline (no VMM): p50=1527 p99=1724"
Write-Host ""

$results = @()
for ($i = 1; $i -le $Iters; $i++) {
    $tmp = "$env:TEMP\vmm_alive_$i.txt"
    Remove-Item $tmp -ErrorAction SilentlyContinue

    # cmd start /AFFINITY sets affinity at CreateProcess time (no race).
    # Empty "" first arg = window title, otherwise cmd treats exe path as title.
    $hex = [Convert]::ToString($mask, 16)
    & cmd /c "start `"`" /B /WAIT /AFFINITY $hex `"$probe`" --check > `"$tmp`""
    $out = Get-Content $tmp -Raw

    $line = ($out -split "`r?`n") | Where-Object { $_ -match "timing_rdtsc_cpuid_delta" } | Select-Object -First 1
    if ($line -match "p50=(\d+) p99=(\d+)") {
        $p50 = [int]$Matches[1]
        $p99 = [int]$Matches[2]
        Write-Host ("  iter {0}:  p50={1,-6} p99={2}" -f $i, $p50, $p99)
        $results += [PSCustomObject]@{p50=$p50; p99=$p99}
    } else {
        Write-Host ("  iter {0}: parse failed" -f $i)
        Write-Host ($out | Out-String)
    }
}

if ($results.Count -gt 0) {
    $avgP50 = ($results | Measure-Object p50 -Average).Average
    $avgP99 = ($results | Measure-Object p99 -Average).Average
    Write-Host ""
    Write-Host ("Average over {0} iterations: p50={1:N0} p99={2:N0}" -f $results.Count, $avgP50, $avgP99) -ForegroundColor Cyan
    if ($avgP50 -gt 1900) {
        Write-Host ("VMM ACTIVE on core {0} (+{1:N0} cycles per CPUID = vmexit overhead)" -f $Core, ($avgP50 - 1527)) -ForegroundColor Green
    } elseif ($avgP50 -lt 1700) {
        Write-Host "VMM not visible on core $Core (baseline timing — BSP-only VMM, AP not virtualized yet)" -ForegroundColor Yellow
    } else {
        Write-Host "Inconclusive — between baseline and intercept range" -ForegroundColor Yellow
    }
}
