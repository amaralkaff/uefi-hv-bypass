#
# post_reboot_verify.ps1 - run after Hyper-V removal reboot to confirm Phase 0 PASS
#
# Run this as the FIRST thing after rebooting following disable_hyperv.ps1.
# Validates:
#   - Hyper-V services no longer running
#   - Hyper-V Windows features no longer enabled
#   - CPUID 0x40000000 returns zeros (no HV vendor signature)
#   - No Hyper-V vSwitch MAC in active NIC list
#   - vgk_probe --check returns 0 fail (excluding probe_drv SKIPs)
#
# On all-PASS: dev rig is at Phase 0 baseline, ready for Phase 2 VMM port work.
#
[CmdletBinding()]
param([switch]$Json)

$ErrorActionPreference = 'Continue'
$root = "C:\Users\AmangLy\Documents\learning"
$results = [ordered]@{}
$details = [ordered]@{}

# 1. Hyper-V services
$hvServices = @("vmcompute", "vmms", "hvhost", "hvservice")
$running = @()
foreach ($s in $hvServices) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { $running += $s }
}
$results.HV_Services_Stopped = ($running.Count -eq 0)
$details.HV_Services_Stopped = if ($running) { "still running: $($running -join ', ')" } else { "all stopped" }

# 2. Hyper-V features
$hvFeatures = @("Microsoft-Hyper-V-All", "Microsoft-Hyper-V-Hypervisor", "VirtualMachinePlatform")
$enabled = @()
foreach ($f in $hvFeatures) {
    $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State
    if ($state -eq 'Enabled') { $enabled += $f }
}
$results.HV_Features_Disabled = ($enabled.Count -eq 0)
$details.HV_Features_Disabled = if ($enabled) { "still enabled: $($enabled -join ', ')" } else { "all disabled" }

# 3. CPUID 0x40000000 zeroed
$probe = "$root\detect\vgk_replica\build\vgk_probe.exe"
if (Test-Path $probe) {
    $probeOut = & $probe --check 2>&1
    $exit = $LASTEXITCODE
    $cpuidLine = $probeOut | Select-String "cpuid_leaf_0x40000000_zeroed"
    $results.CPUID_0x40000000_Zero = ($cpuidLine -match "PASS")
    $details.CPUID_0x40000000_Zero = ($cpuidLine | Out-String).Trim()

    $nicLine = $probeOut | Select-String "nic_mac_oui_not_banned"
    $results.NIC_MAC_OUI_Clean = ($nicLine -match "PASS")
    $details.NIC_MAC_OUI_Clean = ($nicLine | Out-String).Trim()

    $failCount = ($probeOut | Select-String "^\[FAIL").Count
    $results.VgkProbe_NoFails = ($failCount -eq 0)
    $details.VgkProbe_NoFails = "fail count = $failCount, exit code = $exit"
} else {
    $results.CPUID_0x40000000_Zero = $false
    $results.NIC_MAC_OUI_Clean    = $false
    $results.VgkProbe_NoFails     = $false
    $details.CPUID_0x40000000_Zero = "vgk_probe.exe missing at $probe"
    $details.NIC_MAC_OUI_Clean     = "vgk_probe.exe missing"
    $details.VgkProbe_NoFails      = "vgk_probe.exe missing"
}

# 4. CPUID hypervisor present bit
$hvBit = & $probe --check 2>&1 | Select-String "cpuid_hv_present_bit"
$results.CPUID_HV_Bit_Clear = ($hvBit -match "PASS")
$details.CPUID_HV_Bit_Clear = ($hvBit | Out-String).Trim()

# 5. testsigning + hypervisorlaunchtype
$bcd = bcdedit /enum '{current}' 2>&1
$results.HV_LaunchType_Off = ($bcd | Select-String "hypervisorlaunchtype.*Off") -ne $null
$details.HV_LaunchType_Off = ($bcd | Select-String "hypervisorlaunchtype" | Out-String).Trim()

# Emit
if ($Json) {
    @{ results = $results; details = $details } | ConvertTo-Json -Depth 4
} else {
    Write-Host ""
    Write-Host "===== POST-REBOOT VERIFY =====" -ForegroundColor Cyan
    foreach ($k in $results.Keys) {
        $v = $results.$k
        $color = if ($v) { "Green" } else { "Red" }
        $tag   = if ($v) { "PASS" } else { "FAIL" }
        Write-Host ("  [{0}] {1,-26} {2}" -f $tag, $k, $details.$k) -ForegroundColor $color
    }
    Write-Host ""
    if ($results.Values -contains $false) {
        Write-Host "POST-REBOOT GATE: FAIL -- Hyper-V did not fully clear; investigate red items" -ForegroundColor Red
        exit 1
    }
    Write-Host "POST-REBOOT GATE: PASS -- Phase 0 baseline clean. Ready for Phase 2 VMM porting." -ForegroundColor Green
    exit 0
}
