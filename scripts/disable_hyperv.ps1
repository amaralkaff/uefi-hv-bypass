#
# disable_hyperv.ps1 - remove Hyper-V Windows feature so Ophion VMM can run
#
# vgk_probe FAIL on this dev rig:
#   - cpuid_leaf_0x40000000 = 0:1:0:0 (Hyper-V root partition advertised)
#   - nic_mac_oui_not_banned matches 00:15:5D (Hyper-V vSwitch)
#
# Both root cause: Hyper-V Windows feature enabled even though
# hypervisorlaunchtype is OFF. Services vmcompute + vmms autostart, vSwitch
# adapter persists, CPUID synthesis remains.
#
# This script disables the feature and stops the related services. REQUIRES
# REBOOT to take effect. After reboot, vgk_probe should report all PASS.
#
# RUN AS ADMIN.
#
[CmdletBinding()]
param(
    [switch]$NoRestart,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Run-Cmd {
    param([string]$Cmd, [scriptblock]$Block)
    Write-Host "  $Cmd" -ForegroundColor Cyan
    if (-not $DryRun) { & $Block }
}

Write-Host "=== Hyper-V state BEFORE ==="
$features = @(
    "Microsoft-Hyper-V-All",
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-Hypervisor",
    "Microsoft-Hyper-V-Services",
    "Microsoft-Hyper-V-Management-Clients",
    "Microsoft-Hyper-V-Tools-All",
    "VirtualMachinePlatform",
    "HypervisorPlatform",
    "Containers",
    "Containers-DisposableClientVM"
)
foreach ($f in $features) {
    $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State
    if ($state) { Write-Host "  $f = $state" }
}

Write-Host ""
Write-Host "=== Disabling features ==="
foreach ($f in $features) {
    $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State
    if ($state -eq 'Enabled') {
        Run-Cmd "Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart" {
            Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

Write-Host ""
Write-Host "=== bcdedit hypervisorlaunchtype ==="
Run-Cmd "bcdedit /set hypervisorlaunchtype off" {
    bcdedit /set hypervisorlaunchtype off
}

Write-Host ""
Write-Host "=== Stop + disable services ==="
$services = @("vmcompute", "vmms", "hvhost", "hvservice", "vmickvpexchange",
              "vmicheartbeat", "vmicrdv", "vmicshutdown", "vmictimesync",
              "vmicvmsession", "vmicvss", "vmicguestinterface")
foreach ($s in $services) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Run-Cmd "sc stop $s" { Stop-Service $s -Force -ErrorAction SilentlyContinue }
    }
    if ($svc -and $svc.StartType -ne 'Disabled') {
        Run-Cmd "sc config $s start=disabled" {
            Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ""
Write-Host "=== DONE ==="
if ($DryRun) {
    Write-Host "Dry run; no changes applied. Re-run without -DryRun." -ForegroundColor Yellow
    return
}
if ($NoRestart) {
    Write-Host "REBOOT REQUIRED. Re-run vgk_probe.exe --check after reboot." -ForegroundColor Yellow
} else {
    Write-Host "Rebooting in 10s. Press Ctrl+C to abort." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
