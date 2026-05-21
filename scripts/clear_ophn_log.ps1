#
# clear_ophn_log.ps1 - delete Ophion UEFI variables
#
# Clears OphnLastErr / OphnHostState / OphnPostLaunch from NV before reboot
# so post-boot read shows ONLY what current binary writes.
#
# RUN AS ADMIN.
#
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$signature = @"
using System;
using System.Runtime.InteropServices;

public static class FwVar {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
    public static extern bool SetFirmwareEnvironmentVariableA(
        string lpName, string lpGuid, IntPtr pBuffer, uint nSize);

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int RtlAdjustPrivilege(
        int Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
}
"@
Add-Type -TypeDefinition $signature

$prev = $false
[void][FwVar]::RtlAdjustPrivilege(22, $true, $false, [ref]$prev)

$guid = "{4f50484e-0000-0000-6f70-686e2d6c6f67}"
$names = @("OphnLastErr", "OphnHostState", "OphnPostLaunch", "OphnExit",
           "OphnGS1", "OphnGS2", "OphnGS3", "OphnMp", "OphnInit",
           "OphnApDispatch", "OphnInit3", "OphnSipi", "OphnApVmx",
           "OphnApTsc", "OphnAp1Vmx")

foreach ($n in $names) {
    # Setting size=0 with NULL buffer deletes the variable.
    $ok = [FwVar]::SetFirmwareEnvironmentVariableA($n, $guid, [IntPtr]::Zero, 0)
    if ($ok) {
        Write-Host "  cleared: $n" -ForegroundColor Green
    } else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq 203) {
            Write-Host "  absent : $n" -ForegroundColor DarkGray
        } else {
            Write-Host "  err $err on $n" -ForegroundColor Yellow
        }
    }
}
