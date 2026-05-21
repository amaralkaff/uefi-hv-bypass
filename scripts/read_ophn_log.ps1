#
# read_ophn_log.ps1 - read Ophion VMM UEFI variable log from Windows
#
# Reads the OphnLastErr UEFI variable written by OphionDxe at boot.
# Vendor GUID {4f50484e-0000-0000-6f70-686e2d6c6f67}.
#
# RUN AS ADMIN. Auto-enables SeSystemEnvironmentPrivilege.
#
[CmdletBinding()]
param([switch]$Json)

$ErrorActionPreference = 'Stop'

$signature = @"
using System;
using System.Runtime.InteropServices;

public static class FwVar {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
    public static extern uint GetFirmwareEnvironmentVariableA(
        string lpName, string lpGuid, byte[] pBuffer, uint nSize);

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int RtlAdjustPrivilege(
        int Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
}
"@
Add-Type -TypeDefinition $signature -ErrorAction SilentlyContinue

# Privilege #22 = SeSystemEnvironmentPrivilege. RtlAdjustPrivilege is simpler
# than the Open/Lookup/Adjust dance and bypasses the struct-layout pitfall.
$prev = $false
$status = [FwVar]::RtlAdjustPrivilege(22, $true, $false, [ref]$prev)
if ($status -ne 0) {
    Write-Warning "RtlAdjustPrivilege returned NTSTATUS 0x{0:x}; need admin?" -f $status
}

$guid = "{4f50484e-0000-0000-6f70-686e2d6c6f67}"
$names = @("OphnLastErr", "OphnHostState", "OphnPostLaunch", "OphnExit",
           "OphnGS1", "OphnGS2", "OphnGS3", "OphnMp", "OphnInit",
           "OphnApDispatch", "OphnInit3", "OphnSipi", "OphnApVmx",
           "OphnApTsc", "OphnAp1Vmx", "OphnLbr", "OphnMsrLoadFail",
           "OphnMsrLoad", "OphnFirstBad")

$results = [ordered]@{}
foreach ($n in $names) {
    $buf = New-Object byte[] 512
    $sz = [FwVar]::GetFirmwareEnvironmentVariableA($n, $guid, $buf, 512)
    if ($sz -eq 0) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $results[$n] = "(absent or error: $err)"
    } else {
        $results[$n] = [System.Text.Encoding]::ASCII.GetString($buf, 0, $sz)
    }
}

if ($Json) {
    $results | ConvertTo-Json
} else {
    Write-Host ""
    Write-Host "===== OPHION UEFI VAR LOG =====" -ForegroundColor Cyan
    foreach ($k in $results.Keys) {
        "  {0,-20}  {1}" -f $k, $results[$k]
    }
}
