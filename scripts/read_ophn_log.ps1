#
# read_ophn_log.ps1 - read Ophion VMM UEFI variable log from Windows
#
# Reads the OphnLastErr UEFI variable written by OphionDxe at boot.
# Vendor GUID {4f50484e-0000-0000-6f70-686e2d6c6f67}.
#
# RUN AS ADMIN. Auto-enables SeSystemEnvironmentPrivilege.
#
# Step #8 (Grill Q21-C): -CrashDump dumps the per-CPU exit-log snapshot
# the VMM flushed to OphnCrashDump on its way out via VMX abort or #MC.
# Blob layout matches MongilLoader/OphionDxe/VmmPerCpuLog.h:
#   [magic u64 = 'OPHNPCL\0'][cpu_count u32][rec_per_cpu u32][per-CPU rings...]
# Each ring: { head u32, seq u32, record[rec_per_cpu] }
# Each record (32B): { tsc u64, guest_rip u64, exit_qual u64,
#                      exit_reason u16, reserved u16, tag u32 }
#
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$CrashDump
)

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


if ($CrashDump) {
    Write-Host ""
    Write-Host "===== OPHION PER-CPU CRASH DUMP =====" -ForegroundColor Cyan

    # NV var capacity: 12-thread box -> 12 * 1032 + 16 = ~12.4 KB.
    # 32 KB covers up to 24 threads with margin.
    $blob = New-Object byte[] (32 * 1024)
    $sz = [FwVar]::GetFirmwareEnvironmentVariableA('OphnCrashDump', $guid,
                                                   $blob, $blob.Length)
    if ($sz -eq 0) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "OphnCrashDump absent (err=$err). VMM clean since last reset." -ForegroundColor Yellow
        return
    }

    if ($sz -lt 16) {
        Write-Host "OphnCrashDump truncated: $sz bytes (need >=16 for header)" -ForegroundColor Red
        return
    }

    $magic     = [BitConverter]::ToUInt64($blob, 0)
    $cpu_count = [BitConverter]::ToUInt32($blob, 8)
    $rec_per_cpu = [BitConverter]::ToUInt32($blob, 12)
    $expected_magic = [UInt64]0x4F50484E50434C00

    if ($magic -ne $expected_magic) {
        Write-Host ("Bad magic 0x{0:x16} (want 0x{1:x16})" -f $magic, $expected_magic) -ForegroundColor Red
        return
    }

    $ring_bytes = 8 + ($rec_per_cpu * 32)
    $need = 16 + ($cpu_count * $ring_bytes)
    Write-Host ("magic ok | cpu_count={0} rec_per_cpu={1} need={2}B got={3}B" -f $cpu_count, $rec_per_cpu, $need, $sz)
    if ($sz -lt $need) {
        Write-Host "  WARN: blob truncated by NV var size limit" -ForegroundColor Yellow
    }

    $off = 16
    for ($cpu = 0; $cpu -lt $cpu_count; $cpu++) {
        if (($off + $ring_bytes) -gt $sz) {
            Write-Host ("  cpu={0} (truncated)" -f $cpu) -ForegroundColor Yellow
            break
        }
        $head = [BitConverter]::ToUInt32($blob, $off)
        $seq  = [BitConverter]::ToUInt32($blob, $off + 4)
        $rec_off = $off + 8
        Write-Host ("  cpu={0} head={1} seq={2}" -f $cpu, $head, $seq)
        # Walk newest -> oldest. Newest = (head - 1) mod rec_per_cpu.
        $count = [Math]::Min([int]$seq, [int]$rec_per_cpu)
        for ($i = 0; $i -lt $count -and $i -lt 8; $i++) {
            $idx = (($head - 1 - $i) + $rec_per_cpu) % $rec_per_cpu
            $r = $rec_off + ($idx * 32)
            $tsc    = [BitConverter]::ToUInt64($blob, $r)
            $rip    = [BitConverter]::ToUInt64($blob, $r + 8)
            $qual   = [BitConverter]::ToUInt64($blob, $r + 16)
            $reason = [BitConverter]::ToUInt16($blob, $r + 24)
            $tag    = [BitConverter]::ToUInt32($blob, $r + 28)
            Write-Host ("    tsc=0x{0:x16} reason={1,4} qual=0x{2:x16} rip=0x{3:x16} tag=0x{4:x8}" -f $tsc, $reason, $qual, $rip, $tag)
        }
        $off += $ring_bytes
    }
    return
}
