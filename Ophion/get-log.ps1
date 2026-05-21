$src = @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class OphionClient {
    const uint GENERIC_READ        = 0x80000000;
    const uint GENERIC_WRITE       = 0x40000000;
    const uint OPEN_EXISTING       = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    // CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x801, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    const uint IOCTL_HV_STATUS  = (0x22 << 16) | (0 << 14) | (0x800 << 2) | 0;
    const uint IOCTL_HV_GET_LOG = (0x22 << 16) | (0 << 14) | (0x801 << 2) | 0;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        byte[] lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    public static byte[] GetLog() {
        using (var h = CreateFile(@"\\.\Ophion", GENERIC_READ | GENERIC_WRITE, 0,
                                  IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero)) {
            if (h.IsInvalid)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateFile failed");

            byte[] buf = new byte[128 * 1024];
            uint bytes;
            if (!DeviceIoControl(h, IOCTL_HV_GET_LOG, IntPtr.Zero, 0, buf, (uint)buf.Length, out bytes, IntPtr.Zero))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DeviceIoControl failed");

            byte[] result = new byte[bytes];
            Array.Copy(buf, result, bytes);
            return result;
        }
    }

    public static uint GetStatus() {
        using (var h = CreateFile(@"\\.\Ophion", GENERIC_READ | GENERIC_WRITE, 0,
                                  IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero)) {
            if (h.IsInvalid)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateFile failed");

            byte[] buf = new byte[4];
            uint bytes;
            if (!DeviceIoControl(h, IOCTL_HV_STATUS, IntPtr.Zero, 0, buf, (uint)buf.Length, out bytes, IntPtr.Zero))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DeviceIoControl failed");

            return BitConverter.ToUInt32(buf, 0);
        }
    }
}
"@
Add-Type -TypeDefinition $src -Language CSharp

$cores = [OphionClient]::GetStatus()
Write-Output "Virtualized cores: $cores"
Write-Output "----- Ophion Debug Log -----"
$logBytes = [OphionClient]::GetLog()
[System.Text.Encoding]::ASCII.GetString($logBytes)
