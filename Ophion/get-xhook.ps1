$src = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class XhookClient {
    const uint GENERIC_READ        = 0x80000000;
    const uint GENERIC_WRITE       = 0x40000000;
    const uint OPEN_EXISTING       = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    // FILE_DEVICE_UNKNOWN=0x22, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0
    const uint IOCTL_HV_XH_GET_LOG = (0x22 << 16) | (0 << 14) | (0x802 << 2) | 0;
    const uint IOCTL_HV_XH_STATUS  = (0x22 << 16) | (0 << 14) | (0x805 << 2) | 0;

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

    public static void DumpStatus() {
        using (var h = CreateFile(@"\\.\Ophion", GENERIC_READ | GENERIC_WRITE, 0,
                                  IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero)) {
            if (h.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

            byte[] sbuf = new byte[64];
            uint sret;
            if (!DeviceIoControl(h, IOCTL_HV_XH_STATUS, IntPtr.Zero, 0, sbuf, (uint)sbuf.Length, out sret, IntPtr.Zero))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "STATUS failed");

            // XH_IOCTL_STATUS: BOOLEAN(1) + pad(7) + UINT64 base + UINT64 hook_va + UINT32 log_count + UINT32 total
            byte active = sbuf[0];
            ulong xbase = BitConverter.ToUInt64(sbuf, 8);
            ulong hookva = BitConverter.ToUInt64(sbuf, 16);
            uint logc = BitConverter.ToUInt32(sbuf, 24);
            uint total = BitConverter.ToUInt32(sbuf, 28);
            Console.WriteLine("[xhook] active={0} base=0x{1:X} hook_va=0x{2:X} log_count={3} total_intercepted={4}",
                              active, xbase, hookva, logc, total);

            byte[] lbuf = new byte[24 * 1024];
            uint lret;
            if (!DeviceIoControl(h, IOCTL_HV_XH_GET_LOG, IntPtr.Zero, 0, lbuf, (uint)lbuf.Length, out lret, IntPtr.Zero))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "GET_LOG failed");

            // XH_LOG_ENTRY: UINT64 tsc + UINT64 cr3 + UINT32 cmd + UINT32 action = 24 bytes
            int n = (int)(lret / 24);
            Console.WriteLine("[xhook] {0} log entries", n);
            for (int i = 0; i < n; i++) {
                int off = i * 24;
                ulong tsc = BitConverter.ToUInt64(lbuf, off);
                ulong cr3 = BitConverter.ToUInt64(lbuf, off + 8);
                uint cmd = BitConverter.ToUInt32(lbuf, off + 16);
                uint act = BitConverter.ToUInt32(lbuf, off + 20);
                string actn = act == 0 ? "PASS" : act == 1 ? "BLOCK" : act == 2 ? "LOG" : "?";
                Console.WriteLine("  [{0}] tsc=0x{1:X} cr3=0x{2:X} cmd={3} action={4} ({5})",
                                  i, tsc, cr3, cmd, act, actn);
            }
        }
    }
}
"@
Add-Type -TypeDefinition $src -Language CSharp
[XhookClient]::DumpStatus()
