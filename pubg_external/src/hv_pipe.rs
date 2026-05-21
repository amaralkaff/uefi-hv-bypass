//! VMM VMCALL pipe through Ophion.sys ring 0 driver.
//!
//! Flow:
//!   user-mode  -> DeviceIoControl(\\\\.\\Ophion, IOCTL_HV_VMCALL_RELAY, request)
//!   ring 0    -> jumps into trampoline page (UEFI runtime VA)
//!   trampoline-> mov r10, MAGIC; vmcall
//!   VMM       -> vmexit reason=18, dispatches op via VmcallDispatch
//!   VMM       -> writes reply back via vmm_guest_write
//!   ring 0    -> returns to caller IOCTL
//!
//! All memory reads/writes happen in VMX-root host context, invisible to
//! BattlEye scans of NT object table or driver list.

use anyhow::{anyhow, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_NAME: &str = r"\\.\Ophion";

// IOCTL codes match Ophion/src/driver.c
const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}
const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;
const IOCTL_BASE: u32 = 0x800;

const IOCTL_HV_VMCALL_RELAY: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0x20, METHOD_BUFFERED, FILE_ANY_ACCESS);

#[repr(C)]
#[derive(Debug)]
pub struct Session {
    pub key: u64,
    handle: usize,
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                let _ = CloseHandle(HANDLE(self.handle as *mut _));
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub pid: u32,
    pub cr3: u64,
    pub base: u64,
    pub size: u64,
}

/// Open device handle to Ophion.sys.
fn open_device() -> Result<HANDLE> {
    let wide: Vec<u16> = DEVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = CreateFileW(
            PCWSTR(wide.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .context("CreateFile \\\\.\\Ophion failed - is Ophion.sys loaded?")?;
        Ok(h)
    }
}

/// VMCALL OP_REGISTER. Returns session key for subsequent ops.
pub fn register() -> Result<Session> {
    let handle = open_device()?;
    // TODO: wire actual VMCALL relay request struct matching VmcallHandler.c
    // For scaffold: stub session
    Ok(Session {
        key: 0xCAFEBABE_DEADBEEF,
        handle: handle.0 as usize,
    })
}

/// VMCALL OP_RESOLVE_TARGET. Locates process by image name, returns pid + cr3 + base.
pub fn resolve_target(_session: &Session, _name: &str) -> Result<Target> {
    // TODO: build OPHION_OP_RESOLVE_TARGET request, send via IOCTL_HV_VMCALL_RELAY
    Err(anyhow!("resolve_target: not yet wired"))
}

/// VMCALL OP_READ_MANY. Batched memory read via VMM (PT-walk in VMX-root).
pub fn read_many(_session: &Session, _addrs: &[u64], _out: &mut [u8]) -> Result<()> {
    Err(anyhow!("read_many: not yet wired"))
}

/// VMCALL OP_WRITE_MANY. Batched memory write.
pub fn write_many(_session: &Session, _addr: u64, _data: &[u8]) -> Result<()> {
    Err(anyhow!("write_many: not yet wired"))
}
