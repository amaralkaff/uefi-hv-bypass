//! VMM VMCALL pipe through Ophion.sys ring 0 driver.
//!
//! Flow (Grill plan, steps #3-#7):
//!   user-mode  -> DeviceIoControl(\\?\GLOBALROOT\Device\MsftHidIo, IOCTL_HV_*, struct)
//!   ring 0    -> KeStackAttachProcess(caller), jmp trampoline VA
//!   trampoline-> mov rcx,MAGIC; jmp rax (shuffles regs, emits VMCALL, RETs)
//!   VMM       -> vmexit reason=18, dispatches op via VmcallDispatch
//!   VMM       -> writes reply into caller buffer (system VA from MDL)
//!   ring 0    -> returns IOCTL with response in OutputBuffer
//!
//! ABI structs mirror MongilLoader/include/OphionAbi.h byte-for-byte.

use anyhow::{anyhow, bail, Context, Result};
use std::mem::{size_of, zeroed};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_NAME: &str = r"\\?\GLOBALROOT\Device\MsftHidIo";

const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const METHOD_OUT_DIRECT: u32 = 2;
const FILE_ANY_ACCESS: u32 = 0;
const IOCTL_BASE: u32 = 0x800;

const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_HV_STATUS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_GET_LOG: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_REGISTER: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_RESOLVE: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_UNREGISTER: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_HV_READ_SCATTER: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_OUT_DIRECT, FILE_ANY_ACCESS);
const IOCTL_HV_WRITE_MANY: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const OPHION_STATUS_OK: u32 = 0;
pub const OPHION_STATUS_NOT_REGISTERED: u32 = 1;
pub const OPHION_STATUS_IMAGE_HASH_MISMATCH: u32 = 2;
pub const OPHION_STATUS_SESSION_INVALID: u32 = 3;
pub const OPHION_STATUS_TARGET_NOT_FOUND: u32 = 4;
pub const OPHION_STATUS_READ_FAILED: u32 = 5;
pub const OPHION_STATUS_INVALID_ARG: u32 = 6;
pub const OPHION_STATUS_WRITE_FAILED: u32 = 7;

pub const READ_SCATTER_MAX_ENTRIES: usize = 1024;
pub const WRITE_MANY_MAX_ENTRIES: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct RegisterReq {
    image_sha256: [u8; 32],
    image_base: u64,
    image_size: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RegisterResp {
    session_key: u64,
    ophion_version: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResolveReq {
    target_name: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResolveResp {
    target_pid: u32,
    image_size: u32,
    image_base: u64,
    status: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScatterEntry {
    pub src_va: u64,
    pub len: u32,
    pub out_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadScatterReq {
    target_pid: u32,
    entry_count: u32,
    out_buf_va: u64,
    out_buf_size: u32,
    reserved: u32,
    entries: [ScatterEntry; READ_SCATTER_MAX_ENTRIES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadScatterResp {
    pub ok_count: u32,
    pub fail_count: u32,
    pub total_bytes: u32,
    pub status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WriteEntry {
    pub src_va: u64,
    pub dst_va: u64,
    pub len: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WriteManyReq {
    target_pid: u32,
    entry_count: u32,
    entries: [WriteEntry; WRITE_MANY_MAX_ENTRIES],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WriteManyResp {
    bytes_written: [u32; WRITE_MANY_MAX_ENTRIES],
    status: u32,
    reserved: u32,
}

pub struct Session {
    pub key: u64,
    handle: HANDLE,
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.key != 0 {
            let _ = unregister_inner(self.handle);
            self.key = 0;
        }
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub pid: u32,
    pub base: u64,
    pub size: u32,
}

fn open_device() -> Result<HANDLE> {
    let wide: Vec<u16> = DEVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .with_context(|| format!("CreateFile {DEVICE_NAME} failed - is Ophion.sys loaded?"))
    }
}

unsafe fn ioctl(
    h: HANDLE,
    code: u32,
    in_buf: Option<&[u8]>,
    out_buf: Option<&mut [u8]>,
) -> Result<u32> {
    let (in_ptr, in_size) = match in_buf {
        Some(b) => (b.as_ptr() as *const _, b.len() as u32),
        None => (std::ptr::null(), 0),
    };
    let (out_ptr, out_size) = match out_buf {
        Some(b) => (b.as_mut_ptr() as *mut _, b.len() as u32),
        None => (std::ptr::null_mut(), 0),
    };
    let mut returned: u32 = 0;
    DeviceIoControl(
        h,
        code,
        Some(in_ptr),
        in_size,
        Some(out_ptr),
        out_size,
        Some(&mut returned),
        None,
    )
    .with_context(|| format!("DeviceIoControl(code={code:#x}) failed"))?;
    Ok(returned)
}

pub fn hv_status() -> Result<u32> {
    let h = open_device()?;
    let mut out = [0u8; 4];
    let _ = unsafe { ioctl(h, IOCTL_HV_STATUS, None, Some(&mut out))? };
    unsafe {
        let _ = CloseHandle(h);
    }
    Ok(u32::from_le_bytes(out))
}

pub fn get_log(buf: &mut [u8]) -> Result<usize> {
    let h = open_device()?;
    let n = unsafe { ioctl(h, IOCTL_HV_GET_LOG, None, Some(buf))? };
    unsafe {
        let _ = CloseHandle(h);
    }
    Ok(n as usize)
}

pub fn register() -> Result<Session> {
    let h = open_device()?;

    let req = RegisterReq {
        image_sha256: [0; 32],
        image_base: 0,
        image_size: 0,
        reserved: 0,
    };
    let in_bytes: [u8; size_of::<RegisterReq>()] = unsafe { std::mem::transmute(req) };
    let mut resp_bytes = [0u8; size_of::<RegisterResp>()];

    unsafe {
        ioctl(h, IOCTL_HV_REGISTER, Some(&in_bytes), Some(&mut resp_bytes))?;
    }
    let resp: RegisterResp = unsafe { std::ptr::read(resp_bytes.as_ptr() as *const _) };
    if resp.status != OPHION_STATUS_OK {
        unsafe {
            let _ = CloseHandle(h);
        }
        bail!("REGISTER rejected by VMM (status={})", resp.status);
    }
    Ok(Session {
        key: resp.session_key,
        handle: h,
    })
}

pub fn resolve_target(session: &Session, name: &str) -> Result<Target> {
    let mut req = ResolveReq {
        target_name: [0; 16],
    };
    let bytes = name.as_bytes();
    let copy_len = bytes.len().min(15);
    req.target_name[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let in_bytes: [u8; size_of::<ResolveReq>()] = unsafe { std::mem::transmute(req) };
    let mut resp_bytes = [0u8; size_of::<ResolveResp>()];

    unsafe {
        ioctl(
            session.handle,
            IOCTL_HV_RESOLVE,
            Some(&in_bytes),
            Some(&mut resp_bytes),
        )?;
    }
    let resp: ResolveResp = unsafe { std::ptr::read(resp_bytes.as_ptr() as *const _) };
    if resp.status != OPHION_STATUS_OK {
        bail!(
            "RESOLVE failed for {name:?} (status={}): target not found?",
            resp.status
        );
    }
    Ok(Target {
        pid: resp.target_pid,
        base: resp.image_base,
        size: resp.image_size,
    })
}

/// Gathered scatter read.
///
/// `entries` describe (src_va, len, out_offset) per read.
/// Returns the gather buffer; the first 16 bytes are `ReadScatterResp` (header),
/// per-entry results are at `out_offset` (caller-supplied) within the same buffer.
/// Caller-supplied `out_offset` must be >= 16 to avoid clobbering header.
pub fn read_scatter(
    session: &Session,
    entries: &[ScatterEntry],
    gather_size: usize,
) -> Result<(ReadScatterResp, Vec<u8>)> {
    if entries.is_empty() || entries.len() > READ_SCATTER_MAX_ENTRIES {
        bail!("scatter entry_count out of range: {}", entries.len());
    }
    if gather_size < size_of::<ReadScatterResp>() {
        bail!("gather buffer too small for response header");
    }

    let mut req: ReadScatterReq = unsafe { zeroed() };
    req.target_pid = 0;
    req.entry_count = entries.len() as u32;
    req.out_buf_va = 0;
    req.out_buf_size = 0;
    for (i, e) in entries.iter().enumerate() {
        req.entries[i] = *e;
    }
    let in_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            &req as *const _ as *const u8,
            size_of::<ReadScatterReq>(),
        )
    };

    let mut gather = vec![0u8; gather_size];
    unsafe {
        ioctl(
            session.handle,
            IOCTL_HV_READ_SCATTER,
            Some(in_bytes),
            Some(&mut gather),
        )?;
    }
    let header: ReadScatterResp = unsafe { std::ptr::read(gather.as_ptr() as *const _) };
    Ok((header, gather))
}

pub fn write_many(session: &Session, entries: &[WriteEntry]) -> Result<WriteManyResp> {
    if entries.is_empty() || entries.len() > WRITE_MANY_MAX_ENTRIES {
        bail!("write entry_count out of range: {}", entries.len());
    }
    let mut req: WriteManyReq = unsafe { zeroed() };
    req.target_pid = 0;
    req.entry_count = entries.len() as u32;
    for (i, e) in entries.iter().enumerate() {
        req.entries[i] = *e;
    }
    let in_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            &req as *const _ as *const u8,
            size_of::<WriteManyReq>(),
        )
    };
    let mut resp_bytes = vec![0u8; size_of::<WriteManyResp>()];

    unsafe {
        ioctl(
            session.handle,
            IOCTL_HV_WRITE_MANY,
            Some(in_bytes),
            Some(&mut resp_bytes),
        )?;
    }
    let resp: WriteManyResp = unsafe { std::ptr::read(resp_bytes.as_ptr() as *const _) };
    Ok(resp)
}

fn unregister_inner(h: HANDLE) -> Result<()> {
    if h.is_invalid() {
        return Err(anyhow!("unregister on invalid handle"));
    }
    unsafe {
        ioctl(h, IOCTL_HV_UNREGISTER, None, None)?;
    }
    Ok(())
}

/// Convenience: read a single contiguous range into a fresh Vec.
/// Wraps a 1-entry READ_SCATTER. Suitable for small reads (<= 4096 bytes).
pub fn read_one(session: &Session, src_va: u64, len: u32) -> Result<Vec<u8>> {
    let header_size = size_of::<ReadScatterResp>() as u32;
    let entry = ScatterEntry {
        src_va,
        len,
        out_offset: header_size,
    };
    let total = header_size + len;
    let (resp, gather) = read_scatter(session, &[entry], total as usize)?;
    if resp.status != OPHION_STATUS_OK {
        bail!(
            "read_one VA={:#x} len={} failed: status={}",
            src_va,
            len,
            resp.status
        );
    }
    let start = header_size as usize;
    Ok(gather[start..start + len as usize].to_vec())
}

/// Convenience: write a single contiguous range from caller bytes to target VA.
pub fn write_one(session: &Session, target_va: u64, src: &[u8]) -> Result<()> {
    let entry = WriteEntry {
        src_va: src.as_ptr() as u64,
        dst_va: target_va,
        len: src.len() as u32,
        reserved: 0,
    };
    let resp = write_many(session, &[entry])?;
    if resp.status != OPHION_STATUS_OK {
        bail!("write_one target_va={:#x} failed: status={}", target_va, resp.status);
    }
    Ok(())
}
