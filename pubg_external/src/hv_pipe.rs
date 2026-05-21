//! VMM VMCALL pipe through Ophion.sys ring 0 driver.
//!
//! User → Ophion.sys IOCTL → BSP-pinned worker → trampoline VA →
//!   `mov rcx, MAGIC; jmp rax` → `vmcall` → OphionDxe VMM (VMX root) →
//!   `MmCopyVirtualMemory`-equivalent → response copied back.
//!
//! Stays in step with `Ophion/src/driver.c` IOCTL codes (see Steps #4–#7).
//! Device path uses `\\\\?\\GLOBALROOT\\Device\\MsftHidIo` — driver creates no
//! `\\DosDevices\\` symlink (Grill Q9-C).

use anyhow::{anyhow, Context, Result};
use std::ffi::OsStr;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_PATH: &str = r"\\?\GLOBALROOT\Device\MsftHidIo";

const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const METHOD_OUT_DIRECT: u32 = 2;
const FILE_ANY_ACCESS: u32 = 0;
const IOCTL_BASE: u32 = 0x800;

const IOCTL_HV_STATUS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS);
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
const IOCTL_HV_GET_VMM_PERCPU_LOG: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const SCATTER_MAX_ENTRIES: usize = 1024;
pub const WRITE_MANY_MAX_ENTRIES: usize = 64;
pub const SCATTER_RESP_RESERVED_BYTES: u32 = 16;

pub const PERCPU_LOG_MAGIC: u64 = 0x4F50484E50434C00; // "OPHNPCL\0"
pub const PERCPU_LOG_RECORD_BYTES: usize = 32;

pub const OPHION_STATUS_OK: u32 = 0;
pub const OPHION_STATUS_NOT_REGISTERED: u32 = 1;
pub const OPHION_STATUS_IMAGE_HASH_MISMATCH: u32 = 2;
pub const OPHION_STATUS_SESSION_INVALID: u32 = 3;
pub const OPHION_STATUS_TARGET_NOT_FOUND: u32 = 4;
pub const OPHION_STATUS_READ_FAILED: u32 = 5;
pub const OPHION_STATUS_INVALID_ARG: u32 = 6;
pub const OPHION_STATUS_WRITE_FAILED: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
struct OphionRegisterReq {
    image_sha256: [u8; 32],
    image_base: u64,
    image_size: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OphionRegisterResp {
    session_key: u64,
    ophion_version: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OphionResolveReq {
    target_name: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OphionResolveResp {
    target_pid: u32,
    image_size: u32,
    image_base: u64,
    status: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ScatterEntry {
    pub src_va: u64,
    pub len: u32,
    pub out_offset: u32,
}

#[repr(C)]
struct OphionReadScatterReq {
    target_pid: u32,
    entry_count: u32,
    out_buf_va: u64,
    out_buf_size: u32,
    reserved: u32,
    entries: [ScatterEntry; SCATTER_MAX_ENTRIES],
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ScatterResp {
    pub ok_count: u32,
    pub fail_count: u32,
    pub total_bytes: u32,
    pub status: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WriteEntry {
    pub src_va: u64,
    pub dst_va: u64,
    pub len: u32,
    pub reserved: u32,
}

#[repr(C)]
struct OphionWriteManyReq {
    target_pid: u32,
    entry_count: u32,
    entries: [WriteEntry; WRITE_MANY_MAX_ENTRIES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WriteManyResp {
    pub bytes_written: [u32; WRITE_MANY_MAX_ENTRIES],
    pub status: u32,
    pub reserved: u32,
}

impl Default for WriteManyResp {
    fn default() -> Self {
        Self {
            bytes_written: [0u32; WRITE_MANY_MAX_ENTRIES],
            status: 0,
            reserved: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub pid: u32,
    pub base: u64,
    pub size: u64,
}

pub struct Session {
    handle: HANDLE,
    pub key: u64,
    pub version: u32,
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // VMCALL UNREGISTER. IRP_MJ_CLEANUP also auto-tears, but explicit
            // call frees the VMM session slot earlier (4-slot cap).
            unsafe {
                let mut returned = 0u32;
                let _ = DeviceIoControl(
                    self.handle,
                    IOCTL_HV_UNREGISTER,
                    None,
                    0,
                    None,
                    0,
                    Some(&mut returned),
                    None,
                );
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

fn open_device() -> Result<HANDLE> {
    let wide: Vec<u16> = OsStr::new(DEVICE_PATH)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
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
        .context("open Ophion device — driver loaded?")
    }
}

unsafe fn ioctl_raw(
    h: HANDLE,
    code: u32,
    in_ptr: *const u8,
    in_len: u32,
    out_ptr: *mut u8,
    out_len: u32,
) -> Result<u32> {
    let mut returned: u32 = 0;
    let in_opt = (in_len > 0).then_some(in_ptr as *const _);
    let out_opt = (out_len > 0).then_some(out_ptr as *mut _);
    DeviceIoControl(
        h,
        code,
        in_opt,
        in_len,
        out_opt,
        out_len,
        Some(&mut returned),
        None,
    )
    .context("DeviceIoControl")?;
    Ok(returned)
}

pub fn cpu_count() -> Result<u32> {
    let h = open_device()?;
    let mut out = 0u32;
    let r = unsafe {
        let r = ioctl_raw(
            h,
            IOCTL_HV_STATUS,
            std::ptr::null(),
            0,
            &mut out as *mut _ as *mut u8,
            size_of::<u32>() as u32,
        );
        let _ = CloseHandle(h);
        r?
    };
    if r as usize != size_of::<u32>() {
        return Err(anyhow!("STATUS short read: {} bytes", r));
    }
    Ok(out)
}

pub fn register() -> Result<Session> {
    let handle = open_device()?;

    // Image hash auth is currently dev-bypassed in VMM (Q5-D / fa941d2),
    // but compute real SHA-256 of own .text anyway so the prod toggle Just Works.
    let req = OphionRegisterReq {
        image_sha256: own_text_sha256(),
        image_base: own_image_base(),
        image_size: own_image_size(),
        reserved: 0,
    };
    let mut resp = OphionRegisterResp::default();

    let r = unsafe {
        ioctl_raw(
            handle,
            IOCTL_HV_REGISTER,
            &req as *const _ as *const u8,
            size_of::<OphionRegisterReq>() as u32,
            &mut resp as *mut _ as *mut u8,
            size_of::<OphionRegisterResp>() as u32,
        )
    }
    .or_else(|e| {
        unsafe {
            let _ = CloseHandle(handle);
        }
        Err(e)
    })?;

    if (r as usize) < size_of::<OphionRegisterResp>() {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(anyhow!("REGISTER short response: {} bytes", r));
    }
    if resp.status != OPHION_STATUS_OK || resp.session_key == 0 {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(anyhow!(
            "REGISTER rejected: status={} key={:#x}",
            resp.status,
            resp.session_key
        ));
    }

    Ok(Session {
        handle,
        key: resp.session_key,
        version: resp.ophion_version,
    })
}

pub fn resolve_target(session: &Session, name: &str) -> Result<Target> {
    let mut name_buf = [0u8; 16];
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    name_buf[..n].copy_from_slice(&bytes[..n]);

    let req = OphionResolveReq {
        target_name: name_buf,
    };
    let mut resp = OphionResolveResp::default();

    let r = unsafe {
        ioctl_raw(
            session.handle,
            IOCTL_HV_RESOLVE,
            &req as *const _ as *const u8,
            size_of::<OphionResolveReq>() as u32,
            &mut resp as *mut _ as *mut u8,
            size_of::<OphionResolveResp>() as u32,
        )
    }?;

    if (r as usize) < size_of::<OphionResolveResp>() {
        return Err(anyhow!("RESOLVE short response: {} bytes", r));
    }
    if resp.status != OPHION_STATUS_OK || resp.target_pid == 0 {
        return Err(anyhow!(
            "RESOLVE failed: status={} name={}",
            resp.status,
            name
        ));
    }
    Ok(Target {
        pid: resp.target_pid,
        base: resp.image_base,
        size: resp.image_size as u64,
    })
}

/// Run one scatter read.  `out` is the gather buffer the driver hands to the
/// VMM via MDL system VA; first 16 bytes hold the [ScatterResp] header, then
/// per-entry data lands at each entry's `out_offset` (must be >= 16).
///
/// Target process is whichever was last `resolve_target`'d on this session
/// (VMM uses the cached `target_cr3`).
pub fn read_scatter(
    session: &Session,
    entries: &[ScatterEntry],
    out: &mut [u8],
) -> Result<ScatterResp> {
    if entries.is_empty() || entries.len() > SCATTER_MAX_ENTRIES {
        return Err(anyhow!(
            "scatter entry_count out of range: {} (max {})",
            entries.len(),
            SCATTER_MAX_ENTRIES
        ));
    }
    if out.len() < SCATTER_RESP_RESERVED_BYTES as usize {
        return Err(anyhow!(
            "scatter out buffer < {} bytes (header reserved)",
            SCATTER_RESP_RESERVED_BYTES
        ));
    }
    for (i, e) in entries.iter().enumerate() {
        if e.out_offset < SCATTER_RESP_RESERVED_BYTES
            || (e.out_offset as usize)
                .checked_add(e.len as usize)
                .map(|end| end > out.len())
                .unwrap_or(true)
        {
            return Err(anyhow!(
                "scatter entry[{}] out_offset/len exceeds buffer (off={} len={} buf={})",
                i,
                e.out_offset,
                e.len,
                out.len()
            ));
        }
    }

    let mut req = Box::new(OphionReadScatterReq {
        target_pid: 0, // VMM uses session->target_cr3
        entry_count: entries.len() as u32,
        out_buf_va: 0, // driver overrides w/ MDL system VA
        out_buf_size: 0,
        reserved: 0,
        entries: [ScatterEntry::default(); SCATTER_MAX_ENTRIES],
    });
    req.entries[..entries.len()].copy_from_slice(entries);

    let returned = unsafe {
        ioctl_raw(
            session.handle,
            IOCTL_HV_READ_SCATTER,
            req.as_ref() as *const _ as *const u8,
            size_of::<OphionReadScatterReq>() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
        )
    }?;

    if (returned as usize) < SCATTER_RESP_RESERVED_BYTES as usize {
        return Err(anyhow!("scatter short response: {} bytes", returned));
    }
    let resp: ScatterResp = unsafe { std::ptr::read_unaligned(out.as_ptr() as *const ScatterResp) };
    Ok(resp)
}

/// One-shot single-address read helper.  Slow path — prefer batched
/// [`read_scatter`] for tree walks.
pub fn read(session: &Session, src_va: u64, dst: &mut [u8]) -> Result<()> {
    if dst.is_empty() {
        return Ok(());
    }
    let scratch_len = SCATTER_RESP_RESERVED_BYTES as usize + dst.len();
    let mut scratch = vec![0u8; scratch_len];
    let entries = [ScatterEntry {
        src_va,
        len: dst.len() as u32,
        out_offset: SCATTER_RESP_RESERVED_BYTES,
    }];
    let resp = read_scatter(session, &entries, &mut scratch)?;
    if resp.ok_count != 1 {
        return Err(anyhow!(
            "scatter single-read failed: ok={} fail={} status={}",
            resp.ok_count,
            resp.fail_count,
            resp.status
        ));
    }
    dst.copy_from_slice(&scratch[SCATTER_RESP_RESERVED_BYTES as usize..]);
    Ok(())
}

pub fn write_many(session: &Session, entries: &[WriteEntry]) -> Result<WriteManyResp> {
    if entries.is_empty() || entries.len() > WRITE_MANY_MAX_ENTRIES {
        return Err(anyhow!(
            "write_many entry_count out of range: {} (max {})",
            entries.len(),
            WRITE_MANY_MAX_ENTRIES
        ));
    }
    let mut req = Box::new(OphionWriteManyReq {
        target_pid: 0,
        entry_count: entries.len() as u32,
        entries: [WriteEntry::default(); WRITE_MANY_MAX_ENTRIES],
    });
    req.entries[..entries.len()].copy_from_slice(entries);

    let mut resp = WriteManyResp::default();
    let returned = unsafe {
        ioctl_raw(
            session.handle,
            IOCTL_HV_WRITE_MANY,
            req.as_ref() as *const _ as *const u8,
            size_of::<OphionWriteManyReq>() as u32,
            &mut resp as *mut _ as *mut u8,
            size_of_val(&resp) as u32,
        )
    }?;
    if (returned as usize) < size_of::<WriteManyResp>() {
        return Err(anyhow!("write_many short response: {} bytes", returned));
    }
    Ok(resp)
}

pub fn write(session: &Session, dst_va: u64, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let entries = [WriteEntry {
        src_va: data.as_ptr() as u64,
        dst_va,
        len: data.len() as u32,
        reserved: 0,
    }];
    let resp = write_many(session, &entries)?;
    if resp.bytes_written[0] as usize != data.len() {
        return Err(anyhow!(
            "single write short: wrote {} of {} status={}",
            resp.bytes_written[0],
            data.len(),
            resp.status
        ));
    }
    Ok(())
}

fn own_image_base() -> u64 {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    unsafe {
        GetModuleHandleW(PCWSTR::null())
            .map(|h| h.0 as u64)
            .unwrap_or(0)
    }
}

fn own_image_size() -> u32 {
    let base = own_image_base();
    if base == 0 {
        return 0;
    }
    unsafe {
        let dos = base as *const u8;
        let e_lfanew = *(dos.add(0x3C) as *const u32) as usize;
        let nt = dos.add(e_lfanew);
        if *(nt as *const u32) != 0x0000_4550 {
            return 0;
        }
        // IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage at offset
        // 4 (sig) + 20 (file hdr) + 56 (in opt hdr to SizeOfImage)
        *(nt.add(0x18 + 0x38) as *const u32)
    }
}

fn own_text_sha256() -> [u8; 32] {
    // Best-effort .text hash. Real hash gating is dev-bypassed in VMM today;
    // when production gating flips on, swap in dbghelp / SymInitialize-based
    // section walk so PE export-table-stripped builds still work.
    let base = own_image_base();
    if base == 0 {
        return [0u8; 32];
    }
    unsafe {
        let dos = base as *const u8;
        let e_lfanew = *(dos.add(0x3C) as *const u32) as usize;
        let nt = dos.add(e_lfanew);
        if *(nt as *const u32) != 0x0000_4550 {
            return [0u8; 32];
        }
        let n_sections = *(nt.add(4 + 2) as *const u16) as usize;
        let opt_hdr_size = *(nt.add(4 + 16) as *const u16) as usize;
        let sect = nt.add(4 + 20 + opt_hdr_size);
        for i in 0..n_sections {
            let s = sect.add(i * 40);
            if std::slice::from_raw_parts(s, 5) == b".text" {
                let vsize = *(s.add(8) as *const u32) as usize;
                let vaddr = *(s.add(12) as *const u32) as usize;
                let bytes = std::slice::from_raw_parts(dos.add(vaddr), vsize);
                return sha256(bytes);
            }
        }
    }
    [0u8; 32]
}

// Tiny embedded SHA-256 to avoid an extra crate just for register handshake.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, c) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}


#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PercpuLogRecord {
    pub tsc: u64,
    pub guest_rip: u64,
    pub exit_qual: u64,
    pub exit_reason: u16,
    pub reserved16: u16,
    pub tag: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PercpuLogResp {
    pub magic: u64,
    pub bytes_written: u32,
    pub cpu_count: u32,
    pub records_per_cpu: u32,
    pub status: u32,
}

#[derive(Debug, Clone)]
pub struct PercpuLogSnapshot {
    pub cpu_count: u32,
    pub records_per_cpu: u32,
    /// Flattened: outer = CPU, inner = records_per_cpu records.
    pub rings: Vec<Vec<PercpuLogRecord>>,
    /// Per-CPU monotonic write counter (head index = head % records_per_cpu).
    pub heads: Vec<u32>,
    /// Per-CPU monotonic write count (incl. wraps).
    pub seqs: Vec<u32>,
}

impl PercpuLogSnapshot {
    /// Returns records ordered oldest-first per CPU, dropping unwritten slots.
    pub fn ordered_per_cpu(&self) -> Vec<Vec<PercpuLogRecord>> {
        let n = self.records_per_cpu as usize;
        let mut out = Vec::with_capacity(self.rings.len());
        for (i, ring) in self.rings.iter().enumerate() {
            let seq = self.seqs[i] as usize;
            let count = seq.min(n);
            let head = (self.heads[i] as usize) % n;
            let start = if seq <= n { 0 } else { head };
            let mut v = Vec::with_capacity(count);
            for k in 0..count {
                v.push(ring[(start + k) % n]);
            }
            out.push(v);
        }
        out
    }
}

/// Drain the VMM per-CPU vmexit log via VMCALL relay (Step #8).
///
/// Pulls a snapshot blob from the VMM and decodes it into structured form.
/// `capacity_bytes` controls the size of the kernel pool the driver allocates
/// for the blob — pick generously (16-32 KiB covers the 12-core box).
pub fn get_vmm_percpu_log(session: &Session, capacity_bytes: usize) -> Result<PercpuLogSnapshot> {
    let total = capacity_bytes + size_of::<PercpuLogResp>();
    let mut buf = vec![0u8; total];

    let returned = unsafe {
        ioctl_raw(
            session.handle,
            IOCTL_HV_GET_VMM_PERCPU_LOG,
            std::ptr::null(),
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    }?;

    if (returned as usize) < size_of::<PercpuLogResp>() {
        return Err(anyhow!(
            "GET_VMM_PERCPU_LOG short response: {} bytes",
            returned
        ));
    }

    let resp: PercpuLogResp =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const PercpuLogResp) };
    if resp.status != OPHION_STATUS_OK {
        return Err(anyhow!(
            "GET_VMM_PERCPU_LOG VMM rejected: status={} bytes_written={}",
            resp.status,
            resp.bytes_written
        ));
    }
    if resp.magic != PERCPU_LOG_MAGIC {
        return Err(anyhow!(
            "GET_VMM_PERCPU_LOG magic mismatch: 0x{:016x}",
            resp.magic
        ));
    }

    let blob_off = size_of::<PercpuLogResp>();
    let blob_end = blob_off + resp.bytes_written as usize;
    if blob_end > buf.len() {
        return Err(anyhow!(
            "GET_VMM_PERCPU_LOG blob overflow: end={} buf={}",
            blob_end,
            buf.len()
        ));
    }
    let blob = &buf[blob_off..blob_end];
    if blob.len() < 16 {
        return Err(anyhow!("snapshot blob too small: {} bytes", blob.len()));
    }

    // [magic u64][cpu_count u32][rec_per_cpu u32]
    let blob_magic = u64::from_le_bytes(blob[0..8].try_into().unwrap());
    let blob_cpu_count = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    let blob_rec_per_cpu = u32::from_le_bytes(blob[12..16].try_into().unwrap());
    if blob_magic != PERCPU_LOG_MAGIC {
        return Err(anyhow!(
            "snapshot magic mismatch: 0x{:016x}",
            blob_magic
        ));
    }
    let n = blob_rec_per_cpu as usize;
    let ring_bytes = 8 + n * PERCPU_LOG_RECORD_BYTES;
    let need = 16 + (blob_cpu_count as usize) * ring_bytes;
    if blob.len() < need {
        return Err(anyhow!(
            "snapshot truncated: have {} need {}",
            blob.len(),
            need
        ));
    }

    let mut rings = Vec::with_capacity(blob_cpu_count as usize);
    let mut heads = Vec::with_capacity(blob_cpu_count as usize);
    let mut seqs = Vec::with_capacity(blob_cpu_count as usize);
    let mut off = 16;
    for _ in 0..blob_cpu_count {
        let head = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
        let seq = u32::from_le_bytes(blob[off + 4..off + 8].try_into().unwrap());
        off += 8;
        let mut ring = Vec::with_capacity(n);
        for _ in 0..n {
            let r: PercpuLogRecord = unsafe {
                std::ptr::read_unaligned(blob[off..].as_ptr() as *const PercpuLogRecord)
            };
            ring.push(r);
            off += PERCPU_LOG_RECORD_BYTES;
        }
        rings.push(ring);
        heads.push(head);
        seqs.push(seq);
    }

    Ok(PercpuLogSnapshot {
        cpu_count: blob_cpu_count,
        records_per_cpu: blob_rec_per_cpu,
        rings,
        heads,
        seqs,
    })
}
