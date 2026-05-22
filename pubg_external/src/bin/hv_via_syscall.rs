//! Driverless VMCALL bridge via the NtCreateProfile syscall trampoline.
//!
//! After OphionInstall.sys runs once per UEFI boot, NtCreateProfile's body in
//! ntoskrnl.exe is hot-patched with a 14-byte `mov rax, imm64; jmp rax` that
//! lands in a runtime trampoline in EfiRuntimeServicesCode. The trampoline
//! checks `rcx == OPHION_VMCALL_MAGIC_HANDLE` (0xCAFEDEADBEEF1234):
//!
//!   - On match: shuffles regs to the VMM ABI and issues VMCALL.
//!   - On miss : replays the saved 14 bytes and jumps back to NCP+14, so real
//!               NtCreateProfile syscalls behave normally.
//!
//! From user-mode, calling `NtCreateProfile(magic, key, op, buf, size, ...)`
//! triggers the trampoline branch with the magic match. The kernel-side
//! syscall dispatcher loads `rcx` from `r10` (the value the user passed as the
//! first arg of the ntdll syscall stub), so the magic survives the syscall
//! transition and reaches the patched NCP body.
//!
//! Trampoline shuffle (matches MongilLoader/OphionDxe/NtosPatch.c::NtosBuildTrampoline):
//!   rax <- rdx        (session_key)
//!   rdx <- r8         (op)
//!   r8  <- r9         (buf_va)
//!   r9  <- [rsp+0x28] (buf_size)
//!   vmcall
//!   ret               -> pops KiSystemCall64 return address -> sysret -> user
//!
//! VMCALL status returns in `rax`, which the kernel-side syscall epilogue
//! places in `RAX` for sysret. From the user-mode side this looks like a
//! normal NTSTATUS returned by NtCreateProfile.
//!
//! Cargo entry: `cargo run --release --bin hv_via_syscall` (must run on BSP;
//! pin with `cmd /c "start /wait /b /affinity 0x1 cmd /c hv_via_syscall.exe"`
//! while the VMM is BSP-only).

use anyhow::{anyhow, Result};
use std::ffi::c_void;

const MAGIC_HANDLE: u64 = 0xCAFE_DEAD_BEEF_1234;

/// VMM op codes (mirror MongilLoader/include/OphionAbi.h).
const OPHION_OP_REGISTER: u32 = 0x01;
const OPHION_OP_RESOLVE_TARGET: u32 = 0x02;
#[allow(dead_code)]
const OPHION_OP_READ_MANY: u32 = 0x03;
const OPHION_OP_STATUS_QUERY: u32 = 0x04;
#[allow(dead_code)]
const OPHION_OP_UNREGISTER: u32 = 0x05;

/// Function signature of ntdll!NtCreateProfile.
///
/// Win64 calling convention puts args 1-4 in rcx/rdx/r8/r9 and arg 5 at
/// [rsp+0x28] (after the callee return-address push and the caller's 32-byte
/// shadow space). The kernel-side ntoskrnl!NtCreateProfile entry has the same
/// frame layout, so the trampoline's `mov r9, [rsp+0x28]` recovers our 5th
/// argument verbatim.
///
/// Real `NtCreateProfile` declares `BucketSize` as `ULONG`, but we pass it as
/// `u64` here so the compiler emits a full 8-byte store at [rsp+0x28]. The
/// trampoline reads 8 bytes; if the upper 4 were uninitialized stack the
/// VMCALL would see a garbage `buf_size`. We never hit the fall-through path
/// (we always pass the magic in rcx), so the size mismatch with the real
/// kernel routine never matters.
type NtCreateProfileFn = unsafe extern "system" fn(
    profile_handle: u64,    // rcx -> trampoline magic check
    process: u64,           // rdx -> shuffled to rax (session_key)
    range_base: u64,        // r8  -> shuffled to rdx (op)
    range_size: u64,        // r9  -> shuffled to r8  (buf_va)
    bucket_size: u64,       // [rsp+0x28] -> shuffled to r9 (buf_size)
    buffer: *mut c_void,    // [rsp+0x30] -> ignored
    buffer_size: u32,       // [rsp+0x38] -> ignored
    profile_source: u32,    // [rsp+0x40] -> ignored
    affinity: u64,          // [rsp+0x48] -> ignored
) -> i32;                   // NTSTATUS

unsafe fn resolve_nt_create_profile() -> Result<NtCreateProfileFn> {
    // ntdll is always loaded; GetModuleHandle returns its base without a ref.
    let module = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::s!("ntdll.dll"),
    )?;
    let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
        module,
        windows::core::s!("NtCreateProfile"),
    )
    .ok_or_else(|| anyhow!("NtCreateProfile not exported from ntdll"))?;
    Ok(std::mem::transmute(proc))
}

/// Drive the trampoline path for one VMCALL op. Returns the NTSTATUS-shaped
/// value the VMM placed in `rax` (which is `OPHION_STATUS_*`).
unsafe fn vmcall(
    nt_create_profile: NtCreateProfileFn,
    op: u32,
    session_key: u64,
    buf: *mut u8,
    buf_size: u32,
) -> u32 {
    let status = nt_create_profile(
        MAGIC_HANDLE,
        session_key,
        op as u64,
        buf as u64,
        buf_size as u64,
        std::ptr::null_mut(),
        0,
        0,
        0,
    );
    status as u32
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct OphionStatusResp {
    ophion_loaded: u32,
    ophion_version: u32,
    patch_applied: u32,
    ntos_build_known: u32,
    vmm_uptime_ms: u64,
    reserved: [u8; 16],
}

/// Status query exercises the simplest VMCALL path: rcx=magic, rdx=key=0,
/// r8=op=STATUS_QUERY, r9=buffer, [rsp+0x28]=size. VMM fills the response
/// in-place via vmm_guest_write under the caller CR3 (which the trampoline-
/// triggered VMCALL captures from VMCS_GUEST_CR3 = current process kernel CR3
/// at syscall time = full kernel mappings).
fn smoke_status_query() -> Result<OphionStatusResp> {
    unsafe {
        let nt_create_profile = resolve_nt_create_profile()?;

        let mut resp = OphionStatusResp::default();
        let resp_ptr = &mut resp as *mut OphionStatusResp as *mut u8;
        let resp_size = std::mem::size_of::<OphionStatusResp>() as u32;

        let status = vmcall(
            nt_create_profile,
            OPHION_OP_STATUS_QUERY,
            0,
            resp_ptr,
            resp_size,
        );

        if status != 0 {
            return Err(anyhow!("STATUS_QUERY returned VMM status 0x{:x}", status));
        }
        Ok(resp)
    }
}

fn main() -> Result<()> {
    env_logger::init();

    println!("hv_via_syscall: driverless VMCALL bridge test");
    println!("  trampoline magic = 0x{:016x}", MAGIC_HANDLE);
    println!();

    println!("[1] Resolving ntdll!NtCreateProfile ...");
    unsafe {
        let _ = resolve_nt_create_profile()?;
    }
    println!("    OK");

    println!("[2] Issuing OPHION_OP_STATUS_QUERY via NtCreateProfile(magic, ...)");
    let resp = smoke_status_query()?;
    println!("    VMM status:");
    println!("      ophion_loaded   = {}", resp.ophion_loaded);
    println!("      ophion_version  = 0x{:08x}", resp.ophion_version);
    println!("      patch_applied   = {}", resp.patch_applied);
    println!("      ntos_build_known= {}", resp.ntos_build_known);
    println!("      vmm_uptime_ms   = {}", resp.vmm_uptime_ms);

    println!();
    println!("Driverless VMCALL bridge LIVE.");
    println!(
        "Future ops (REGISTER=0x{:02x}, RESOLVE=0x{:02x}, READ_MANY=0x{:02x}, ...) ",
        OPHION_OP_REGISTER, OPHION_OP_RESOLVE_TARGET, OPHION_OP_READ_MANY
    );
    println!("can be issued the same way: vmcall(op, key, buf, size).");
    Ok(())
}
