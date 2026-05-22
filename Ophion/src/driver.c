/*
*   driver.c - windows kernel driver entry point for the hypervisor
*   creates a device object and initializes vmx
*   Step #3 (Grill Q9-C): obscure device name, no DosDevices symlink
*   Step #3 (Grill Q6-B): per-FILE_OBJECT session in FsContext
*   Step #3 (Grill Q1/Q2/Q8): relay worker + trampoline VA discovery
*   Step #4 (Grill Q3-B): IOCTL_HV_REGISTER typed IOCTL
*   Step #5: IOCTL_HV_RESOLVE + IOCTL_HV_UNREGISTER + cleanup VMCALL
*   Step #6 (Grill Q4-B/Q7-B): IOCTL_HV_READ_SCATTER METHOD_OUT_DIRECT, MDL system VA
*   Step #7: IOCTL_HV_WRITE_MANY METHOD_BUFFERED (scatter ABI -> per-entry caller VAs)
*/
#include "hv.h"
#include "relay.h"
#include "OphionAbi.h"

#define IOCTL_BASE      0x800
#define IOCTL_HV_STATUS             CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_GET_LOG            CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_REGISTER           CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_RESOLVE            CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_UNREGISTER         CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_READ_SCATTER       CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_HV_WRITE_MANY         CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_GET_VMM_PERCPU_LOG CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 7, METHOD_BUFFERED,   FILE_ANY_ACCESS)

static NTSTATUS DriverCreate(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverCleanup(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);

static NTSTATUS
SessionVmcallUnregister(_In_ POPHION_SESSION session)
{
    if (!session || !session->registered || session->session_key == 0)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!relay_is_armed())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    OPHION_RELAY_REQ req = {0};
    req.session     = session;
    req.op          = OPHION_OP_UNREGISTER;
    req.in_buf      = NULL;
    req.in_size     = 0;
    req.out_buf     = NULL;
    req.out_size    = 0;
    req.attach_proc = session->owner_proc;

    NTSTATUS rs = relay_submit(&req);
    if (NT_SUCCESS(rs) && req.out_rax == OPHION_STATUS_OK)
    {
        session->registered  = FALSE;
        session->session_key = 0;
    }
    return rs;
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    hv_log("[hv] Unloading bridge driver...\n");

    // Bridge-only mode: VMM lifecycle is owned by UEFI OphionDxe. We never
    // ran vmx_init/broadcast_virtualize_all from DriverEntry, so there is
    // nothing for vmx_terminate / broadcast_terminate_all to clean up here.
    // Calling them anyway would have left HOST_RIP pointing into our image
    // on any AP we accidentally VMXONed (APs are bare-metal under BSP-only
    // UEFI virt) and BSODed the box on the next vmexit after unload.
    relay_shutdown();

    if (driver_obj->DeviceObject)
    {
        IoDeleteDevice(driver_obj->DeviceObject);
    }

    hv_log("[hv] Bridge driver unloaded.\n");
}

// Bring-up worker. Runs in PsInitialSystemProcess (system CR3) because
// PsCreateSystemThread always sets PROCESS = nt!PsInitialSystemProcess for
// its thread bodies. Calls VMM magic CPUID leaves in the order required by
// the bridge:
//   1. OPHR sub 0   - resolve ntos_base + KiServiceTable + NtCreateProfile.
//   2. OPHS         - push NtCreateProfile RVA. VMM's prologue check reads
//                     the live caller CR3, which here is system CR3 -> ntos
//                     pages mapped -> prologue_ok=1 -> NtosBuildTrampoline
//                     populates the runtime trampoline page with real code.
//   3. OPHX 0xFF    - uncloaked install. Writes the 14-byte inline patch
//                     into NtCreateProfile body so a guest tail-call into
//                     it lands in the now-built trampoline.
//   4. OPHX sub 0   - read install status into hv_log.
//   5. OPHR sub 8   - read live trampoline VA, hand to relay_set_trampoline_va.
//
// Pinned to BSP because the Phase 2.7 baseline VMM virtualizes only CPU 0.
// A CPUID leaf issued from an AP would hit bare metal and miss the VMM
// dispatcher entirely.
static VOID
BridgeBringUpThread(_In_ PVOID context)
{
    UNREFERENCED_PARAMETER(context);

    int regs_buf[4] = {0};
    KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);

    __cpuidex(regs_buf, 0x4F504852, 0);
    hv_log("[hv] OPHR resolve: a=0x%x b=0x%x c=0x%x d=0x%x\n",
           regs_buf[0], regs_buf[1], regs_buf[2], regs_buf[3]);

    // RVA hardcoded for ntoskrnl.exe 10.0.19041.7058. Bump on each kernel
    // patch -- compute via cdb / ? ntoskrnl!NtCreateProfile - ntoskrnl.
    ULONG ncp_rva = 0x95ac10;
    __cpuidex(regs_buf, 0x4F504853, (int)ncp_rva);
    hv_log("[hv] OPHS push NCP rva=0x%x: a=0x%x b=0x%x c=0x%x d=0x%x\n",
           ncp_rva, regs_buf[0], regs_buf[1], regs_buf[2], regs_buf[3]);

    __cpuidex(regs_buf, 0x4F504858, 0xFF);
    hv_log("[hv] OPHX uncloaked install: a=0x%x b=0x%x c=0x%x d=0x%x\n",
           regs_buf[0], regs_buf[1], regs_buf[2], regs_buf[3]);

    __cpuidex(regs_buf, 0x4F504858, 0);
    hv_log("[hv] OPHX install status: a=0x%x b=0x%x c=0x%x d=0x%x\n",
           regs_buf[0], regs_buf[1], regs_buf[2], regs_buf[3]);

    __cpuidex(regs_buf, 0x4F504852, 8);
    UINT64 vmm_tramp_va = (UINT64)(UINT32)regs_buf[1] |
                          ((UINT64)(UINT32)regs_buf[2] << 32);
    hv_log("[hv] OPHR sub 8: tramp_lo=0x%x tramp_hi=0x%x va=0x%llx\n",
           regs_buf[1], regs_buf[2], vmm_tramp_va);
    relay_set_trampoline_va(vmm_tramp_va);

    KeRevertToUserAffinityThreadEx(old_aff);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    NTSTATUS       status;
    PDEVICE_OBJECT device_obj = NULL;
    UNICODE_STRING device_name;

    UNREFERENCED_PARAMETER(registry_path);

    hv_log_init();
    hv_log("[hv] Ophion initializing...\n");

    RtlInitUnicodeString(&device_name, OPHION_DEVICE_NAME);
    status = IoCreateDevice(
        driver_obj,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_obj);

    if (!NT_SUCCESS(status))
    {
        hv_log("[hv] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    driver_obj->DriverUnload                         = DriverUnload;
    driver_obj->MajorFunction[IRP_MJ_CREATE]         = DriverCreate;
    driver_obj->MajorFunction[IRP_MJ_CLEANUP]        = DriverCleanup;
    driver_obj->MajorFunction[IRP_MJ_CLOSE]          = DriverClose;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

    // Bridge-only mode: this driver no longer owns the VMX root state
    // because UEFI OphionDxe already runs the hypervisor. Calling
    // vmx_init() here would VMXON every CPU and set HOST_RIP into
    // driver image; once the driver unloads, any subsequent vmexit
    // on a bare-metal AP (APs are not BSP-virt'd today) would page-
    // fault into the freed image - exact BSOD signature observed
    // 2026-05-22 (DRIVER_IRQL_NOT_LESS_OR_EQUAL,
    // <Unloaded_Ophion.sys>+0x5a30 = asm_vmexit_handler).
    //
    // From here on the driver only owns:
    //   - \Device\<obscure-name> create/cleanup
    //   - per-handle session in FsContext
    //   - relay worker + trampoline VMCALL path
    //   - IOCTL surface (REGISTER/RESOLVE/UNREGISTER/READ_SCATTER/WRITE_MANY/...)

    if (!vmx_check_support())
    {
        hv_log("[hv] CPU does not support VMX (cannot bridge to UEFI VMM)\n");
        IoDeleteDevice(device_obj);
        return STATUS_HV_OPERATION_FAILED;
    }

    status = relay_init();
    if (!NT_SUCCESS(status))
    {
        hv_log("[hv] relay_init failed: 0x%X (continuing without relay)\n", status);
        // Non-fatal: VMM still works for status/log IOCTLs even if relay fails.
        // No CPUID bring-up either; the cpuidex block below requires the
        // relay queue / spinlocks to be initialized before the worker fires.
        hv_log("[hv] Hypervisor loaded and active on all cores!\n");
        return STATUS_SUCCESS;
    }

    // Bridge-mode bring-up: VMM ships the NtCreateProfile patch builder
    // (Phase 4 / 4d-i) but defers running it until a guest issues the
    // CPUID magic leaves below. Old mongil_external did this from user-
    // mode; with the new bridge architecture the driver is the canonical
    // trigger because it loads exactly once and runs in system CR3 (full
    // ntos mapping needed for the resolve + write).
    //
    //   OPHR (eax=0x4F504852) sub 0: resolve ntos_base + KiServiceTable +
    //                                NtCreateProfile via guest CR3 syscall
    //                                table walk.  Cached; idempotent.
    //   OPHX (eax=0x4F504858) sub 0xFF: uncloaked install. Allocates the
    //                                trampoline page in EfiRuntimeServicesCode
    //                                and writes the 14-byte inline patch
    //                                directly into NtCreateProfile body.
    //                                Reads of NtCreateProfile from kernel
    //                                return the patched bytes.
    //
    //                                NB: cloaked install (sub 0xFE) hides
    //                                the patch from PG read-scans by serving
    //                                a shadow page, but it ALSO hides it
    //                                from us. Cloak is for Step #B3 once we
    //                                discover the trampoline through a
    //                                separate channel; here we want the
    //                                patch visible.
    //   OPHR sub 8: returns the live trampoline VA in EBX:ECX (low:high u32).
    //               Canonical discovery channel because NtCreateProfile is
    //               *not* exported from ntoskrnl.exe on Win10 19041 (only
    //               ZwCreateProfileEx is). MmGetSystemRoutineAddress
    //               returns NULL there, and the PE-walk fallback in
    //               relay_parse_trampoline_va never runs. relay_init above
    //               leaves s_armed = FALSE; the OPHR sub 8 read below arms
    //               the relay if VMM hands back a non-zero trampoline VA.
    //
    // BSP affinity + System CR3: DriverEntry runs in the caller-process
    // context (sc.exe -> services.exe), where KVA Shadow on Win10 19041
    // strips kernel page mappings from the user CR3 half. VMM's OPHS
    // prologue check reads NtCreateProfile via VMCS_GUEST_CR3, which is
    // the live user-CR3, and silently returns a zero page -> prologue_ok = 0
    // -> NtosBuildTrampoline never runs -> trampoline page stays 0xCC fill
    // -> relay tail-call lands on int3 -> BSOD. Spawn a system thread so
    // the cpuidex chain runs in PsInitialSystemProcess (system CR3) where
    // every kernel page is mapped.
    HANDLE thread_handle = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS thread_status = PsCreateSystemThread(
        &thread_handle, THREAD_ALL_ACCESS, &oa, NULL, NULL,
        BridgeBringUpThread, NULL);
    if (NT_SUCCESS(thread_status))
    {
        PVOID thread_obj = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(thread_handle, SYNCHRONIZE,
                                                 *PsThreadType, KernelMode,
                                                 &thread_obj, NULL)))
        {
            KeWaitForSingleObject(thread_obj, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(thread_obj);
        }
        ZwClose(thread_handle);
    }
    else
    {
        hv_log("[hv] PsCreateSystemThread for bring-up failed: 0x%X\n",
               thread_status);
    }

    {
        UINT64 tramp = relay_get_trampoline_va();
        if (tramp)
        {
            hv_log("[hv] relay armed, trampoline VA = 0x%llx\n", tramp);
        }
        else
        {
            hv_log("[hv] relay started but trampoline NOT discovered (VMM patch absent?)\n");
        }
    }

    // Push SET_KERNEL_OFFSETS so RESOLVE_TARGET / LIST_PROCESSES /
    // RESOLVE_TARGET_BY_PID work without the user-mode dbghelp helper.
    // Hooked into the IOCTL_HV_REGISTER success path below; the bring-up
    // session here cannot self-REGISTER because driver image hash != baked
    // user-mode hash (only one accepted hash) and dev-bypass is off in the
    // baseline VMM. Push fires once on first user-mode REGISTER.

    hv_log("[hv] Bridge driver loaded.\n");
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverCreate(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    UNREFERENCED_PARAMETER(device_obj);

    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(irp);
    POPHION_SESSION    session = relay_session_alloc();

    NTSTATUS status;
    if (session)
    {
        sl->FileObject->FsContext = session;
        status = STATUS_SUCCESS;
    }
    else
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    irp->IoStatus.Status      = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
DriverCleanup(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    UNREFERENCED_PARAMETER(device_obj);

    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(irp);
    POPHION_SESSION    session = (POPHION_SESSION)sl->FileObject->FsContext;

    if (session)
    {
        if (session->registered)
        {
            (VOID)SessionVmcallUnregister(session);
        }
        relay_session_free(session);
        sl->FileObject->FsContext = NULL;
    }

    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverClose(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverIoControl(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack;
    ULONG              ioctl_code;

    UNREFERENCED_PARAMETER(device_obj);

    io_stack       = IoGetCurrentIrpStackLocation(irp);
    ioctl_code = io_stack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctl_code)
    {
    case IOCTL_HV_STATUS:
    {
        if (io_stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(UINT32))
        {
            *(UINT32 *)irp->AssociatedIrp.SystemBuffer = g_cpu_count;
            irp->IoStatus.Information = sizeof(UINT32);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_GET_LOG:
    {
        ULONG  out_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;
        SIZE_T copied  = hv_log_snapshot(irp->AssociatedIrp.SystemBuffer, out_len);
        irp->IoStatus.Information = copied;
        break;
    }

    case IOCTL_HV_REGISTER:
    {
        ULONG in_len  = io_stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (in_len < sizeof(ophion_register_req_t) ||
            out_len < sizeof(ophion_register_resp_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POPHION_SESSION session = (POPHION_SESSION)io_stack->FileObject->FsContext;
        if (!session)
        {
            status = STATUS_INVALID_HANDLE;
            break;
        }
        if (session->registered)
        {
            status = STATUS_ALREADY_REGISTERED;
            break;
        }
        if (!relay_is_armed())
        {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        SIZE_T pool_size = sizeof(ophion_register_req_t) +
                           sizeof(ophion_register_resp_t);
        PVOID  pool      = ExAllocatePool2(POOL_FLAG_NON_PAGED, pool_size,
                                           OPHION_RELAY_TAG);
        if (!pool)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(pool, irp->AssociatedIrp.SystemBuffer,
                      sizeof(ophion_register_req_t));
        RtlZeroMemory((PUCHAR)pool + sizeof(ophion_register_req_t),
                      sizeof(ophion_register_resp_t));

        OPHION_RELAY_REQ req = {0};
        req.session     = session;
        req.op          = OPHION_OP_REGISTER;
        req.in_buf      = pool;
        req.in_size     = (UINT32)pool_size;
        req.out_buf     = pool;
        req.out_size    = (UINT32)pool_size;
        req.attach_proc = session->owner_proc;

        NTSTATUS rs = relay_submit(&req);
        if (!NT_SUCCESS(rs))
        {
            ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
            status = rs;
            break;
        }

        ophion_register_resp_t *resp = (ophion_register_resp_t *)
            ((PUCHAR)pool + sizeof(ophion_register_req_t));

        if (resp->status == OPHION_STATUS_OK && resp->session_key != 0)
        {
            session->session_key = resp->session_key;
            session->registered  = TRUE;

            // Hook (Phase 5b): on first REGISTER, piggyback SET_KERNEL_OFFSETS
            // using the freshly minted session_key. Driver self-resolves
            // PsActiveProcessHead by walking PsInitialSystemProcess.ActiveProcessLinks
            // chain (no dbghelp / PDB needed). Sticky flag — only fires once
            // per boot so we do not thrash global VMM state on each cheat run.
            static volatile LONG s_offsets_pushed = 0;
            if (InterlockedCompareExchange(&s_offsets_pushed, 1, 0) == 0)
            {
#define OPHN_OFF_ACTIVE_PROCESS_LINKS  0x448
#define OPHN_OFF_UNIQUE_PROCESS_ID     0x440
#define OPHN_OFF_IMAGE_FILE_NAME       0x5A8
#define OPHN_OFF_DIRECTORY_TABLE_BASE  0x028
#define OPHN_OFF_SECTION_BASE_ADDRESS  0x520
#define OPHN_OFF_PEB                   0x550

                UINT64 head_va = 0;
                if (PsInitialSystemProcess)
                {
                    PLIST_ENTRY sys_links = (PLIST_ENTRY)
                        ((UCHAR *)PsInitialSystemProcess +
                         OPHN_OFF_ACTIVE_PROCESS_LINKS);
                    PLIST_ENTRY cur = sys_links->Blink;
                    for (UINT32 i = 0; i < 8192; i++)
                    {
                        if (cur == NULL) break;
                        if (cur->Flink == sys_links && cur != sys_links)
                        {
                            head_va = (UINT64)(ULONG_PTR)cur;
                            break;
                        }
                        cur = cur->Blink;
                        if (cur == sys_links) break;
                    }
                    hv_log("[hv] head_va=0x%llx (sys=%p)\n",
                           head_va, PsInitialSystemProcess);
                }

                if (head_va)
                {
                    ophion_kernel_offsets_t kof = {0};
                    kof.ps_active_process_head_va = head_va;
                    kof.off_active_process_links  = OPHN_OFF_ACTIVE_PROCESS_LINKS;
                    kof.off_unique_process_id     = OPHN_OFF_UNIQUE_PROCESS_ID;
                    kof.off_image_file_name       = OPHN_OFF_IMAGE_FILE_NAME;
                    kof.off_directory_table_base  = OPHN_OFF_DIRECTORY_TABLE_BASE;
                    kof.off_section_base_address  = OPHN_OFF_SECTION_BASE_ADDRESS;
                    kof.off_peb                   = OPHN_OFF_PEB;

                    UINT64 vm = OphionRelayCallDirect(
                        session->session_key,
                        OPHION_OP_SET_KERNEL_OFFSETS,
                        (UINT64)(ULONG_PTR)&kof,
                        sizeof(kof));
                    hv_log("[hv] SET_KERNEL_OFFSETS vm=0x%llx kof.status=0x%x\n",
                           vm, kof.status);
                }
            }
        }

        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, resp,
                      sizeof(ophion_register_resp_t));
        irp->IoStatus.Information = sizeof(ophion_register_resp_t);

        ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
        break;
    }

    case IOCTL_HV_RESOLVE:
    {
        ULONG in_len  = io_stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (in_len < sizeof(ophion_resolve_req_t) ||
            out_len < sizeof(ophion_resolve_resp_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POPHION_SESSION session = (POPHION_SESSION)io_stack->FileObject->FsContext;
        if (!session)
        {
            status = STATUS_INVALID_HANDLE;
            break;
        }
        if (!session->registered)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        if (!relay_is_armed())
        {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        SIZE_T pool_size = sizeof(ophion_resolve_req_t) +
                           sizeof(ophion_resolve_resp_t);
        PVOID  pool      = ExAllocatePool2(POOL_FLAG_NON_PAGED, pool_size,
                                           OPHION_RELAY_TAG);
        if (!pool)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(pool, irp->AssociatedIrp.SystemBuffer,
                      sizeof(ophion_resolve_req_t));
        RtlZeroMemory((PUCHAR)pool + sizeof(ophion_resolve_req_t),
                      sizeof(ophion_resolve_resp_t));

        OPHION_RELAY_REQ req = {0};
        req.session     = session;
        req.op          = OPHION_OP_RESOLVE_TARGET;
        req.in_buf      = pool;
        req.in_size     = (UINT32)pool_size;
        req.out_buf     = pool;
        req.out_size    = (UINT32)pool_size;
        req.attach_proc = session->owner_proc;

        NTSTATUS rs = relay_submit(&req);
        if (!NT_SUCCESS(rs))
        {
            ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
            status = rs;
            break;
        }

        ophion_resolve_resp_t *resp = (ophion_resolve_resp_t *)
            ((PUCHAR)pool + sizeof(ophion_resolve_req_t));

        if (resp->status == OPHION_STATUS_OK && resp->target_pid != 0)
        {
            session->target_pid = resp->target_pid;
        }

        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, resp,
                      sizeof(ophion_resolve_resp_t));
        irp->IoStatus.Information = sizeof(ophion_resolve_resp_t);

        ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
        break;
    }

    case IOCTL_HV_UNREGISTER:
    {
        POPHION_SESSION session = (POPHION_SESSION)io_stack->FileObject->FsContext;
        if (!session)
        {
            status = STATUS_INVALID_HANDLE;
            break;
        }
        if (!session->registered)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        status = SessionVmcallUnregister(session);
        irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_HV_READ_SCATTER:
    {
        // METHOD_OUT_DIRECT:
        //   input  -> SystemBuffer  (ophion_read_scatter_req_t, full size)
        //   output -> irp->MdlAddress (gathered results land here, len = OutputBufferLength)
        ULONG in_len  = io_stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (in_len < sizeof(ophion_read_scatter_req_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (!irp->MdlAddress || out_len == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        POPHION_SESSION session = (POPHION_SESSION)io_stack->FileObject->FsContext;
        if (!session)
        {
            status = STATUS_INVALID_HANDLE;
            break;
        }
        if (!session->registered)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        if (!relay_is_armed())
        {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        ophion_read_scatter_req_t *user_req =
            (ophion_read_scatter_req_t *)irp->AssociatedIrp.SystemBuffer;
        if (user_req->entry_count == 0 ||
            user_req->entry_count > OPHION_READ_SCATTER_MAX_ENTRIES)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PVOID gather_sysva = MmGetSystemAddressForMdlSafe(
            irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        if (!gather_sysva)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        SIZE_T pool_size = sizeof(ophion_read_scatter_req_t) +
                           sizeof(ophion_read_scatter_resp_t);
        PVOID  pool      = ExAllocatePool2(POOL_FLAG_NON_PAGED, pool_size,
                                           OPHION_RELAY_TAG);
        if (!pool)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(pool, user_req, sizeof(ophion_read_scatter_req_t));
        RtlZeroMemory((PUCHAR)pool + sizeof(ophion_read_scatter_req_t),
                      sizeof(ophion_read_scatter_resp_t));

        // Replace user-supplied out_buf_va with MDL-pinned system VA (Q7-B).
        // Cap out_buf_size to MDL byte count to bound VMM writes.
        ophion_read_scatter_req_t *kreq = (ophion_read_scatter_req_t *)pool;
        kreq->out_buf_va   = (UINT64)(ULONG_PTR)gather_sysva;
        kreq->out_buf_size = out_len;

        OPHION_RELAY_REQ req = {0};
        req.session     = session;
        req.op          = OPHION_OP_READ_SCATTER;
        req.in_buf      = pool;
        req.in_size     = (UINT32)pool_size;
        req.out_buf     = pool;
        req.out_size    = (UINT32)pool_size;
        req.attach_proc = session->owner_proc;

        NTSTATUS rs = relay_submit(&req);
        if (!NT_SUCCESS(rs))
        {
            ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
            status = rs;
            break;
        }

        ophion_read_scatter_resp_t *resp = (ophion_read_scatter_resp_t *)
            ((PUCHAR)pool + sizeof(ophion_read_scatter_req_t));

        // METHOD_OUT_DIRECT has no separate response channel beyond the gather
        // buffer. Convention: driver writes the 16-byte ophion_read_scatter_resp_t
        // at offset 0 of the gather buffer; caller-supplied entries must use
        // out_offset >= sizeof(ophion_read_scatter_resp_t) (i.e. >= 16).
        if (out_len >= sizeof(ophion_read_scatter_resp_t))
        {
            RtlCopyMemory(gather_sysva, resp, sizeof(ophion_read_scatter_resp_t));
        }

        irp->IoStatus.Information = (ULONG_PTR)resp->total_bytes +
                                    sizeof(ophion_read_scatter_resp_t);

        if (resp->status != OPHION_STATUS_OK)
        {
            status = STATUS_PARTIAL_COPY;
        }
        else
        {
            status = STATUS_SUCCESS;
        }

        ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
        break;
    }

    case IOCTL_HV_WRITE_MANY:
    {
        ULONG in_len  = io_stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (in_len < sizeof(ophion_write_many_req_t) ||
            out_len < sizeof(ophion_write_many_resp_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POPHION_SESSION session = (POPHION_SESSION)io_stack->FileObject->FsContext;
        if (!session)
        {
            status = STATUS_INVALID_HANDLE;
            break;
        }
        if (!session->registered)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        if (!relay_is_armed())
        {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        ophion_write_many_req_t *user_req =
            (ophion_write_many_req_t *)irp->AssociatedIrp.SystemBuffer;
        if (user_req->entry_count == 0 ||
            user_req->entry_count > OPHION_WRITE_MANY_MAX_ENTRIES)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        SIZE_T pool_size = sizeof(ophion_write_many_req_t) +
                           sizeof(ophion_write_many_resp_t);
        PVOID  pool      = ExAllocatePool2(POOL_FLAG_NON_PAGED, pool_size,
                                           OPHION_RELAY_TAG);
        if (!pool)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(pool, user_req, sizeof(ophion_write_many_req_t));
        RtlZeroMemory((PUCHAR)pool + sizeof(ophion_write_many_req_t),
                      sizeof(ophion_write_many_resp_t));

        OPHION_RELAY_REQ req = {0};
        req.session     = session;
        req.op          = OPHION_OP_WRITE_MANY;
        req.in_buf      = pool;
        req.in_size     = (UINT32)pool_size;
        req.out_buf     = pool;
        req.out_size    = (UINT32)pool_size;
        req.attach_proc = session->owner_proc;

        NTSTATUS rs = relay_submit(&req);
        if (!NT_SUCCESS(rs))
        {
            ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
            status = rs;
            break;
        }

        ophion_write_many_resp_t *resp = (ophion_write_many_resp_t *)
            ((PUCHAR)pool + sizeof(ophion_write_many_req_t));

        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, resp,
                      sizeof(ophion_write_many_resp_t));
        irp->IoStatus.Information = sizeof(ophion_write_many_resp_t);

        if (resp->status != OPHION_STATUS_OK)
        {
            status = STATUS_PARTIAL_COPY;
        }

        ExFreePoolWithTag(pool, OPHION_RELAY_TAG);
        break;
    }

    case IOCTL_HV_GET_VMM_PERCPU_LOG:
    {
        // Step #8 (Grill Q21-C): drain VMM per-CPU vmexit log via VMCALL.
        //
        // User layout (METHOD_BUFFERED, single SystemBuffer used for both
        // directions):
        //   - input: ignored (any size, including 0)
        //   - output: [ophion_get_percpu_log_resp_t][snapshot blob...]
        //     where blob is [magic u64][cpu_count u32][rec_per_cpu u32][rings...]
        //
        // Snapshot blob lives in a separate non-paged pool (out_pool) which
        // we hand to VMM as out_buf_va; VMM PT-walks via system CR3 (no
        // KeStackAttachProcess required) and writes via vmm_guest_write.
        ULONG out_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;
        if (out_len < sizeof(ophion_get_percpu_log_resp_t))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POPHION_SESSION session = (POPHION_SESSION)io_stack->FileObject->FsContext;
        if (!session)
        {
            status = STATUS_INVALID_HANDLE;
            break;
        }
        if (!session->registered)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        if (!relay_is_armed())
        {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        ULONG  blob_capacity = out_len - sizeof(ophion_get_percpu_log_resp_t);
        SIZE_T req_pool_size = sizeof(ophion_get_percpu_log_req_t) +
                               sizeof(ophion_get_percpu_log_resp_t);

        PVOID  req_pool  = ExAllocatePool2(POOL_FLAG_NON_PAGED, req_pool_size,
                                           OPHION_RELAY_TAG);
        PVOID  blob_pool = (blob_capacity > 0)
                         ? ExAllocatePool2(POOL_FLAG_NON_PAGED, blob_capacity,
                                           OPHION_RELAY_TAG)
                         : NULL;

        if (!req_pool || (blob_capacity > 0 && !blob_pool))
        {
            if (req_pool)  ExFreePoolWithTag(req_pool,  OPHION_RELAY_TAG);
            if (blob_pool) ExFreePoolWithTag(blob_pool, OPHION_RELAY_TAG);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ophion_get_percpu_log_req_t *kreq =
            (ophion_get_percpu_log_req_t *)req_pool;
        kreq->out_buf_va   = (UINT64)(ULONG_PTR)blob_pool;
        kreq->out_buf_size = blob_capacity;
        kreq->reserved     = 0;
        RtlZeroMemory((PUCHAR)req_pool + sizeof(ophion_get_percpu_log_req_t),
                      sizeof(ophion_get_percpu_log_resp_t));

        OPHION_RELAY_REQ req = {0};
        req.session     = session;
        req.op          = OPHION_OP_GET_PERCPU_LOG;
        req.in_buf      = req_pool;
        req.in_size     = (UINT32)req_pool_size;
        req.out_buf     = req_pool;
        req.out_size    = (UINT32)req_pool_size;
        req.attach_proc = NULL;        // system-CR3 path; no user attach needed

        NTSTATUS rs = relay_submit(&req);
        if (!NT_SUCCESS(rs))
        {
            ExFreePoolWithTag(req_pool, OPHION_RELAY_TAG);
            if (blob_pool) ExFreePoolWithTag(blob_pool, OPHION_RELAY_TAG);
            status = rs;
            break;
        }

        ophion_get_percpu_log_resp_t *kresp =
            (ophion_get_percpu_log_resp_t *)
            ((PUCHAR)req_pool + sizeof(ophion_get_percpu_log_req_t));

        // user out layout: [resp][blob...]
        PUCHAR user_out = (PUCHAR)irp->AssociatedIrp.SystemBuffer;
        RtlCopyMemory(user_out, kresp, sizeof(*kresp));

        ULONG bytes = kresp->bytes_written;
        if (bytes > blob_capacity) bytes = blob_capacity;
        if (blob_pool && bytes > 0)
        {
            RtlCopyMemory(user_out + sizeof(*kresp), blob_pool, bytes);
        }
        irp->IoStatus.Information = sizeof(*kresp) + bytes;

        if (kresp->status != OPHION_STATUS_OK)
        {
            status = STATUS_PARTIAL_COPY;
        }

        ExFreePoolWithTag(req_pool, OPHION_RELAY_TAG);
        if (blob_pool) ExFreePoolWithTag(blob_pool, OPHION_RELAY_TAG);
        break;
    }


    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
