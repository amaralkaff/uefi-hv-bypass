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
#define IOCTL_HV_STATUS       CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_GET_LOG      CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_REGISTER     CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_RESOLVE      CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_UNREGISTER   CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED,   FILE_ANY_ACCESS)
#define IOCTL_HV_READ_SCATTER CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_HV_WRITE_MANY   CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED,   FILE_ANY_ACCESS)

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
    hv_log("[hv] Unloading hypervisor driver...\n");

    relay_shutdown();

    broadcast_terminate_all();
    vmx_terminate();

    if (driver_obj->DeviceObject)
    {
        IoDeleteDevice(driver_obj->DeviceObject);
    }

    hv_log("[hv] Driver unloaded.\n");
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

    if (!vmx_init())
    {
        hv_log("[hv] VMX initialization FAILED!\n");
        vmx_terminate();
        IoDeleteDevice(device_obj);
        return STATUS_HV_OPERATION_FAILED;
    }

    status = relay_init();
    if (!NT_SUCCESS(status))
    {
        hv_log("[hv] relay_init failed: 0x%X (continuing without relay)\n", status);
        // Non-fatal: VMM still works for status/log IOCTLs even if relay fails
    }
    else
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

    hv_log("[hv] Hypervisor loaded and active on all cores!\n");
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


    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
