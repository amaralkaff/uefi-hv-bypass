/*
*   driver.c - windows kernel driver entry point for the hypervisor
*   creates a device object and initializes vmx
*   Step #3 (Grill Q9-C): obscure device name, no DosDevices symlink
*   Step #3 (Grill Q6-B): per-FILE_OBJECT session in FsContext
*   Step #3 (Grill Q1/Q2/Q8): relay worker + trampoline VA discovery
*/
#include "hv.h"
#include "relay.h"

#define IOCTL_BASE      0x800
#define IOCTL_HV_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_LOG CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

static NTSTATUS DriverCreate(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverCleanup(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);

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
        // Future step #4+: if session->registered, issue UNREGISTER VMCALL here
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

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
