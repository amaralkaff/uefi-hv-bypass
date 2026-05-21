/*
 * probe_drv.c - Kernel companion for vgk_probe.exe
 *
 * Exposes IOCTLs for RDMSR / readcr4 / readDEBUGCTL with SEH-wrapped reads so
 * the user-mode probe can verify HV synthetic MSRs trigger #GP and CR4
 * enforcement bits stay set at idle.
 *
 * Driver name: VgkProbeDrv
 * Device:      \Device\VgkProbeDrv
 * DOS symlink: \DosDevices\VgkProbeDrv (\\\\.\\VgkProbeDrv)
 *
 * Load via SCM:
 *   sc create VgkProbeDrv type=kernel binPath=C:\Tools\probe_drv\VgkProbeDrv.sys
 *   sc start VgkProbeDrv
 *
 * Unload:
 *   sc stop VgkProbeDrv && sc delete VgkProbeDrv
 *
 * SECURITY: this driver allows arbitrary RDMSR from user-mode. ONLY load
 * on the dev test bench. DO NOT install on a system that ever runs Vanguard.
 */
#include <ntddk.h>
#include <intrin.h>

#define POOL_TAG  'BorP'

#define IOCTL_PROBE_RDMSR        CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROBE_RDMSR_AP     CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROBE_READCR4      CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROBE_READDEBUGCTL CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct {
    ULONG  msr_index;
    UINT64 value;
    ULONG  gp_fired;
    ULONG  cpu_before;
    ULONG  cpu_after;
} rdmsr_req_t;
#pragma pack(pop)

static UNICODE_STRING g_device_name;
static UNICODE_STRING g_symlink_name;

static NTSTATUS
probe_dispatch_create_close(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
do_rdmsr_ioctl_pinned(PIRP irp, PIO_STACK_LOCATION sl, ULONG target_cpu)
{
    if (sl->Parameters.DeviceIoControl.InputBufferLength < sizeof(rdmsr_req_t) ||
        sl->Parameters.DeviceIoControl.OutputBufferLength < sizeof(rdmsr_req_t)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    rdmsr_req_t *req = (rdmsr_req_t *)irp->AssociatedIrp.SystemBuffer;
    req->value = 0;
    req->gp_fired = 0;
    req->cpu_before = KeGetCurrentProcessorNumberEx(NULL);

    KAFFINITY old = KeSetSystemAffinityThreadEx((KAFFINITY)(1ULL << target_cpu));

    for (int i = 0; i < 100 && KeGetCurrentProcessorNumberEx(NULL) != target_cpu; ++i) {
        YieldProcessor();
    }
    req->cpu_after = KeGetCurrentProcessorNumberEx(NULL);

    __try {
        req->value = __readmsr(req->msr_index);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        req->gp_fired = 1;
    }

    KeRevertToUserAffinityThreadEx(old);

    irp->IoStatus.Information = sizeof(rdmsr_req_t);
    return STATUS_SUCCESS;
}

static NTSTATUS
do_rdmsr_ioctl(PIRP irp, PIO_STACK_LOCATION sl)
{
    return do_rdmsr_ioctl_pinned(irp, sl, 0);  // BSP
}

static NTSTATUS
do_rdmsr_ioctl_ap(PIRP irp, PIO_STACK_LOCATION sl)
{
    return do_rdmsr_ioctl_pinned(irp, sl, 4);  // AP4 (Phase 3 partial = not virt'd)
}

static NTSTATUS
do_readcr4_ioctl(PIRP irp, PIO_STACK_LOCATION sl)
{
    if (sl->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT64)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    UINT64 *out = (UINT64 *)irp->AssociatedIrp.SystemBuffer;
    *out = __readcr4();
    irp->IoStatus.Information = sizeof(UINT64);
    return STATUS_SUCCESS;
}

static NTSTATUS
do_readdebugctl_ioctl(PIRP irp, PIO_STACK_LOCATION sl)
{
    if (sl->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT64)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    UINT64 *out = (UINT64 *)irp->AssociatedIrp.SystemBuffer;
    *out = 0;
    __try {
        *out = __readmsr(0x1D9);  // IA32_DEBUGCTL
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Some CPUs gate DEBUGCTL behind PMU enable; treat as zero.
    }
    irp->IoStatus.Information = sizeof(UINT64);
    return STATUS_SUCCESS;
}

static NTSTATUS
probe_dispatch_ioctl(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (sl->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_PROBE_RDMSR:        status = do_rdmsr_ioctl(irp, sl); break;
    case IOCTL_PROBE_RDMSR_AP:     status = do_rdmsr_ioctl_ap(irp, sl); break;
    case IOCTL_PROBE_READCR4:      status = do_readcr4_ioctl(irp, sl); break;
    case IOCTL_PROBE_READDEBUGCTL: status = do_readdebugctl_ioctl(irp, sl); break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

VOID
DriverUnload(PDRIVER_OBJECT drv)
{
    IoDeleteSymbolicLink(&g_symlink_name);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);
    PDEVICE_OBJECT dev = NULL;

    RtlInitUnicodeString(&g_device_name,  L"\\Device\\VgkProbeDrv");
    RtlInitUnicodeString(&g_symlink_name, L"\\DosDevices\\VgkProbeDrv");

    NTSTATUS status = IoCreateDevice(drv, 0, &g_device_name,
                                     FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&g_symlink_name, &g_device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(dev);
        return status;
    }

    drv->MajorFunction[IRP_MJ_CREATE]         = probe_dispatch_create_close;
    drv->MajorFunction[IRP_MJ_CLOSE]          = probe_dispatch_create_close;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = probe_dispatch_ioctl;
    drv->DriverUnload                         = DriverUnload;

    return STATUS_SUCCESS;
}
