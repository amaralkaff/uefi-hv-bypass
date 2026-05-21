/*
 *  relay.c - user->VMM VMCALL bridge (Step #3)
 *
 *  Step #3 lands plumbing only. No IOCTLs use this yet; subsequent steps
 *  wire IOCTL_HV_REGISTER (#4), RESOLVE/UNREGISTER (#5), READ_SCATTER (#6),
 *  WRITE_MANY (#7).
 *
 *  Architecture (Grill Q1-Q9):
 *    - Driver discovers trampoline VA at DriverEntry by parsing the
 *      NtCreateProfile patch:  48 B8 <imm64> FF E0 90 90  (mov rax,imm64;
 *      jmp rax; nop nop). The imm64 field is the trampoline VA in
 *      EfiRuntimeServicesCode.
 *    - One worker system thread is pinned to the BSP via
 *      KeSetSystemAffinityThread, then drains a queue of OPHION_RELAY_REQ.
 *    - Worker optionally KeStackAttachProcess(req->attach_proc) so VMCALL
 *      observes user CR3 for session.caller_cr3 auth (Grill Q6).
 *    - Buffer VAs passed in r9 are MDL system VAs (Grill Q7); the IOCTL
 *      handlers (later steps) will lock user buffers with METHOD_*_DIRECT
 *      and forward MmGetSystemAddressForMdlSafe results.
 *    - Each FILE_OBJECT carries a per-handle OPHION_SESSION in FsContext
 *      (Grill Q6), allocated on IRP_MJ_CREATE, freed on IRP_MJ_CLEANUP.
 */

#include "hv.h"
#include "relay.h"
#include "asm_prototypes.h"

#define RELAY_QUEUE_TAG     'qRpO'

static volatile LONG    s_initialized;
static UINT64           s_trampoline_va;
static BOOLEAN          s_armed;

static LIST_ENTRY       s_queue;
static KSPIN_LOCK       s_queue_lock;
static KSEMAPHORE       s_queue_sem;
static PETHREAD         s_worker_thread;
static volatile LONG    s_worker_stop;

static LIST_ENTRY       s_session_list;
static KSPIN_LOCK       s_session_lock;

static UINT64
relay_parse_trampoline_va(VOID)
{
    UNICODE_STRING name;
    PUCHAR         body;
    UINT64         tramp = 0;

    RtlInitUnicodeString(&name, L"NtCreateProfile");
    body = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!body)
    {
        hv_log("[relay] NtCreateProfile lookup failed\n");
        return 0;
    }

    if (body[0] == 0x48 && body[1] == 0xB8 &&
        body[10] == 0xFF && body[11] == 0xE0)
    {
        RtlCopyMemory(&tramp, &body[2], sizeof(UINT64));
    }
    else
    {
        hv_log("[relay] NtCreateProfile prologue not patched: %02X %02X .. %02X %02X\n",
               body[0], body[1], body[10], body[11]);
    }

    return tramp;
}

static VOID
relay_worker(_In_ PVOID context)
{
    UNREFERENCED_PARAMETER(context);

    KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);
    UNREFERENCED_PARAMETER(old_aff);
    hv_log("[relay] worker started, pinned to BSP\n");

    for (;;)
    {
        KeWaitForSingleObject(&s_queue_sem, Executive, KernelMode, FALSE, NULL);

        if (InterlockedCompareExchange(&s_worker_stop, 0, 0))
        {
            break;
        }

        KIRQL irql;
        KeAcquireSpinLock(&s_queue_lock, &irql);
        PLIST_ENTRY entry = NULL;
        if (!IsListEmpty(&s_queue))
        {
            entry = RemoveHeadList(&s_queue);
        }
        KeReleaseSpinLock(&s_queue_lock, irql);

        if (!entry)
        {
            continue;
        }

        POPHION_RELAY_REQ req = CONTAINING_RECORD(entry, OPHION_RELAY_REQ, link);

        KAPC_STATE apc_state = {0};
        BOOLEAN attached = FALSE;
        if (req->attach_proc)
        {
            KeStackAttachProcess(req->attach_proc, &apc_state);
            attached = TRUE;
        }

        if (s_armed && s_trampoline_va)
        {
            UINT64 key_in_rax = req->session ? req->session->session_key : 0;
            req->out_rax = OphionRelayCallTrampoline(
                s_trampoline_va,
                key_in_rax,
                (UINT64)req->op,
                (UINT64)(ULONG_PTR)req->in_buf,
                (UINT64)req->in_size);
            req->result = STATUS_SUCCESS;
        }
        else
        {
            req->out_rax = 0;
            req->result = STATUS_DEVICE_NOT_READY;
        }

        if (attached)
        {
            KeUnstackDetachProcess(&apc_state);
        }

        KeSetEvent(&req->completion, IO_NO_INCREMENT, FALSE);
    }

    hv_log("[relay] worker exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
relay_init(VOID)
{
    if (InterlockedCompareExchange(&s_initialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    InitializeListHead(&s_queue);
    KeInitializeSpinLock(&s_queue_lock);
    KeInitializeSemaphore(&s_queue_sem, 0, MAXLONG);

    InitializeListHead(&s_session_list);
    KeInitializeSpinLock(&s_session_lock);

    s_trampoline_va = relay_parse_trampoline_va();
    s_armed = (s_trampoline_va != 0);
    hv_log("[relay] trampoline_va=0x%llx armed=%u\n", s_trampoline_va, (UINT32)s_armed);

    HANDLE hthread = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = PsCreateSystemThread(
        &hthread,
        THREAD_ALL_ACCESS,
        &oa,
        NULL,
        NULL,
        relay_worker,
        NULL);

    if (!NT_SUCCESS(status))
    {
        hv_log("[relay] PsCreateSystemThread failed: 0x%X\n", status);
        InterlockedExchange(&s_initialized, 0);
        return status;
    }

    status = ObReferenceObjectByHandle(
        hthread,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID *)&s_worker_thread,
        NULL);
    ZwClose(hthread);

    if (!NT_SUCCESS(status))
    {
        hv_log("[relay] ObReferenceObjectByHandle(thread) failed: 0x%X\n", status);
        InterlockedExchange(&s_worker_stop, 1);
        KeReleaseSemaphore(&s_queue_sem, IO_NO_INCREMENT, 1, FALSE);
        InterlockedExchange(&s_initialized, 0);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
relay_shutdown(VOID)
{
    if (InterlockedCompareExchange(&s_initialized, 0, 1) != 1)
    {
        return;
    }

    InterlockedExchange(&s_worker_stop, 1);
    KeReleaseSemaphore(&s_queue_sem, IO_NO_INCREMENT, 1, FALSE);

    if (s_worker_thread)
    {
        KeWaitForSingleObject(s_worker_thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(s_worker_thread);
        s_worker_thread = NULL;
    }

    KIRQL irql;
    KeAcquireSpinLock(&s_queue_lock, &irql);
    while (!IsListEmpty(&s_queue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&s_queue);
        POPHION_RELAY_REQ req = CONTAINING_RECORD(entry, OPHION_RELAY_REQ, link);
        req->result = STATUS_CANCELLED;
        KeSetEvent(&req->completion, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&s_queue_lock, irql);

    s_armed = FALSE;
    s_trampoline_va = 0;
}

UINT64
relay_get_trampoline_va(VOID)
{
    return s_trampoline_va;
}

BOOLEAN
relay_is_armed(VOID)
{
    return s_armed;
}

POPHION_SESSION
relay_session_alloc(VOID)
{
    POPHION_SESSION s = (POPHION_SESSION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OPHION_SESSION), OPHION_RELAY_TAG);
    if (!s)
    {
        return NULL;
    }

    s->owner_proc = PsGetCurrentProcess();
    ObReferenceObject(s->owner_proc);
    s->owner_pid = PsGetCurrentProcessId();

    KIRQL irql;
    KeAcquireSpinLock(&s_session_lock, &irql);
    InsertTailList(&s_session_list, &s->link);
    KeReleaseSpinLock(&s_session_lock, irql);

    return s;
}

VOID
relay_session_free(POPHION_SESSION s)
{
    if (!s)
    {
        return;
    }

    KIRQL irql;
    KeAcquireSpinLock(&s_session_lock, &irql);
    RemoveEntryList(&s->link);
    KeReleaseSpinLock(&s_session_lock, irql);

    if (s->target_proc)
    {
        ObDereferenceObject(s->target_proc);
        s->target_proc = NULL;
    }
    if (s->owner_proc)
    {
        ObDereferenceObject(s->owner_proc);
        s->owner_proc = NULL;
    }

    ExFreePoolWithTag(s, OPHION_RELAY_TAG);
}

NTSTATUS
relay_submit(POPHION_RELAY_REQ req)
{
    if (!req)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!s_armed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!InterlockedCompareExchange(&s_initialized, 0, 0))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeInitializeEvent(&req->completion, NotificationEvent, FALSE);

    KIRQL irql;
    KeAcquireSpinLock(&s_queue_lock, &irql);
    InsertTailList(&s_queue, &req->link);
    KeReleaseSpinLock(&s_queue_lock, irql);

    KeReleaseSemaphore(&s_queue_sem, IO_NO_INCREMENT, 1, FALSE);

    KeWaitForSingleObject(&req->completion, Executive, KernelMode, FALSE, NULL);

    return req->result;
}
