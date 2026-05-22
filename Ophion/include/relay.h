/*
 *  relay.h - user->VMM VMCALL bridge (Step #3 scaffolding, no IOCTLs yet)
 *
 *  Per-handle session attached to FILE_OBJECT->FsContext at IRP_MJ_CREATE.
 *  Worker thread pinned to BSP drains a queue and invokes the trampoline.
 *  Trampoline VA is parsed once at DriverEntry from NtCreateProfile patch.
 */
#pragma once

#include <ntddk.h>

#define OPHION_DEVICE_NAME      L"\\Device\\MsftHidIo"
#define OPHION_RELAY_TAG        'lRpO'   // 'OpRl'

typedef struct _OPHION_SESSION {
    LIST_ENTRY  link;                    // global session list (relay.c)
    HANDLE      owner_pid;
    PEPROCESS   owner_proc;              // ObReferenceObject'd
    UINT64      session_key;             // returned by VMM REGISTER (0 = not registered)
    BOOLEAN     registered;
    UINT32      target_pid;              // cached after RESOLVE
    PEPROCESS   target_proc;             // ObReferenceObject'd, NULL until RESOLVE
} OPHION_SESSION, *POPHION_SESSION;

typedef struct _OPHION_RELAY_REQ {
    LIST_ENTRY      link;
    POPHION_SESSION session;
    UINT32          op;                  // OPHION_OP_*
    PVOID           in_buf;              // system VA (kernel pool or MDL-mapped)
    UINT32          in_size;
    PVOID           out_buf;             // system VA, can equal in_buf for in-place
    UINT32          out_size;
    PEPROCESS       attach_proc;         // KeStackAttachProcess target (NULL = no attach)
    NTSTATUS        result;
    UINT64          out_rax;             // rax returned by VMCALL
    KEVENT          completion;
} OPHION_RELAY_REQ, *POPHION_RELAY_REQ;

NTSTATUS relay_init(VOID);
VOID     relay_shutdown(VOID);

UINT64   relay_get_trampoline_va(VOID);
VOID     relay_set_trampoline_va(UINT64 va);
BOOLEAN  relay_is_armed(VOID);

POPHION_SESSION relay_session_alloc(VOID);
VOID            relay_session_free(POPHION_SESSION session);

NTSTATUS relay_submit(POPHION_RELAY_REQ req);
