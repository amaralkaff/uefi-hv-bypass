/*
*   xhunter_hook.h - EPT hook definitions for xhunter1.sys (XIGNCODE3) interception
*   protocol structs derived from public vulnerability disclosure by Zahedinia Yassan
*/
#pragma once

#include <ntddk.h>

/*
 * xhunter1 protocol constants
 * communication: WriteFile to \\.\xhunter1, IRP_MJ_WRITE, DO_BUFFERED_IO
 */
#define XH_CMD_LEN              624
#define XH_RSP_LEN              762
#define XH_REQUEST_MAGIC        0x345821ABu
#define XH_RESPONSE_MAGIC       0x12121212u
#define XH_CMD_MIN              774
#define XH_CMD_MAX              821
#define XH_CMD_COUNT            (XH_CMD_MAX - XH_CMD_MIN + 1)

/* offsets within IRP structure (Windows 10 x64) */
#define IRP_SYSTEMBUF_OFFSET    0x18    /* AssociatedIrp.SystemBuffer */

/* offsets within XH_CMD_PACKET (SystemBuffer) */
#define XH_OFF_IN_SIZE          0       /* UINT32 in_size = 624 */
#define XH_OFF_MAGIC            4       /* UINT32 magic = 0x345821AB */
#define XH_OFF_NONCE            8       /* UINT32 nonce */
#define XH_OFF_COMMAND          12      /* UINT32 command (774..821) */
#define XH_OFF_RESPONSE_VA      16      /* UINT64 user VA for response */
#define XH_OFF_ARGS             24      /* per-command args */

/* filter actions per command */
typedef enum _XH_FILTER_ACTION {
    XH_ACTION_PASS      = 0,
    XH_ACTION_BLOCK     = 1,
    XH_ACTION_LOG_ONLY  = 2
} XH_FILTER_ACTION;

/* log entry — written atomically from VMX-root, read from PASSIVE_LEVEL */
typedef struct _XH_LOG_ENTRY {
    UINT64              timestamp;
    UINT64              guest_cr3;
    UINT32              command;
    XH_FILTER_ACTION    action;
} XH_LOG_ENTRY, *PXH_LOG_ENTRY;

#define XH_LOG_CAPACITY         4096
#define XH_LOG_MASK             (XH_LOG_CAPACITY - 1)

/* EPT hook state — allocated once, global */
typedef struct _XH_HOOK_STATE {
    volatile BOOLEAN    active;
    UINT64              xhunter_base;
    UINT64              hook_rva;
    UINT64              hook_va;
    UINT64              hook_pa;
    UINT64              hook_page_pa;       /* page-aligned PA */
    UINT32              pml1_index;         /* PML1 index within split (PFN & 0x1FF) */

    /* per-VCPU PML1 entry pointers for hooked page — set during setup,
     * used in vmexit handlers (avoids pa_to_va in VMX-root) */
    void *              pml1_per_vcpu[256];

    /* per-command filter table (indexed by cmd - XH_CMD_MIN) */
    volatile LONG       rules[XH_CMD_COUNT];

    /* ring buffer log */
    DECLSPEC_ALIGN(64) XH_LOG_ENTRY log[XH_LOG_CAPACITY];
    volatile LONG       log_head;
    volatile LONG       log_tail;
    volatile LONG       total_intercepted;
} XH_HOOK_STATE, *PXH_HOOK_STATE;

/* IOCTLs (base 0x802, continuing after existing 0x800/0x801) */
#define IOCTL_HV_XH_GET_LOG    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_XH_SET_RULE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_XH_GET_RULES  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_XH_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_XH_SETUP      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* IOCTL input: set filter rule for one command */
typedef struct _XH_IOCTL_SET_RULE {
    UINT32              command;
    UINT32              action;     /* XH_FILTER_ACTION */
} XH_IOCTL_SET_RULE;

/* IOCTL input: manual hook setup (provide xhunter base + dispatch RVA) */
typedef struct _XH_IOCTL_SETUP {
    UINT64              xhunter_base;
    UINT64              dispatch_rva;
} XH_IOCTL_SETUP;

/* IOCTL output: hook status */
typedef struct _XH_IOCTL_STATUS {
    BOOLEAN             hook_active;
    UINT64              xhunter_base;
    UINT64              hook_va;
    UINT32              log_count;
    UINT32              total_intercepted;
} XH_IOCTL_STATUS, *PXH_IOCTL_STATUS;

/* default dispatch RVA from waryas PoC (sub_14000B568 → RVA 0xB568) */
#define XH_DEFAULT_DISPATCH_RVA     0xB568ULL

/* forward declarations — full types in hv_types.h */
struct _VIRTUAL_MACHINE_STATE;

/*
 * non-root (PASSIVE_LEVEL) functions
 */
BOOLEAN xhook_init(VOID);
VOID    xhook_destroy(VOID);
BOOLEAN xhook_setup_ept(UINT64 xhunter_base, UINT64 dispatch_rva);
VOID    xhook_teardown_ept(VOID);

/*
 * VMX-root functions (called from vmexit handler)
 * return TRUE if the exit was handled by xhook
 */
BOOLEAN xhook_handle_ept_violation(struct _VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN xhook_handle_mtf(struct _VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN xhook_handle_breakpoint(struct _VIRTUAL_MACHINE_STATE * vcpu);

/*
 * IOCTL helpers (PASSIVE_LEVEL)
 */
UINT32  xhook_log_read(PXH_LOG_ENTRY out_buf, UINT32 max_entries);
VOID    xhook_set_rule(UINT32 command, XH_FILTER_ACTION action);
VOID    xhook_get_rules(LONG * out_rules, UINT32 count);
VOID    xhook_get_status(PXH_IOCTL_STATUS status_out);

extern XH_HOOK_STATE * g_xhook;
