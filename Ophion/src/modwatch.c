/*
*   modwatch.c - kernel module watcher
*   auto-detects xhunter1.sys via image-load callback + module list walk
*   triggers EPT hook setup when target is found
*/
#include "hv.h"
#include "modwatch.h"
#include "xhunter_hook.h"

static BOOLEAN g_callback_registered = FALSE;

/*
 * PsLoadedModuleList entry (undocumented but stable since NT 4)
 */
typedef struct _LDR_DATA_TABLE_ENTRY_KM {
    LIST_ENTRY      InLoadOrderLinks;
    PVOID           Reserved1[2];
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
} LDR_DATA_TABLE_ENTRY_KM, *PLDR_DATA_TABLE_ENTRY_KM;

static BOOLEAN
match_name(PCUNICODE_STRING name, PCWSTR target)
{
    UNICODE_STRING target_str;
    RtlInitUnicodeString(&target_str, target);
    return RtlEqualUnicodeString(name, &target_str, TRUE);
}

/*
 * Walk PsLoadedModuleList for a module by name.
 * Must be called at PASSIVE_LEVEL.
 */
BOOLEAN
modwatch_find_module(
    PCWSTR   module_name,
    UINT64 * out_base,
    UINT32 * out_size)
{
    extern LIST_ENTRY * PsLoadedModuleList;
    PLIST_ENTRY head;
    PLIST_ENTRY entry;

    /*
     * PsLoadedModuleList is an exported symbol from ntoskrnl.
     * We resolve it dynamically to avoid link-time dependency on undocumented exports.
     */
    UNICODE_STRING func_name;
    RtlInitUnicodeString(&func_name, L"PsLoadedModuleList");
    head = (PLIST_ENTRY)MmGetSystemRoutineAddress(&func_name);
    if (!head)
    {
        hv_log("[modwatch] PsLoadedModuleList not found\n");
        return FALSE;
    }

    for (entry = head->Flink; entry != head; entry = entry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY_KM ldr =
            CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_KM, InLoadOrderLinks);

        if (ldr->BaseDllName.Buffer && match_name(&ldr->BaseDllName, module_name))
        {
            *out_base = (UINT64)ldr->DllBase;
            *out_size = ldr->SizeOfImage;
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Image-load callback — fires for every driver/DLL load.
 * If xhunter1.sys loads after Ophion, this catches it.
 */
static VOID
modwatch_image_load_callback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);

    if (!FullImageName || !ImageInfo)
        return;

    /* kernel-mode images only (ProcessId == 0 for drivers) */
    if ((UINT64)ProcessId != 0)
        return;

    if (!ImageInfo->SystemModeImage)
        return;

    /* check if filename ends with "xhunter1.sys" */
    UNICODE_STRING target;
    RtlInitUnicodeString(&target, L"xhunter1.sys");

    if (FullImageName->Length < target.Length)
        return;

    UNICODE_STRING suffix;
    suffix.Buffer = (PWCH)((UINT8 *)FullImageName->Buffer +
                   FullImageName->Length - target.Length);
    suffix.Length = target.Length;
    suffix.MaximumLength = target.Length;

    if (!RtlEqualUnicodeString(&suffix, &target, TRUE))
        return;

    hv_log("[modwatch] xhunter1.sys loaded at 0x%llX (size 0x%X)\n",
           (UINT64)ImageInfo->ImageBase, ImageInfo->ImageSize);

    if (g_xhook && !g_xhook->active)
    {
        xhook_setup_ept((UINT64)ImageInfo->ImageBase, XH_DEFAULT_DISPATCH_RVA);
    }
}

BOOLEAN
modwatch_init(VOID)
{
    NTSTATUS status;

    /* first: check if xhunter1 is already loaded */
    UINT64 base = 0;
    UINT32 size = 0;
    if (modwatch_find_module(L"xhunter1.sys", &base, &size))
    {
        hv_log("[modwatch] xhunter1.sys already loaded at 0x%llX (size 0x%X)\n",
               base, size);

        if (g_xhook && !g_xhook->active)
        {
            xhook_setup_ept(base, XH_DEFAULT_DISPATCH_RVA);
        }
    }

    /* register callback for future loads */
    status = PsSetLoadImageNotifyRoutine(modwatch_image_load_callback);
    if (!NT_SUCCESS(status))
    {
        hv_log("[modwatch] PsSetLoadImageNotifyRoutine failed: 0x%X\n", status);
        return FALSE;
    }

    g_callback_registered = TRUE;
    hv_log("[modwatch] Image-load callback registered\n");
    return TRUE;
}

VOID
modwatch_destroy(VOID)
{
    if (g_callback_registered)
    {
        PsRemoveLoadImageNotifyRoutine(modwatch_image_load_callback);
        g_callback_registered = FALSE;
        hv_log("[modwatch] Image-load callback removed\n");
    }
}
