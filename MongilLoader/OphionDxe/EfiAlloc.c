/*
 * EfiAlloc.c - EfiRuntimeServicesCode page allocator for Ophion VMM body
 *
 * VMM allocations must persist across ExitBootServices and survive Windows
 * boot. EfiRuntimeServicesCode pages are not enumerable from the Windows
 * kernel side via PsLoadedModuleList, hiding the VMM body from vgk's
 * `vgk_refresh_driver_list()` 1.5s scan loop.
 *
 * Tracked allocations get freed in the unlikely teardown path; in the normal
 * boot flow allocations persist for the system lifetime.
 */
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>

#include "EfiCompat.h"

#define MAX_TRACKED_ALLOCS 64

typedef struct {
    EFI_PHYSICAL_ADDRESS  base;
    UINTN                 page_count;
    BOOLEAN               in_use;
} VMM_ALLOCATION_RECORD;

static VMM_ALLOCATION_RECORD g_alloc_table[MAX_TRACKED_ALLOCS];
static UINTN                  g_alloc_count = 0;

PVOID
EfiAllocateRuntimePages(SIZE_T Pages)
{
    if (Pages == 0) return NULL;

    EFI_PHYSICAL_ADDRESS phys = 0;
    EFI_STATUS Status = gBS->AllocatePages(AllocateAnyPages,
                                           EfiRuntimeServicesCode,
                                           Pages,
                                           &phys);
    if (EFI_ERROR(Status)) {
        Print(L"[EfiAlloc] AllocatePages(RuntimeCode, %u pages) = %r\n",
              (UINT32)Pages, Status);
        return NULL;
    }

    ZeroMem((VOID *)(UINTN)phys, Pages * EFI_PAGE_SIZE);

    if (g_alloc_count < MAX_TRACKED_ALLOCS) {
        g_alloc_table[g_alloc_count].base       = phys;
        g_alloc_table[g_alloc_count].page_count = Pages;
        g_alloc_table[g_alloc_count].in_use     = TRUE;
        g_alloc_count++;
    }

    return (PVOID)(UINTN)phys;
}

VOID
EfiFreeRuntimePages(PVOID Buffer, SIZE_T Pages)
{
    if (Buffer == NULL || Pages == 0) return;

    EFI_PHYSICAL_ADDRESS phys = (EFI_PHYSICAL_ADDRESS)(UINTN)Buffer;

    for (UINTN i = 0; i < g_alloc_count; ++i) {
        if (g_alloc_table[i].in_use && g_alloc_table[i].base == phys) {
            g_alloc_table[i].in_use = FALSE;
            break;
        }
    }

    gBS->FreePages(phys, Pages);
}

UINTN
EfiAllocCount(VOID)
{
    UINTN n = 0;
    for (UINTN i = 0; i < g_alloc_count; ++i) {
        if (g_alloc_table[i].in_use) ++n;
    }
    return n;
}
