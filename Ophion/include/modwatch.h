/*
*   modwatch.h - kernel module watcher for auto-detecting xhunter1.sys
*   uses PsSetLoadImageNotifyRoutine + PsLoadedModuleList walk
*/
#pragma once

#include <ntddk.h>

BOOLEAN modwatch_init(VOID);
VOID    modwatch_destroy(VOID);

BOOLEAN modwatch_find_module(
    PCWSTR              module_name,
    UINT64 *            out_base,
    UINT32 *            out_size
);
