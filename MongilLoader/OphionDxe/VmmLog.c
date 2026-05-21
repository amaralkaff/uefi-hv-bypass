/*
 * VmmLog.c - minimal logger replacing Ophion/src/logger.c.
 *
 * Pre-ExitBootServices: print directly via UEFI Print() (boot console).
 * Post-EBS: ring buffer (deferred to Phase 2.5 — stub for now, drops messages).
 *
 * Real Ophion has a 1MB ring buffer + IOCTL exposure. For Phase 2 we only need
 * the boot-time path so that vmm bring-up is observable.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include "EfiCompat.h"

#include <stdarg.h>

#define HV_LOG_BUF_SIZE 512

static BOOLEAN g_post_ebs = FALSE;

VOID
hv_log_post_ebs(VOID)
{
    g_post_ebs = TRUE;
}

VOID
hv_log(IN CONST CHAR8 *fmt, ...)
{
    if (g_post_ebs) {
        // TODO: ring buffer in EfiRuntimeServicesData. For now, drop.
        return;
    }
    CHAR8 buf[HV_LOG_BUF_SIZE];
    VA_LIST va;
    VA_START(va, fmt);
    AsciiVSPrint(buf, sizeof(buf), fmt, va);
    VA_END(va);
    Print(L"%a", buf);
}
