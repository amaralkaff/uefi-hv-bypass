/*
 * VmmLogVar.c - persist VMM status to UEFI non-volatile variable
 *
 * Writes a single string to UEFI var (vendor GUID OPHN) with NV+BS+RT attrs
 * so it persists across reboot AND is readable from Windows via
 * GetFirmwareEnvironmentVariable / PowerShell.
 *
 * Used when boot-time Print() output is invisible (post-EBS or fast flash).
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>

#include "EfiCompat.h"

// Vendor GUID for our variables (random per project)
static EFI_GUID gOphionVarGuid = {
    0x4f50484e, 0x0000, 0x0000,
    { 0x6f, 0x70, 0x68, 0x6e, 0x2d, 0x6c, 0x6f, 0x67 }
};

VOID
VmmLogVarSet(IN CONST CHAR16 *Name, IN CONST CHAR8 *Msg)
{
    UINTN  len = AsciiStrLen(Msg);
    UINT32 attrs = EFI_VARIABLE_NON_VOLATILE
                 | EFI_VARIABLE_BOOTSERVICE_ACCESS
                 | EFI_VARIABLE_RUNTIME_ACCESS;
    gRT->SetVariable((CHAR16 *)Name, &gOphionVarGuid, attrs, len, (VOID *)Msg);
}

VOID
VmmLogVarSetf(IN CONST CHAR16 *Name, IN CONST CHAR8 *Fmt, ...)
{
    static CHAR8 buf[512];
    VA_LIST va;
    VA_START(va, Fmt);
    UINTN n = AsciiVSPrint(buf, sizeof(buf), Fmt, va);
    VA_END(va);
    UINT32 attrs = EFI_VARIABLE_NON_VOLATILE
                 | EFI_VARIABLE_BOOTSERVICE_ACCESS
                 | EFI_VARIABLE_RUNTIME_ACCESS;
    gRT->SetVariable((CHAR16 *)Name, &gOphionVarGuid, attrs, n, buf);
}
