/*
 * Loader.c - Combined MongilLoader EFI entry point
 *
 * Replaces vanilla EfiGuard Loader.efi. Load order:
 *   1. Boot firmware -> MongilLoader (via NVRAM entry, first in displayorder)
 *   2. MongilLoader loads EfiGuardDxe.efi from .\EFI\EfiGuard\EfiGuardDxe.efi
 *   3. MongilLoader loads OphionDxe.efi from .\EFI\Ophion\OphionDxe.efi
 *   4. Both DXE drivers register ExitBootServices notifications
 *   5. MongilLoader chains to bootmgfw.efi (Windows Boot Manager)
 *   6. winload.efi runs -> EfiGuardDxe patches DSE/PG -> OphionDxe arms VMM
 *      via ExitBootServices callback right before boot services close
 *   7. Windows boots inside Ophion VM (BSP only in phase 2; APs follow in phase 3)
 *
 * Recovery: if MongilLoader bricks boot, F12 boot menu shows "EfiGuard Safe
 * Mode" entry pointing to backed-up vanilla Loader.original.efi.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

#include "Loader.h"

#define EFIGUARD_DXE_PATH  L"\\EFI\\EfiGuard\\EfiGuardDxe.efi"
#define OPHION_DXE_PATH    L"\\EFI\\Ophion\\OphionDxe.efi"
//
// Path B integration with NOVA-style spoofer: spoofer renames original
// bootmgfw.efi to boot.efi during install (see spoof.bat). startup.nsh
// then chains directly to boot.efi after loading mp.efi spoof worker.
// We chain to boot.efi (the renamed bootmgfw) instead of original path.
//
#define WINDOWS_BOOTMGR    L"\\EFI\\Microsoft\\Boot\\boot.efi"

//
// LoadAndStartDxeDriver - load + start a DXE driver from current ESP volume
//
// Phase-1 stub: just attempts to load both DXE drivers; if either is missing,
// continues to chain Windows. This makes the empty MongilLoader equivalent
// to vanilla EfiGuard's loader.
//
static EFI_STATUS
LoadAndStartDxeDriver(
    IN EFI_HANDLE          ImageHandle,
    IN EFI_SYSTEM_TABLE   *SystemTable,
    IN EFI_HANDLE          DeviceHandle,
    IN CHAR16             *DriverPath
    )
{
    EFI_STATUS Status;
    EFI_DEVICE_PATH_PROTOCOL *DevicePath = NULL;
    EFI_HANDLE NewImageHandle = NULL;

    DevicePath = FileDevicePath(DeviceHandle, DriverPath);
    if (DevicePath == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    Status = gBS->LoadImage(FALSE, ImageHandle, DevicePath, NULL, 0, &NewImageHandle);
    FreePool(DevicePath);
    if (EFI_ERROR(Status)) {
        Print(L"[MongilLoader] LoadImage(%s) = %r\n", DriverPath, Status);
        return Status;
    }

    Status = gBS->StartImage(NewImageHandle, NULL, NULL);
    if (EFI_ERROR(Status)) {
        Print(L"[MongilLoader] StartImage(%s) = %r\n", DriverPath, Status);
        gBS->UnloadImage(NewImageHandle);
        return Status;
    }
    Print(L"[MongilLoader] loaded %s\n", DriverPath);
    return EFI_SUCCESS;
}

//
// ChainToBootmgr - load Windows Boot Manager and transfer control
//
static EFI_STATUS
ChainToBootmgr(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_HANDLE        DeviceHandle
    )
{
    EFI_STATUS Status;
    EFI_DEVICE_PATH_PROTOCOL *DevicePath;
    EFI_HANDLE BootmgrHandle = NULL;

    DevicePath = FileDevicePath(DeviceHandle, WINDOWS_BOOTMGR);
    if (DevicePath == NULL) return EFI_OUT_OF_RESOURCES;

    Status = gBS->LoadImage(FALSE, ImageHandle, DevicePath, NULL, 0, &BootmgrHandle);
    FreePool(DevicePath);
    if (EFI_ERROR(Status)) {
        Print(L"[MongilLoader] LoadImage(bootmgr) = %r\n", Status);
        return Status;
    }

    // StartImage never returns on success — control passes to Windows.
    return gBS->StartImage(BootmgrHandle, NULL, NULL);
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS Status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;

    Print(L"\n[MongilLoader] v%u.%u.%u (combined EfiGuard + Ophion)\n",
          MONGIL_LOADER_VERSION_MAJOR,
          MONGIL_LOADER_VERSION_MINOR,
          MONGIL_LOADER_VERSION_PATCH);

    // Resolve our own loaded-image device handle (used to locate
    // EfiGuardDxe.efi + OphionDxe.efi on same ESP).
    Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                                  (VOID **)&LoadedImage);
    if (EFI_ERROR(Status)) {
        Print(L"[MongilLoader] HandleProtocol(LoadedImage) = %r\n", Status);
        return Status;
    }

    // Phase 1: try to load both DXE drivers, but fall through to Windows
    // even if Ophion DXE is missing (allows partial install / safe mode).
    LoadAndStartDxeDriver(ImageHandle, SystemTable,
                          LoadedImage->DeviceHandle, EFIGUARD_DXE_PATH);
    LoadAndStartDxeDriver(ImageHandle, SystemTable,
                          LoadedImage->DeviceHandle, OPHION_DXE_PATH);

    Print(L"[MongilLoader] chaining to Windows Boot Manager...\n");
    return ChainToBootmgr(ImageHandle, LoadedImage->DeviceHandle);
}
