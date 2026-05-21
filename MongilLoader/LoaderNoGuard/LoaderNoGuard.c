/*
 * LoaderNoGuard.c - MongilLoader without EfiGuard.
 *
 * Phase 7d-pg-test: boot path with PatchGuard ACTIVE. Verifies EPT cloak
 * survives PG's ntos.text SHA hash scan. If cloak fails, expect BSOD 0x109
 * CRITICAL_STRUCTURE_CORRUPTION within 1-10 minutes of cloak install.
 *
 * Differences from Loader.c:
 *   - Does NOT load EfiGuardDxe.efi → DSE active, PG active
 *   - Loads OphionDxe.efi only
 *   - Chains to bootmgfw.efi (Windows Boot Manager)
 *
 * Recovery: F12 boot menu → Windows Boot Manager (PG normal) or main
 * MongilLoader (with EfiGuard).
 *
 * SAFETY: do NOT run EfiDSEFix.exe in this session. PG would trip on
 * CI.dll patch separately from cloak test.
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

#define OPHION_DXE_PATH    L"\\EFI\\Ophion\\OphionDxe.efi"
#define WINDOWS_BOOTMGR    L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

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
        Print(L"[MongilLoaderNoGuard] LoadImage(%s) = %r\n", DriverPath, Status);
        return Status;
    }

    Status = gBS->StartImage(NewImageHandle, NULL, NULL);
    if (EFI_ERROR(Status)) {
        Print(L"[MongilLoaderNoGuard] StartImage(%s) = %r\n", DriverPath, Status);
        gBS->UnloadImage(NewImageHandle);
        return Status;
    }
    Print(L"[MongilLoaderNoGuard] loaded %s\n", DriverPath);
    return EFI_SUCCESS;
}

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
        Print(L"[MongilLoaderNoGuard] LoadImage(bootmgr) = %r\n", Status);
        return Status;
    }

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

    Print(L"\n[MongilLoaderNoGuard] phase 7d PG-test variant (Ophion only, no EfiGuard)\n");
    Print(L"[MongilLoaderNoGuard] PatchGuard ACTIVE this boot\n");

    Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                                  (VOID **)&LoadedImage);
    if (EFI_ERROR(Status)) {
        Print(L"[MongilLoaderNoGuard] HandleProtocol(LoadedImage) = %r\n", Status);
        return Status;
    }

    LoadAndStartDxeDriver(ImageHandle, SystemTable,
                          LoadedImage->DeviceHandle, OPHION_DXE_PATH);

    Print(L"[MongilLoaderNoGuard] chaining to Windows Boot Manager...\n");
    return ChainToBootmgr(ImageHandle, LoadedImage->DeviceHandle);
}
