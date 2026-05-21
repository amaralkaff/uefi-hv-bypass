#
# add_safe_mode_nvram.ps1 - add fallback "EfiGuard Safe Mode" NVRAM boot entry
#
# Creates a UEFI boot entry pointing to \EFI\EfiGuard\Loader.original.efi so
# you can recover if MongilLoader ever bricks boot. Press F12 at POST to
# pick the fallback entry.
#
# RUN AS ADMIN.
#
param(
    [string]$Label = "EfiGuard Safe Mode",
    [string]$LoaderPath = "\EFI\EfiGuard\Loader.original.efi"
)

$ErrorActionPreference = 'Stop'

# Use bcdedit to create a Windows-side firmware boot entry pointing to the
# original EfiGuard loader. Simpler than raw efibootmgr (Windows ships bcdedit).

Write-Host "Adding NVRAM boot entry: '$Label' -> '$LoaderPath'"

# Step 1: create a copy of the bootmgr entry with the new path as its 'path'
$out = & bcdedit /copy '{bootmgr}' /d "$Label"
if ($LASTEXITCODE -ne 0) { throw "bcdedit /copy failed" }

# Extract the new GUID from output
$newGuid = ($out | Select-String -Pattern "{[0-9A-Fa-f-]+}").Matches.Value | Select-Object -First 1
if (-not $newGuid) { throw "could not parse new bcdedit GUID from '$out'" }
Write-Host "new entry GUID: $newGuid"

# Step 2: set its path + device
& bcdedit /set "$newGuid" path "$LoaderPath"
& bcdedit /set "$newGuid" description "$Label"

# Step 3: add to firmware bootorder (after primary MongilLoader entry)
& bcdedit /set '{fwbootmgr}' displayorder "$newGuid" /addlast

Write-Host ""
Write-Host "----- VERIFY -----"
Write-Host "bcdedit /enum firmware"
Write-Host ""
Write-Host "Expected displayorder:"
Write-Host "  1) {311ec363-...} MongilLoader (or EfiGuard's existing GUID, since we kept the file path)"
Write-Host "  2) $newGuid $Label"
Write-Host "  3) {bootmgr} Windows Boot Manager"
Write-Host ""
Write-Host "Reboot, press F12, confirm both entries appear."
