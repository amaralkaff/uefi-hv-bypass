#requires -RunAsAdministrator
# unload_ophion.ps1 - Stop Ophion, keep service entry registered.

$state = (sc.exe query Ophion 2>&1 | Select-String 'STATE') -join ''
if ($state -match 'STOPPED') {
    Write-Host "[i] Ophion already STOPPED."
    exit 0
}

sc.exe stop Ophion | Out-Null
Start-Sleep -Milliseconds 500
$state = (sc.exe query Ophion 2>&1 | Select-String 'STATE') -join ''
Write-Host "[*] Ophion: $state"
