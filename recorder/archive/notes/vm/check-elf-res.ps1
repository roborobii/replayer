#Requires -RunAsAdministrator

$vmName = "Elf"
$cred = Get-Credential -Message "Enter guest credentials for $vmName (e.g. $vmName\Administrator)"

Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    Get-CimInstance Win32_VideoController |
        Select-Object Name, CurrentHorizontalResolution, CurrentVerticalResolution |
        Format-Table -AutoSize
}

Read-Host "Press Enter to exit"
