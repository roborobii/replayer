#Requires -RunAsAdministrator

$vmName = "Elf"

$memprocfs = Get-Process -Name "MemProcFS" -ErrorAction SilentlyContinue
if ($memprocfs) {
    Write-Host "Stopping MemProcFS (PID $($memprocfs.Id))..."
    Stop-Process -Id $memprocfs.Id -Force
    Start-Sleep -Seconds 2
}

$vm = Get-VM -Name $vmName -ErrorAction Stop

if ($vm.State -eq "Running") {
    Write-Host "Stopping $vmName..."
    Stop-VM -Name $vmName -Force
    Start-Sleep -Seconds 3
}

Write-Host "Closing any existing VMConnect sessions..."
Get-Process vmconnect -ErrorAction SilentlyContinue | Stop-Process -Force

$vm = Get-VM -Name $vmName
Write-Host "$vmName is $($vm.State)."
