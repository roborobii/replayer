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

# Pin the synthetic display adapter to 1440x900. Set-VMVideo only takes effect
# while the VM is off, and only governs the basic-session ("Microsoft Hyper-V
# Video") adapter. In enhanced session VMConnect uses the Remote Display
# Adapter and the resolution is driven by the VMConnect window instead, which
# overrides this — so enhanced session is disabled host-wide below.
Write-Host "Setting $vmName resolution to 1440x900..."
Set-VMVideo -VMName $vmName -HorizontalResolution 1440 -VerticalResolution 900 -ResolutionType Single

# Force basic session so Set-VMVideo's resolution actually sticks after login.
# Trade-off: no clipboard/USB/drive redirection from VMConnect.
Write-Host "Disabling enhanced session mode (host-wide)..."
Set-VMHost -EnableEnhancedSessionMode $false

Write-Host "Restarting vmms..."
Restart-Service vmms -Force
Start-Sleep -Seconds 5

Write-Host "Closing any existing VMConnect sessions..."
Get-Process vmconnect -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

Write-Host "Starting $vmName..."
Start-VM -Name $vmName
Start-Process "vmconnect.exe" -ArgumentList "localhost",$vmName

$vm = Get-VM -Name $vmName
Write-Host "$vmName is $($vm.State)."

Write-Host "Waiting for guest OS to boot (heartbeat OK)..."
$bootDeadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $bootDeadline) {
    $hb = (Get-VMIntegrationService -VMName $vmName -Name Heartbeat -ErrorAction SilentlyContinue).PrimaryStatusDescription
    if ($hb -eq "OK") { break }
    Start-Sleep -Seconds 2
}
if ($hb -ne "OK") {
    Write-Warning "Guest heartbeat not OK after 180s (status: $hb). Proceeding anyway."
} else {
    Write-Host "Guest heartbeat OK."
    Start-Sleep -Seconds 5
}

Write-Host "Starting MemProcFS (mount M:\)..."
$logPath = "C:\Tools\MemProcFS\memprocfs_session.log"
$attempt = 0
$mounted = $false
while (-not $mounted -and $attempt -lt 5) {
    $attempt++
    Write-Host "  attempt $attempt..."
    $proc = Start-Process -FilePath "C:\Tools\MemProcFS\MemProcFS.exe" `
        -ArgumentList "-device","hvmm://id=0","-mount","M" `
        -RedirectStandardOutput $logPath `
        -RedirectStandardError "$logPath.err" `
        -WindowStyle Hidden -PassThru

    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not (Test-Path "M:\pid")) {
        if ($proc.HasExited) { break }
        Start-Sleep -Milliseconds 500
    }
    if (Test-Path "M:\pid") {
        $mounted = $true
        break
    }
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 10
}

if ($mounted) {
    Write-Host "MemProcFS mounted at M:\."
} else {
    Write-Warning "MemProcFS failed to mount after $attempt attempts. Check $logPath"
    if (Test-Path $logPath) { Get-Content $logPath -Tail 20 }
}
