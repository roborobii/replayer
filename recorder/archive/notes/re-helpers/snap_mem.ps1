param([int]$ProcessId_, [string]$Label)
$vmem = "M:\pid\${ProcessId_}\memory.vmem"
$base = 0x06000000
$size = 0x04000000
$out = "C:\Users\RC\sessions\snap_${Label}.bin"
$f = [System.IO.File]::OpenRead($vmem)
try {
  $f.Seek($base, 'Begin') | Out-Null
  $buf = New-Object byte[] $size
  $read = $f.Read($buf, 0, $size)
  [System.IO.File]::WriteAllBytes($out, $buf[0..($read-1)])
  Write-Host "snap_${Label}: $read bytes from VA 0x$($base.ToString('x')) -> $out"
} finally {
  $f.Close()
}
