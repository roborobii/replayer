param([int]$ProcessId_, [string]$VaHex, [int]$Bytes = 128)
$va = [Convert]::ToInt64($VaHex.Substring(2), 16)
$start = [Math]::Max(0, $va - 16)
$f = [System.IO.File]::OpenRead("M:\pid\$ProcessId_\memory.vmem")
try {
  $f.Seek($start, 'Begin') | Out-Null
  $buf = New-Object byte[] $Bytes
  $f.Read($buf, 0, $Bytes) | Out-Null
} finally { $f.Close() }
$hex = ($buf | ForEach-Object { $_.ToString("x2") }) -join " "
$asc = ($buf | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { "." } }) -join ""
"VA $VaHex (-16 ctx, $Bytes B):"
"hex: $hex"
"asc: $asc"
