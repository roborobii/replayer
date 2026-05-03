param([int]$ProcessId_, [string]$TargetVaHex)
$pid_ = $ProcessId_
$dir = "M:\pid\$pid_\search\bin"
$va = [Convert]::ToInt64($TargetVaHex.Substring(2), 16)
# Build LE u32 pattern
$b0 = ($va -band 0xFF).ToString("x2")
$b1 = (($va -shr 8) -band 0xFF).ToString("x2")
$b2 = (($va -shr 16) -band 0xFF).ToString("x2")
$b3 = (($va -shr 24) -band 0xFF).ToString("x2")
$hex = "$b0$b1$b2$b3"
[System.IO.File]::WriteAllBytes("$dir\reset.txt", [byte[]](49))
Start-Sleep -Milliseconds 300
[System.IO.File]::WriteAllBytes("$dir\search.txt", [System.Text.Encoding]::ASCII.GetBytes($hex))
Start-Sleep -Seconds 4
"--- pointers to $TargetVaHex (LE hex=$hex) ---"
Get-Content "$dir\result.txt" -ErrorAction SilentlyContinue | Select-Object -First 30
