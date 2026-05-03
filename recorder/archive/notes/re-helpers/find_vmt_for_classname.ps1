param([int]$ProcessId_, [string]$ClassNameHexAddr)
$pid_ = $ProcessId_
$dir = "M:\pid\$pid_\search\bin"
# Build LE u32 for the class-name address (length byte address = arg - 1, but caller already knows; pass exact addr)
$addr = [Convert]::ToInt64($ClassNameHexAddr.Substring(2), 16)
$b0 = ($addr -band 0xFF).ToString("x2")
$b1 = (($addr -shr 8) -band 0xFF).ToString("x2")
$b2 = (($addr -shr 16) -band 0xFF).ToString("x2")
$b3 = (($addr -shr 24) -band 0xFF).ToString("x2")
$hex = "$b0$b1$b2$b3"
[System.IO.File]::WriteAllBytes("$dir\reset.txt", [byte[]](49))
Start-Sleep -Milliseconds 300
[System.IO.File]::WriteAllBytes("$dir\search.txt", [System.Text.Encoding]::ASCII.GetBytes($hex))
Start-Sleep -Seconds 4
"--- pointers to $ClassNameHexAddr (LE hex=$hex) ---"
Get-Content "$dir\result.txt" -ErrorAction SilentlyContinue | Select-Object -First 30
