param([int]$ProcessId_, [string]$Term)
$pid_ = $ProcessId_
$dir = "M:\pid\$pid_\search\bin"
# Reset search
[System.IO.File]::WriteAllBytes("$dir\reset.txt", [byte[]](49))
Start-Sleep -Milliseconds 300
# ASCII pattern as hex
$bytes = [System.Text.Encoding]::ASCII.GetBytes($Term)
$hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
[System.IO.File]::WriteAllBytes("$dir\search.txt", [System.Text.Encoding]::ASCII.GetBytes($hex))
Start-Sleep -Seconds 4
"--- ASCII '$Term' (hex=$hex) ---"
Get-Content "$dir\result.txt" -ErrorAction SilentlyContinue | Select-Object -First 30
# Reset and search UTF-16 LE
[System.IO.File]::WriteAllBytes("$dir\reset.txt", [byte[]](49))
Start-Sleep -Milliseconds 300
$bytes16 = [System.Text.Encoding]::Unicode.GetBytes($Term)
$hex16 = ($bytes16 | ForEach-Object { $_.ToString("x2") }) -join ""
[System.IO.File]::WriteAllBytes("$dir\search.txt", [System.Text.Encoding]::ASCII.GetBytes($hex16))
Start-Sleep -Seconds 4
"--- UTF16-LE '$Term' (hex=$hex16) ---"
Get-Content "$dir\result.txt" -ErrorAction SilentlyContinue | Select-Object -First 30
