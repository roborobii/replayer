# Run from an interactive desktop session on the host (NOT via SSH).
# Captures vmconnect input via WH_MOUSE_LL/WH_KEYBOARD_LL and writes
# normalized JSONL events to input_events.jsonl in this folder.
$ErrorActionPreference = "Stop"
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent  = Join-Path $here "host_agent.py"
$outlog = Join-Path $here "input_events.jsonl"
Write-Host "[start] agent: $agent"
Write-Host "[start] writing JSONL to: $outlog"
Write-Host "[start] bring vmconnect (Elf VM) to foreground; clicks will be captured."
Write-Host "[start] Ctrl+C to stop."
python $agent --out $outlog
