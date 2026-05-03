@echo off
REM Wrapper used by Task Scheduler to capture input_replayer.py logs.
REM Args: <jsonl_path> [extra args]
set REPLAY=C:\Users\RC3\replay
set PY=C:\Tools\python311\python.exe
"%PY%" "%REPLAY%\input_replayer.py" %* > "%REPLAY%\input_replayer.log" 2>&1
