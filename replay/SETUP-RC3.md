# RC3 one-time setup

Embedded Python distro lives at `replay/_vendor/python-3.11.9-embed-amd64.zip`
on the Mac (already GPG-verified).

## Steps

1. SCP the zip to RC3:
   ```
   scp /Users/robin/dev/github.com/roborobii/replayer/replay/_vendor/python-3.11.9-embed-amd64.zip RC3@192.168.12.188:C:/Tools/
   ```

2. On RC3, extract to `C:\Tools\python311`:
   ```
   Expand-Archive C:\Tools\python-3.11.9-embed-amd64.zip -DestinationPath C:\Tools\python311
   ```

3. Edit `C:\Tools\python311\python311._pth` and uncomment the `import site`
   line so embedded Python can resolve relative imports if needed.

4. Verify:
   ```
   C:\Tools\python311\python.exe --version
   ```

5. SCP `replay/play-rc3.ps1` and `replay/input_replayer.py` to
   `C:\Users\RC3\replay\` (or run `play-rc3.ps1` from a checked-out
   copy of this repo on RC3).

No pip install needed: input_replayer.py uses stdlib + ctypes only.

## Per-session

```
powershell -File C:\Users\RC3\replay\play-rc3.ps1 -RecordingId smoke5
```
