CC = i686-w64-mingw32-gcc
CFLAGS = -Wall -O2
LDFLAGS_DLL = -shared
LDLIBS = -lws2_32

DLLS = connect.dll charctl.dll probe.dll chatcmd.dll trace.dll dom_replay.dll dom_hook.dll version.dll
EXES = injector.exe

all: $(DLLS) $(EXES)

connect.dll: connect.c
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -o $@ $< $(LDLIBS)

charctl.dll: charctl.c
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -o $@ $< $(LDLIBS)

probe.dll: probe.c
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -o $@ $< $(LDLIBS)

chatcmd.dll: chatcmd.c
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -o $@ $< $(LDLIBS)

trace.dll: trace.c
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -o $@ $< $(LDLIBS)

dom_replay.dll: dom_replay.c
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -o $@ $< $(LDLIBS)

dom_hook.dll: dom_hook.c
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -o $@ $< $(LDLIBS)

# version.dll — DLL-hijack proxy. Forwards version.dll exports to system32
# and side-loads dom_replay.dll. Drops into client/ so wine loads it
# automatically at game start (avoids CreateRemoteThread + wow64 crash).
version.dll: version_proxy.c version_proxy.def
	$(CC) $(CFLAGS) $(LDFLAGS_DLL) -Wl,--kill-at -o $@ version_proxy.c version_proxy.def $(LDLIBS)

injector.exe: injector.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(DLLS) $(EXES)

.PHONY: all clean
