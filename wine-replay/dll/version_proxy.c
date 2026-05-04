// version_proxy.c — DLL hijack proxy for version.dll.
//
// Why: Wine 10.0 (wow64 mode, the only supported config on Apple Silicon)
// crashes the game when injection runs via CreateRemoteThread+LoadLibraryA
// (injector.exe technique). The crash is in the loader/TLS thunk path, not
// in our DLL code — even an attach-only DLL with no work to do crashes the
// game shortly after injection. Documented Wine wow64 issue.
//
// Workaround: drop a file named "version.dll" into the game's app dir.
// Wine's loader searches the app dir BEFORE system32 for imported DLLs, so
// our copy gets loaded as DXRender's version.dll dependency at process
// startup — no remote-thread injection, no wow64 thunk corruption.
//
// DXRender imports exactly 3 functions from version.dll (per objdump -x):
//   VerQueryValueA, GetFileVersionInfoSizeA, GetFileVersionInfoA
// We forward all 3 to the real version.dll (loaded explicitly from
// system32 to bypass our own hijack), and also load dom_replay.dll from
// the app dir so its existing DllMain spins up the polling thread.
//
// Build: see dll/Makefile (version.dll target). Install: copy version.dll
// + dom_replay.dll into client/. Wine handles the rest at game launch.

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static HMODULE g_real_version;
static FARPROC g_VerQueryValueA;
static FARPROC g_GetFileVersionInfoSizeA;
static FARPROC g_GetFileVersionInfoA;

static void hp_log(const char* fmt, ...) {
    FILE* f = fopen("C:\\version_proxy.log", "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(hModule);

    hp_log("=== version_proxy attached, hModule=%p ===", hModule);

    // Load the REAL version.dll. LOAD_LIBRARY_SEARCH_SYSTEM32 forces lookup
    // in system32 only, so the loader doesn't return our own handle.
    g_real_version = LoadLibraryExA("version.dll", NULL,
        LOAD_LIBRARY_SEARCH_SYSTEM32);
    hp_log("LoadLibraryEx(version.dll, SEARCH_SYSTEM32) = %p (gle=%lu)",
        g_real_version, g_real_version ? 0 : GetLastError());
    if (g_real_version) {
        g_VerQueryValueA = GetProcAddress(g_real_version, "VerQueryValueA");
        g_GetFileVersionInfoSizeA =
            GetProcAddress(g_real_version, "GetFileVersionInfoSizeA");
        g_GetFileVersionInfoA =
            GetProcAddress(g_real_version, "GetFileVersionInfoA");
        hp_log("real fns: VerQueryValueA=%p GFVIS=%p GFVI=%p",
            g_VerQueryValueA, g_GetFileVersionInfoSizeA, g_GetFileVersionInfoA);
    }

    // Locate ourselves and load sibling dom_replay.dll. Its DllMain spawns
    // the poll thread (reads C:\dom_cmd.txt, dispatches into the game).
    char self_path[MAX_PATH] = {0};
    GetModuleFileNameA(hModule, self_path, MAX_PATH);
    char* slash = strrchr(self_path, '\\');
    if (slash) {
        *(slash + 1) = '\0';
        char dom_path[MAX_PATH];
        snprintf(dom_path, MAX_PATH, "%sdom_replay.dll", self_path);
        HMODULE dom = LoadLibraryA(dom_path);
        hp_log("LoadLibrary(%s) = %p (gle=%lu)",
            dom_path, dom, dom ? 0 : GetLastError());
    } else {
        hp_log("could not derive sibling dir from %s", self_path);
    }

    return TRUE;
}

__declspec(dllexport) BOOL WINAPI VerQueryValueA(
    LPCVOID block, LPCSTR sub_block, LPVOID* buffer, PUINT len)
{
    if (!g_VerQueryValueA) return FALSE;
    typedef BOOL (WINAPI *fn_t)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    return ((fn_t)g_VerQueryValueA)(block, sub_block, buffer, len);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(
    LPCSTR file, LPDWORD handle)
{
    if (!g_GetFileVersionInfoSizeA) return 0;
    typedef DWORD (WINAPI *fn_t)(LPCSTR, LPDWORD);
    return ((fn_t)g_GetFileVersionInfoSizeA)(file, handle);
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(
    LPCSTR file, DWORD handle, DWORD len, LPVOID data)
{
    if (!g_GetFileVersionInfoA) return FALSE;
    typedef BOOL (WINAPI *fn_t)(LPCSTR, DWORD, DWORD, LPVOID);
    return ((fn_t)g_GetFileVersionInfoA)(file, handle, len, data);
}
