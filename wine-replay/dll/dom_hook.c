#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/*
 * dom_hook.dll — JMP-hook the OnClick handler in TDncCharSelectShow's
 * child buttons. When user clicks a slot/button on offline, the hook fires
 * with EAX=child_self (Delphi register calling convention for TNotifyEvent).
 * We log child, parent (=*(child+0x84)), VMT pointers, and a parent hexdump.
 *
 * Diagnostic mode: hook RETs without running the real handler — so the click
 * is dropped, BUT we capture every piece of runtime state we need to:
 *   1) confirm the actual obj[0] VMT-pointer convention
 *   2) confirm child+0x84 -> parent layout
 *   3) see the live widget bytes (slot field, mode byte, child ptrs, etc.)
 *
 * Two handlers per the ctor decomp:
 *   FUN_000F1484  — buttons at parent+0x60 and +0x68 (slots A)
 *   LAB_000F164C  — buttons at parent+0x6C and +0x64 (slots B)
 */

/* Runtime VAs (= module base + RVA, since DXRender loads at preferred 0x10000) */
#define VA_HANDLER_A  0x000F1484
#define VA_HANDLER_B  0x000F164C

static FILE* logf = NULL;
static volatile int capture_count = 0;

static void logmsg(const char* fmt, ...) {
    if (!logf) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(logf, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    vfprintf(logf, fmt, ap);
    va_end(ap);
    fputc('\n', logf);
    fflush(logf);
}

static void hexdump_at(const char* label, void* base, int n) {
    BYTE* b = (BYTE*)base;
    for (int i = 0; i < n; i += 16) {
        fprintf(logf, "  %s +%03x:", label, i);
        for (int j = 0; j < 16; j++) {
            if (i + j < n) fprintf(logf, " %02x", b[i+j]);
        }
        fprintf(logf, "\n");
    }
    fflush(logf);
}

/* Called from the asm trampolines.  child_self comes through as the first
 * stack arg (we pushed EAX from the trampoline). */
void __cdecl on_handler_fired(const char* tag, uint32_t child_self) {
    capture_count++;
    fprintf(logf, "\n========================================================\n");
    logmsg("[#%d] %s fired", capture_count, tag);
    logmsg("  child_self (EAX at entry) = 0x%08x", child_self);
    if (child_self == 0 || (child_self & 3)) {
        logmsg("  child_self looks invalid; aborting deref");
        return;
    }
    uint32_t child_vmt = *(uint32_t*)child_self;
    uint32_t parent_self = *(uint32_t*)(child_self + 0x84);
    logmsg("  *(child+0x00) = child_vmt = 0x%08x", child_vmt);
    logmsg("  *(child+0x84) = parent_self = 0x%08x", parent_self);
    if (parent_self) {
        uint32_t parent_vmt = *(uint32_t*)parent_self;
        logmsg("  *(parent+0x00) = parent_vmt = 0x%08x", parent_vmt);
        hexdump_at("parent", (void*)parent_self, 0x100);
    }
    hexdump_at("child", (void*)child_self, 0x90);
}

/* Naked trampolines.  Delphi TNotifyEvent passes Sender in EAX (register
 * calling convention).  We save EAX before any clobber, push it as arg to
 * the C logger, then RET (= drop the click; we're in diagnostic mode). */
__attribute__((naked)) void hook_a(void) {
    __asm__ __volatile__(
        "pushl %%eax\n\t"             /* arg2: child_self */
        "pushl $tag_a\n\t"            /* arg1: tag str */
        "call _on_handler_fired\n\t"
        "addl $8, %%esp\n\t"
        "xorl %%eax, %%eax\n\t"       /* return value */
        "ret\n\t"
        "tag_a: .asciz \"FUN_000F1484\"\n\t"
        : : :);
}

__attribute__((naked)) void hook_b(void) {
    __asm__ __volatile__(
        "pushl %%eax\n\t"
        "pushl $tag_b\n\t"
        "call _on_handler_fired\n\t"
        "addl $8, %%esp\n\t"
        "xorl %%eax, %%eax\n\t"
        "ret\n\t"
        "tag_b: .asciz \"LAB_000F164C\"\n\t"
        : : :);
}

static int install_jmp(uintptr_t target_va, void* hook_fn) {
    void* target = (void*)target_va;
    DWORD old;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old)) {
        logmsg("install_jmp 0x%08x: VirtualProtect failed err=%lu",
            (unsigned)target_va, GetLastError());
        return -1;
    }
    BYTE* p = (BYTE*)target;
    p[0] = 0xE9;
    int32_t rel = (int32_t)((uintptr_t)hook_fn - target_va - 5);
    *(int32_t*)(p + 1) = rel;
    DWORD dummy;
    VirtualProtect(target, 5, old, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    logmsg("install_jmp: 0x%08x -> 0x%08x (rel=0x%08x)",
        (unsigned)target_va, (unsigned)(uintptr_t)hook_fn, rel);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(hModule);
    logf = fopen("C:\\dom_hook.log", "a");
    if (!logf) return TRUE;
    HMODULE base = GetModuleHandleA(NULL);
    logmsg("=== dom_hook.dll attached === base=%p", base);
    install_jmp(VA_HANDLER_A, (void*)hook_a);
    install_jmp(VA_HANDLER_B, (void*)hook_b);
    logmsg("hooks installed; waiting for clicks");
    return TRUE;
}
