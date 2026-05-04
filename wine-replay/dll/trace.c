/*
 * trace.dll - Inline-hook tracer for game client RE.
 *
 * Uses INT3 breakpoint + Vectored Exception Handler (VEH) pattern.
 * Much more reliable than JMP hooks for Delphi register calling convention.
 *
 * Hook targets (from Ghidra):
 *   0x005305FC - SVC packet dispatcher
 *   0x0052CD14 - World packet dispatcher
 *   0x004A773C - Connect to server
 *   0x004A7864 - Disconnect from server
 *
 * Log output: C:\trace.log (unbuffered, append mode)
 *
 * Compile: i686-w64-mingw32-gcc -shared -O2 -o trace.dll trace.c -lws2_32
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ---- Target addresses ---- */
#define ADDR_SVC_DISPATCH   0x005305FC
#define ADDR_WORLD_DISPATCH 0x0052CD14
#define ADDR_CONNECT        0x004A773C
#define ADDR_DISCONNECT     0x004A7864
#define ADDR_CONNMGR_PTR    0x0054D228
#define ADDR_STATE_TRANS    0x0053214C   /* FUN_0053214c - state machine transition */
#define ADDR_WORLD_ENTER    0x004E27A4   /* FUN_004e27a4 - world enter/load */
#define ADDR_WORLD_CONN     0x004E2874   /* FUN_004e2874 - world connect (disconnect SVC + connect world) */

#define NUM_HOOKS 7

/* ---- Hook state ---- */
typedef struct {
    DWORD addr;
    BYTE  orig_byte;
    const char *name;
} BreakpointHook;

static BreakpointHook g_bp[NUM_HOOKS];
static FILE *g_log = NULL;
static DWORD g_tick_base = 0;
static int g_initialized = 0;

/* ---- Logging ---- */

static void log_msg(const char *fmt, ...) {
    va_list ap;
    if (!g_log) return;
    fprintf(g_log, "[%6lu] ", GetTickCount() - g_tick_base);
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fprintf(g_log, "\n");
    fflush(g_log);
}

static void log_hex(const char *prefix, const unsigned char *buf, int len) {
    char hex[200];
    int pos = 0;
    int n = len > 32 ? 32 : len;
    for (int i = 0; i < n; i++) {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02x ", buf[i]);
    }
    if (len > 32) snprintf(hex + pos, sizeof(hex) - pos, "...");
    log_msg("%s len=%d [%s]", prefix, len, hex);
}

/* ---- Breakpoint management ---- */

static void set_bp(BreakpointHook *bp) {
    DWORD old;
    VirtualProtect((void *)bp->addr, 1, PAGE_EXECUTE_READWRITE, &old);
    bp->orig_byte = *(BYTE *)bp->addr;
    *(BYTE *)bp->addr = 0xCC;  /* INT3 */
    VirtualProtect((void *)bp->addr, 1, old, &old);
}

static void clear_bp(BreakpointHook *bp) {
    DWORD old;
    VirtualProtect((void *)bp->addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE *)bp->addr = bp->orig_byte;
    VirtualProtect((void *)bp->addr, 1, old, &old);
}

/* ---- VEH Handler ---- */

static LONG WINAPI VehHandler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD eip = ep->ContextRecord->Eip;

    for (int i = 0; i < NUM_HOOKS; i++) {
        if (eip != g_bp[i].addr)
            continue;

        DWORD eax = ep->ContextRecord->Eax;
        DWORD edx = ep->ContextRecord->Edx;
        DWORD ecx = ep->ContextRecord->Ecx;

        switch (i) {
        case 0: {
            /* SVC dispatcher FUN_005305fc(__fastcall):
             *   Ghidra __fastcall: ECX=param_1(ushort* pkt), EDX=param_2(connmgr)
             *   EAX = implicit self
             * Packet layout: [0-1]=size(u16), [2]=opcode, [3]=sub */
            unsigned char *pkt = (unsigned char *)ecx;  /* try ECX first */
            log_msg("SVC_DISPATCH eax=0x%08x edx=0x%08x ecx=0x%08x", eax, edx, ecx);
            /* Try reading packet from ECX (Ghidra __fastcall param_1) */
            if (ecx > 0x10000 && ecx < 0x7FFFFFFF) {
                unsigned short size = *(unsigned short *)pkt;
                if (size > 0 && size < 0x2000) {
                    unsigned char opcode = pkt[2];
                    unsigned char sub = pkt[3];
                    log_msg("  SVC_PKT(ecx) op=0x%02x sub=%d size=%d", opcode, sub, size);
                    int dump_len = size + 2;
                    if (dump_len > 64) dump_len = 64;
                    log_hex("  SVC_RAW(ecx)", pkt, dump_len);
                }
            }
            /* If this is D7 response (0xD7=215), log extra state */
            if (ecx > 0x10000 && ecx < 0x7FFFFFFF) {
                pkt = (unsigned char *)ecx;
                unsigned short sz = *(unsigned short *)pkt;
                if (sz > 0 && sz < 0x2000 && pkt[2] == 0xD7) {
                    /* Log PTR_DAT_0054d3f0 + 0x4d flag */
                    DWORD ptr_d3f0 = *(DWORD *)0x0054d3f0;
                    if (ptr_d3f0) {
                        DWORD obj = *(DWORD *)ptr_d3f0;
                        if (obj) {
                            log_msg("  D7: PTR_0054d3f0->obj=0x%08x [+0x4d]=0x%02x",
                                    obj, *(unsigned char *)(obj + 0x4d));
                        }
                    }
                    /* Log world ConnMgr state */
                    /* Try to find world ConnMgr - it should be at a known global */
                    DWORD dat_0059f708 = *(DWORD *)0x0059f708;
                    if (dat_0059f708) {
                        log_msg("  D7: DAT_0059f708=0x%08x [+0x4d]=0x%02x",
                                dat_0059f708, *(unsigned char *)(dat_0059f708 + 0x4d));
                    }
                }
            }
            break;
        }
        case 1: {
            /* World dispatcher FUN_0052cd14(__fastcall):
             *   ECX=param_1(pkt), EDX=param_2(connmgr)
             *   EAX=implicit self */
            log_msg("WORLD_DISPATCH eax=0x%08x edx=0x%08x ecx=0x%08x", eax, edx, ecx);
            if (ecx > 0x10000 && ecx < 0x7FFFFFFF) {
                unsigned char *pkt = (unsigned char *)ecx;
                unsigned short size = *(unsigned short *)pkt;
                if (size > 0 && size < 0x2000) {
                    unsigned char opcode = pkt[2];
                    log_msg("  WORLD_PKT op=0x%02x size=%d", opcode, size);
                    int dump_len = size + 2;
                    if (dump_len > 64) dump_len = 64;
                    log_hex("  WORLD_RAW", pkt, dump_len);
                }
            }
            break;
        }
        case 2: {
            /* Connect: EAX=self(ConnMgr) */
            unsigned char *mgr = (unsigned char *)eax;
            unsigned char has_addr = mgr[0x0c];
            log_msg("CONNECT mgr=0x%08x has_addr=%d sock=%d connected=%d",
                    eax, has_addr, *(int *)(mgr + 0x14), mgr[0x492c]);
            /* Dump the first 32 bytes of ConnMgr for RE */
            log_hex("  MGR_HEAD", mgr, 32);
            /* Also log bytes around the address area (0x0c..0x13) */
            log_hex("  MGR_ADDR", mgr + 0x08, 16);
            break;
        }
        case 3: {
            /* Disconnect: EAX=self(ConnMgr), EDX=param_1 */
            unsigned char *mgr = (unsigned char *)eax;
            log_msg("DISCONNECT mgr=0x%08x sock=%d connected=%d param1=0x%08x",
                    eax, *(int *)(mgr + 0x14), mgr[0x492c], edx);
            break;
        }
        case 4: {
            /* State transition FUN_0053214c(__fastcall):
             *   ECX=param_1(undefined4), EDX=param_2(uint)
             *   EAX=implicit self
             * switch(param_2 & 0x7f) -> case 0..6
             * But Ghidra __fastcall: ECX=1st, EDX=2nd
             * So param_2(the state) is in EDX */
            unsigned int state = edx & 0x7f;
            log_msg("STATE_TRANS state=%d eax=0x%08x edx=0x%08x ecx=0x%08x",
                    state, eax, edx, ecx);
            /* Check the 0x4d flag that controls world transition */
            DWORD dat_0059f708 = *(DWORD *)0x0059f708;
            if (dat_0059f708) {
                log_msg("  DAT_0059f708=0x%08x [+0x4d]=0x%02x",
                        dat_0059f708, *(unsigned char *)(dat_0059f708 + 0x4d));
            }
            DWORD dat_0054d034 = *(DWORD *)0x0054d034;
            log_msg("  DAT_0054d034=0x%02x (gate flag)", dat_0054d034 & 0xff);
            break;
        }
        case 5: {
            /* World enter FUN_004e27a4: EAX=self, EDX=param_1 */
            log_msg("WORLD_ENTER eax=0x%08x edx=0x%08x ecx=0x%08x", eax, edx, ecx);
            break;
        }
        case 6: {
            /* World connect FUN_004e2874: EAX=self (void params) */
            log_msg("WORLD_CONN eax=0x%08x edx=0x%08x ecx=0x%08x", eax, edx, ecx);
            /* Check SVC ConnMgr state */
            void **p = (void **)ADDR_CONNMGR_PTR;
            if (p && *p) {
                unsigned char *mgr = (unsigned char *)*(void **)*p;
                if (mgr) {
                    log_msg("  SVC_MGR sock=%d connected=%d",
                            *(int *)(mgr + 0x14), mgr[0x492c]);
                }
            }
            break;
        }
        }

        /* Restore original byte, set TF (single-step) to re-arm after one instruction */
        clear_bp(&g_bp[i]);
        ep->ContextRecord->EFlags |= 0x100;  /* TF = single step */
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* Single-step handler: re-arm the breakpoint after executing the original byte */
static LONG WINAPI VehSingleStep(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    /* Re-arm all cleared breakpoints */
    for (int i = 0; i < NUM_HOOKS; i++) {
        if (*(BYTE *)g_bp[i].addr != 0xCC) {
            set_bp(&g_bp[i]);
        }
    }

    /* Clear TF */
    ep->ContextRecord->EFlags &= ~0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* Combined VEH */
static LONG WINAPI CombinedVeh(EXCEPTION_POINTERS *ep) {
    if (!g_initialized)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        return VehHandler(ep);

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
        return VehSingleStep(ep);

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- Init ---- */

void CALLBACK TraceInitTimer(HWND hwnd, UINT msg, UINT_PTR id, DWORD tick) {
    KillTimer(hwnd, id);

    g_tick_base = GetTickCount();
    g_log = fopen("C:\\trace.log", "a");
    if (!g_log) return;
    setbuf(g_log, NULL);

    log_msg("========================================");
    log_msg("=== trace.dll initializing ===");

    /* Diagnostic: read ConnMgr */
    void **p = (void **)ADDR_CONNMGR_PTR;
    if (p && *p) {
        unsigned char *mgr = (unsigned char *)*(void **)*p;
        if (mgr) {
            log_msg("ConnMgr @ 0x%08x: sock=%d connected=%d",
                    (DWORD)mgr, *(int *)(mgr + 0x14), mgr[0x492c]);
            log_hex("  MGR[0x00]", mgr, 32);
            log_hex("  MGR[0x08]", mgr + 0x08, 16);
        } else {
            log_msg("ConnMgr inner ptr is NULL");
        }
    } else {
        log_msg("ConnMgr outer ptr is NULL");
    }

    /* Register VEH (first handler) */
    if (!AddVectoredExceptionHandler(1, CombinedVeh)) {
        log_msg("FAILED to register VEH!");
        return;
    }
    log_msg("VEH registered");

    /* Set up breakpoints */
    g_bp[0] = (BreakpointHook){ ADDR_SVC_DISPATCH, 0, "SVC_DISPATCH" };
    g_bp[1] = (BreakpointHook){ ADDR_WORLD_DISPATCH, 0, "WORLD_DISPATCH" };
    g_bp[2] = (BreakpointHook){ ADDR_CONNECT, 0, "CONNECT" };
    g_bp[3] = (BreakpointHook){ ADDR_DISCONNECT, 0, "DISCONNECT" };
    g_bp[4] = (BreakpointHook){ ADDR_STATE_TRANS, 0, "STATE_TRANS" };
    g_bp[5] = (BreakpointHook){ ADDR_WORLD_ENTER, 0, "WORLD_ENTER" };
    g_bp[6] = (BreakpointHook){ ADDR_WORLD_CONN, 0, "WORLD_CONN" };

    for (int i = 0; i < NUM_HOOKS; i++) {
        set_bp(&g_bp[i]);
        log_msg("BP set: %s @ 0x%08x (orig=0x%02x)",
                g_bp[i].name, g_bp[i].addr, g_bp[i].orig_byte);
    }

    g_initialized = 1;
    log_msg("=== trace.dll ready (INT3/VEH mode) ===");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        HWND hwnd = FindWindowA("TMainForm", "Secret of the Solstice");
        if (hwnd) {
            SetTimer(hwnd, 11111, 100, TraceInitTimer);
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_initialized) {
            /* Remove breakpoints */
            for (int i = 0; i < NUM_HOOKS; i++) {
                if (*(BYTE *)g_bp[i].addr == 0xCC) {
                    clear_bp(&g_bp[i]);
                }
            }
            g_initialized = 0;
        }
        if (g_log) {
            log_msg("=== trace.dll unloading ===");
            fclose(g_log);
            g_log = NULL;
        }
    }
    return TRUE;
}
