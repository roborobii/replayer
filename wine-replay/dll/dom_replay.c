#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* Forward declarations (mingw doesn't support __try/__except; we use
 * VirtualQuery-based guards instead). */
static void logmsg(const char* fmt, ...);
static void* va2rt(uintptr_t va);

/*
 * dom_replay.dll — fire DOM events on offline DXRender.exe to mirror VM clicks.
 *
 * Polls C:\dom_cmd.txt every 200ms. Commands (one per line, latest wins):
 *   probe                  — dump state to C:\dom_replay.log
 *   pick_slot N            — write slot index N (0..n) into widget+0x7d
 *   start_game             — synthesize "Start Game" click on TDncCharSelectShow
 *
 * Static-analysis facts (from /Users/robin/proj/new-decompiled/decomp/ghidra/):
 *   PE ImageBase = 0x10000.
 *   TDncCharSelectShow class-info VA = 0x000EE694.
 *   Active widget instance global VA = 0x00206784 (PTR).
 *   Active char-index global VA = 0x001C1678 (BYTE PTR).
 *   Cursor-Y baseline VA = 0x00206788 (WORD).
 *   Mouse-handler VA = 0x000EF6D8 — sig (self, flags, packed_xy, btn).
 *   Child dispatcher VA = 0x000F1244 — bypass scroll code, route packed msg to child.
 *   InitCursorAndDispatch VA = 0x000FE808 — seeds cursor, re-enters big switch.
 *   Children laid out at self+0x60, +0x64, +0x68, +0x6C, +0x70, +0x74 (button strip).
 *   Per Ghidra writeup, +0x70 is the centred Start-Game button child.
 *
 * To convert these VAs to runtime addresses:
 *   runtime = GetModuleHandle(NULL) + (VA - 0x10000)
 *   (Delphi PEs are no-reloc, so the module always loads at ImageBase 0x10000.)
 */

#define IMG_BASE        0x10000

#define VA_ACTIVE_WIDGET    0x00206784  /* PTR to live TDncCharSelectShow */
#define VA_ACTIVE_CHAR_IDX  0x001C1678  /* PTR to BYTE; *p = active slot N */
#define VA_CURSOR_Y         0x00206788  /* WORD; baseline Y for hit-test */
#define VA_FN_MOUSE         0x000EF6D8  /* mouse handler */
#define VA_FN_CHILD_DISP    0x000F1244  /* per-child dispatcher (skip scroll) */
#define VA_FN_INIT_DISP     0x000FE808  /* InitCursorAndDispatch */

#define OFF_SLOT_BYTE       0x7D        /* widget+0x7d = active slot byte */
#define OFF_BTN_CHILD       0x70        /* widget+0x70 = centred button child */

typedef int (__cdecl *fn_mouse_t)(void* self, int flags, int xy, int btn);
typedef int (__cdecl *fn_child_disp_t)(void* self, int xy_packed);
typedef int (__cdecl *fn_init_disp_t)(void* self);

static FILE* logf = NULL;
static HANDLE poll_thread = NULL;
static volatile int stop_flag = 0;

/* ---------------------------------------------------------------------------
 * Generic click-injection support (WS-D)
 *
 * HandleMouse VMT slot = +0x3C from each form's class_info_va.
 * To resolve at runtime: handler = *(uint32_t*)(class_info_va + 0x3C).
 * Calling convention: Delphi register fastcall —
 *   EAX=Self, EDX=flags, ECX=xy_packed, [esp+4]=btn ; callee `ret 4`.
 * Coordinate space: form-local pixels, xy_packed = (X<<16) | (Y & 0xFFFF).
 * Click sequence: DOWN (flags=0x08) then UP (flags=0x10), btn=1 for LMB.
 *
 * Form vmt → class_info_va = vmt - 0x2C (Delphi-7 vmtClassName=-0x2C).
 * Wait — vmt itself IS class_info_va here (per forms_catalog.json convention:
 * vmt_base = class_info_va + 0x2C means the catalog's "vmt_base" field equals
 * the address pointed to by live instances, i.e. the value of *(instance+0x00).
 * Live instances point at class_info_va + 0x2C. So:
 *   instance_vmt   = class_info_va + 0x2C   (value of *instance)
 *   class_info_va  = instance_vmt - 0x2C
 *   handler_va     = *(class_info_va + 0x3C) = *(instance_vmt + 0x10)
 *
 * The catalog VAs below are class_info_va values.
 * --------------------------------------------------------------------------- */

/* Form VMT lookup table (class_info_va values) — used to terminate the
 * owner walk when we reach the form, and to find live form instances. */
typedef struct {
    uint32_t class_info_va;  /* matches *(instance+0x00) - 0x2C */
    uint32_t instance_vmt;   /* matches *(instance+0x00) directly */
    const char* name;
} form_vmt_t;

static const form_vmt_t g_form_vmts[] = {
    /* Per WS-D inputs, "form vmts" are the values stored at *instance:
     * TDncServerSelectForm 0x001524B4, TDncCharSelectShow 0x000EE6C0,
     * TDncCharCreateForm 0x00149A00, TDncGameMainMenu 0x000F3AE8,
     * TMainForm 0x0011A470. class_info_va = vmt - 0x2C. */
    { 0x00152488, 0x001524B4, "TDncServerSelectForm" },
    { 0x000EE694, 0x000EE6C0, "TDncCharSelectShow"   },
    { 0x001499D4, 0x00149A00, "TDncCharCreateForm"   },
    { 0x000F3ABC, 0x000F3AE8, "TDncGameMainMenu"     },
    { 0x0011A444, 0x0011A470, "TMainForm"            },
};
#define N_FORM_VMTS (sizeof(g_form_vmts)/sizeof(g_form_vmts[0]))

/* Check if [addr, addr+len) is readable using VirtualQuery. */
static int mem_readable(uintptr_t addr, size_t len) {
    if (addr < 0x10000) return 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & PAGE_NOACCESS) return 0;
    if (mbi.Protect & PAGE_GUARD) return 0;
    /* Region must cover the full range. */
    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    if (addr + len > region_end) return 0;
    return 1;
}

/* Try to read a u32 at addr; return 0 on failure (and set *ok=0). */
static uint32_t safe_read_u32(uintptr_t addr, int* ok) {
    if (ok) *ok = 0;
    if (!mem_readable(addr, 4)) return 0;
    if (ok) *ok = 1;
    return *(uint32_t*)addr;
}

static int safe_read_rect_i16(uintptr_t addr, int16_t out[4]) {
    if (!mem_readable(addr + 0x10, 8)) return 0;
    out[0] = *(int16_t*)(addr + 0x10);
    out[1] = *(int16_t*)(addr + 0x12);
    out[2] = *(int16_t*)(addr + 0x14);
    out[3] = *(int16_t*)(addr + 0x16);
    return 1;
}

/* Look up form-vmt entry by either class_info_va or instance_vmt match. */
static const form_vmt_t* lookup_form_vmt(uint32_t v) {
    for (size_t i = 0; i < N_FORM_VMTS; i++) {
        if (g_form_vmts[i].class_info_va == v ||
            g_form_vmts[i].instance_vmt == v) {
            return &g_form_vmts[i];
        }
    }
    return NULL;
}

/* Naked trampoline that synthesizes the Delphi register call.
 * We stash args in globals (single-threaded poll loop, so no race). */
static volatile uint32_t g_call_self;
static volatile uint32_t g_call_flags;
static volatile uint32_t g_call_xy;
static volatile uint32_t g_call_btn;
static void* volatile  g_call_handler;

__attribute__((naked)) static void call_handle_mouse(void) {
    __asm__ __volatile__(
        "pushl %%ebx\n\t"
        "pushl %%esi\n\t"
        "pushl %%edi\n\t"
        "pushl %%ebp\n\t"
        "movl _g_call_btn, %%eax\n\t"
        "pushl %%eax\n\t"                 /* [esp+4] = btn */
        "movl _g_call_self, %%eax\n\t"    /* EAX = Self */
        "movl _g_call_flags, %%edx\n\t"   /* EDX = flags */
        "movl _g_call_xy, %%ecx\n\t"      /* ECX = xy_packed */
        "call *_g_call_handler\n\t"       /* callee does ret 4 */
        "popl %%ebp\n\t"
        "popl %%edi\n\t"
        "popl %%esi\n\t"
        "popl %%ebx\n\t"
        "ret\n\t"
        : : : );
}

/* Walk owner chain from `start_addr` upward. On each step, accumulate the
 * ancestor's local left/top into (*dx, *dy). Stop when the ancestor's vmt
 * matches a form vmt; return the form's heap address.
 *
 * Note on accumulation: the original widget's own rect contributes its
 * local center, then each ancestor (from immediate parent up to and including
 * the form) contributes its (left, top). The form itself is "(x,y) inside form
 * coords" = sum of all ancestors-below-form (left, top).  We don't add the
 * form's own (left, top) because we're producing form-local coords.
 *
 * Returns 0 on failure. */
static uintptr_t walk_to_form(uintptr_t start_addr, int* dx, int* dy,
                              const form_vmt_t** form_vmt_out) {
    uintptr_t cur = start_addr;
    int sum_x = 0, sum_y = 0;
    int depth = 0;
    while (depth < 32) {
        int ok = 0;
        uint32_t vmt = safe_read_u32(cur, &ok);
        if (!ok || vmt == 0) {
            logmsg("walk_to_form: bad read at 0x%08x (depth=%d)", (unsigned)cur, depth);
            return 0;
        }
        const form_vmt_t* fv = lookup_form_vmt(vmt);
        if (fv) {
            *form_vmt_out = fv;
            *dx = sum_x;
            *dy = sum_y;
            return cur;
        }
        /* Read this node's rect and add to running sum (this is an ancestor of
         * the start widget — except on first iteration, where it's the widget
         * itself; that's handled by the caller passing widget_local_center
         * separately). For the owner chain accumulation, we want the parent's
         * (left, top) summed for every ancestor above the start widget. */
        if (depth > 0) {
            int16_t rect[4];
            if (safe_read_rect_i16(cur, rect)) {
                sum_x += rect[0];
                sum_y += rect[1];
            }
        }
        /* Step to FOwner at +0x08. */
        int ok2 = 0;
        uint32_t owner = safe_read_u32(cur + 0x08, &ok2);
        if (!ok2 || owner == 0 || owner == cur) {
            logmsg("walk_to_form: chain ended with no form match at depth=%d (cur=0x%08x)",
                depth, (unsigned)cur);
            return 0;
        }
        cur = owner;
        depth++;
    }
    logmsg("walk_to_form: depth limit exceeded");
    return 0;
}

/* Synthesize a click on the given heap-resident widget.
 * Returns 0 on success, negative on failure. */
static int do_click_addr(uintptr_t widget_addr) {
    int ok = 0;
    uint32_t widget_vmt = safe_read_u32(widget_addr, &ok);
    if (!ok) {
        logmsg("click_addr: bad widget addr 0x%08x", (unsigned)widget_addr);
        return -1;
    }
    int16_t rect[4];
    if (!safe_read_rect_i16(widget_addr, rect)) {
        logmsg("click_addr: cannot read rect at 0x%08x", (unsigned)widget_addr);
        return -2;
    }
    int local_cx = (rect[0] + rect[2]) / 2;
    int local_cy = (rect[1] + rect[3]) / 2;

    /* Walk owner chain to find the form. The walk accumulates each ancestor's
     * (left, top) above the start widget.  The widget's own local center
     * (local_cx, local_cy) gives the offset relative to its parent's origin. */
    int dx = 0, dy = 0;
    const form_vmt_t* fv = NULL;
    uintptr_t form_addr = walk_to_form(widget_addr, &dx, &dy, &fv);
    if (!form_addr || !fv) {
        logmsg("click_addr: no form ancestor found from 0x%08x", (unsigned)widget_addr);
        return -3;
    }

    /* Form-local coords of the widget center. */
    int x_form = local_cx + dx;
    int y_form = local_cy + dy;
    uint32_t xy_packed = ((uint32_t)(x_form & 0xFFFF) << 16) | (uint32_t)(y_form & 0xFFFF);

    /* Resolve handler VA from class_info_va + 0x3C. */
    uint32_t handler_va = 0;
    {
        uintptr_t ci_rt = (uintptr_t)va2rt(fv->class_info_va);
        int ok3 = 0;
        handler_va = safe_read_u32(ci_rt + 0x3C, &ok3);
        if (!ok3 || handler_va == 0) {
            logmsg("click_addr: failed to read handler at class_info_va+0x3C "
                "(class_info_va=0x%08x rt=%p)", fv->class_info_va, (void*)ci_rt);
            return -4;
        }
    }
    /* handler_va is itself a runtime address (read out of the live VMT in
     * memory, which already contains image-base-relative pointers patched at
     * load).  Use directly as a function pointer — do NOT pass through va2rt
     * (which would double-rebase). */
    void* handler_rt = (void*)handler_va;

    logmsg("click_addr: widget=0x%08x rect=(%d,%d)-(%d,%d) form=%s@0x%08x "
        "xy_form=(%d,%d) handler=0x%08x",
        (unsigned)widget_addr, rect[0], rect[1], rect[2], rect[3],
        fv->name, (unsigned)form_addr, x_form, y_form, (unsigned)handler_va);

    /* DOWN */
    g_call_self = (uint32_t)form_addr;
    g_call_flags = 0x08;
    g_call_xy = xy_packed;
    g_call_btn = 1;
    g_call_handler = handler_rt;
    call_handle_mouse();
    logmsg("click_addr: DOWN OK (flags=0x08 xy=0x%08x)", xy_packed);

    Sleep(50);

    /* UP */
    g_call_self = (uint32_t)form_addr;
    g_call_flags = 0x10;
    g_call_xy = xy_packed;
    g_call_btn = 1;
    g_call_handler = handler_rt;
    call_handle_mouse();
    logmsg("click_addr: UP OK (flags=0x10 xy=0x%08x)", xy_packed);
    return 0;
}

/* Find first live instance of the given vmt by scanning MEM_PRIVATE regions.
 * Filter false positives by re-reading and matching exactly.
 * Returns 0 if not found. */
static uintptr_t find_instance_by_vmt(uint32_t target_vmt) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    BYTE* p = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* end = (BYTE*)0x7FFE0000;
    if (end > (BYTE*)si.lpMaximumApplicationAddress) end = (BYTE*)si.lpMaximumApplicationAddress;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) break;
        BYTE* nxt = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        DWORD prot = mbi.Protect & 0xFF;
        int readable = (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                        prot == PAGE_WRITECOPY);
        int has_guard = (mbi.Protect & PAGE_GUARD) != 0;
        if (mbi.State == MEM_COMMIT && readable && !has_guard &&
            mbi.Type == MEM_PRIVATE) {
            BYTE* rp = (BYTE*)mbi.BaseAddress;
            BYTE* re = nxt;
            for (BYTE* x = rp; x + 4 <= re; x += 4) {
                if (*(uint32_t*)x == target_vmt) {
                    return (uintptr_t)x;
                }
            }
        }
        p = nxt;
        if (nxt < (BYTE*)mbi.BaseAddress) break;
    }
    return 0;
}

/* Resolve a stable DOM path:
 *   <RootClass>@vmt=0xVMT/<Child>[idx=N]/<GrandChild>[idx=M]/...
 * Returns final widget heap addr, or 0 on failure. */
static uintptr_t resolve_path(const char* path) {
    /* Find "vmt=0x" marker; parse hex; that's the root vmt. */
    const char* vmt_marker = strstr(path, "vmt=0x");
    if (!vmt_marker) {
        logmsg("resolve_path: no vmt=0x marker in '%s'", path);
        return 0;
    }
    uint32_t root_vmt = (uint32_t)strtoul(vmt_marker + 6, NULL, 16);
    if (root_vmt == 0) {
        logmsg("resolve_path: bad root vmt in '%s'", path);
        return 0;
    }
    /* Determine child-list offset based on root class.  TMainForm uses +0x10
     * (TComponent.FComponents); TDnc forms use +0x28 (FList container). */
    int is_tmainform = (strstr(path, "TMainForm") == path);
    uint32_t child_list_off = is_tmainform ? 0x10 : 0x28;

    uintptr_t cur = find_instance_by_vmt(root_vmt);
    if (!cur) {
        logmsg("resolve_path: no live instance for vmt=0x%08x", root_vmt);
        return 0;
    }
    logmsg("resolve_path: root vmt=0x%08x found @ 0x%08x", root_vmt, (unsigned)cur);

    /* Walk path segments — each segment after the root either has [idx=N] or
     * is a name we ignore (we only use idx). Find each "[idx=" and parse. */
    const char* p = path;
    while ((p = strstr(p, "[idx=")) != NULL) {
        int idx = atoi(p + 5);
        p += 5;
        /* Read child container at cur + child_list_off:
         *   [+0x00] vt
         *   [+0x04] FList (TList) ptr
         *   [+0x08] FCount
         *   [+0x0C] FCap
         * (For TDnc forms.) For TMainForm/TComponent the layout is similar
         * (TList* at +0x04, count at +0x08). */
        int ok = 0;
        uint32_t list_ptr = safe_read_u32(cur + child_list_off + 0x04, &ok);
        if (!ok || !list_ptr) {
            logmsg("resolve_path: cannot read child list at 0x%08x+0x%x",
                (unsigned)cur, child_list_off);
            return 0;
        }
        /* TList holds an FList pointer at +0x04 too (Delphi convention varies).
         * But more directly: list_ptr points to an array of pointers — children
         * are at list_ptr[idx]. Try that first. */
        uintptr_t child = 0;
        int ok2 = 0;
        child = safe_read_u32(list_ptr + idx * 4, &ok2);
        if (!ok2 || !child) {
            logmsg("resolve_path: idx=%d child read failed (list_ptr=0x%08x)",
                idx, list_ptr);
            return 0;
        }
        logmsg("resolve_path: [idx=%d] -> 0x%08x", idx, (unsigned)child);
        cur = child;
        /* Subsequent levels always use TDnc layout (+0x28). */
        child_list_off = 0x28;
    }
    return cur;
}

/* ---------------------------------------------------------------------------
 * `invoke` command — call a widget's OnClick handler directly using the
 * per-class TMethod offset table from STEP2A.  This bypasses the fragile
 * coord-based HandleMouse path entirely.
 *
 * The widget instance lives at `heap_addr`. *(u32*)heap_addr is its VMT.
 * VMT-0x2C points at a Delphi ShortString class name.  Look up the class
 * in the static table below to get the OnClick offset.  Read TMethod:
 *   code = *(u32*)(heap_addr + offset)
 *   data = *(u32*)(heap_addr + offset + 4)
 * Call code(data) with EAX=data per Delphi register cv (verified by STEP1
 * decomp of 0x152708 which uses EAX as Self throughout).
 * --------------------------------------------------------------------------- */

typedef struct {
    const char* class_name;
    uint32_t    onclick_offset;
} class_onclick_t;

/* Per-class OnClick TMethod offsets — STEP2A verified.
 * NOTE: class names are matched against the Delphi ShortString at vmt-0x2C
 * (1-byte length prefix + ASCII, NOT null-terminated). */
static const class_onclick_t g_class_onclicks[] = {
    { "TDncNormBtn",      0x80 },
    { "TDncCloseBtn",     0x48 },
    { "TDncStyleButton",  0x38 },
    { "TDncCharListItem", 0x40 },
    { "TDncItemListbox",  0x98 },
};
#define N_CLASS_ONCLICKS (sizeof(g_class_onclicks)/sizeof(g_class_onclicks[0]))

/* Read a Delphi ShortString (1B length + ASCII). Writes into out_buf
 * (NUL-terminated). Returns 1 on success, 0 on failure. */
static int read_pascal_short_string(uintptr_t addr, char* out_buf, size_t buf_sz) {
    if (buf_sz == 0) return 0;
    if (!mem_readable(addr, 1)) return 0;
    uint8_t len = *(uint8_t*)addr;
    if (len == 0 || len > 250) return 0;
    if (!mem_readable(addr + 1, len)) return 0;
    if ((size_t)len + 1 > buf_sz) len = (uint8_t)(buf_sz - 1);
    memcpy(out_buf, (void*)(addr + 1), len);
    out_buf[len] = 0;
    return 1;
}

/* Naked trampoline for Delphi register cv: EAX = data, call code.
 * The handler may return via `ret` or `ret N` — we save all callee-preserved
 * regs around the call and restore. Result in EAX is ignored. */
static volatile uint32_t g_inv_data;
static volatile uint32_t g_inv_code;
static volatile uint32_t g_inv_sender;

/* Delphi OnClick TMethod call convention:
 *   procedure(Sender: TObject) of object
 *   EAX = Self (TMethod.data — captured at OnClick assignment, usually the form)
 *   EDX = Sender (the widget that was clicked — the heap addr we resolved)
 *   ECX = unused (typically 0)
 *
 * Initial STEP3A trampoline used EDX=0 because 0x152708 (Server Select OK)
 * doesn't dereference EDX. But 0xf236c (Char Select per-row inner btn)
 * does `mov eax,[edx+0x24]` to read the clicked button's role byte — passing
 * EDX=0 there causes a page fault. Fix: pass EDX=g_inv_sender = heap_addr of
 * invoked widget. STEP3A's smoke 1 still passes (EDX is harmless when unused).
 */
__attribute__((naked)) static void call_onclick_register_cv(void) {
    __asm__ __volatile__(
        "pushl %%ebx\n\t"
        "pushl %%esi\n\t"
        "pushl %%edi\n\t"
        "pushl %%ebp\n\t"
        "movl _g_inv_data, %%eax\n\t"   /* EAX = Self (data half of TMethod) */
        "movl _g_inv_sender, %%edx\n\t" /* EDX = Sender = widget heap addr */
        "xorl %%ecx, %%ecx\n\t"          /* ECX = unused */
        "call *_g_inv_code\n\t"
        "popl %%ebp\n\t"
        "popl %%edi\n\t"
        "popl %%esi\n\t"
        "popl %%ebx\n\t"
        "ret\n\t"
        : : : );
}

/* call_vmt trampoline — Delphi register cv "procedure of object" but with
 * Self=heap_addr (instance) directly, no Sender. EAX=Self, EDX=0, ECX=0.
 * Used to invoke virtual methods like Show/Hide via VMT slot. Same callee-
 * preserved register save/restore as call_onclick_register_cv. The callee
 * may `ret` or `ret N`; either is fine because we only restore registers,
 * we don't pop our own arg list (we passed args in regs). */
static volatile uint32_t g_vmt_self;
static volatile uint32_t g_vmt_code;

__attribute__((naked)) static void call_vmt_method(void) {
    __asm__ __volatile__(
        "pushl %%ebx\n\t"
        "pushl %%esi\n\t"
        "pushl %%edi\n\t"
        "pushl %%ebp\n\t"
        "movl _g_vmt_self, %%eax\n\t"   /* EAX = Self = instance heap addr */
        "xorl %%edx, %%edx\n\t"          /* EDX = 0 (no Sender) */
        "xorl %%ecx, %%ecx\n\t"          /* ECX = 0 */
        "call *_g_vmt_code\n\t"
        "popl %%ebp\n\t"
        "popl %%edi\n\t"
        "popl %%esi\n\t"
        "popl %%ebx\n\t"
        "ret\n\t"
        : : : );
}

/* ---------------------------------------------------------------------------
 * UI-thread dispatch (Phase 1A).
 *
 * Original design ran the OnClick directly on the polling thread. When the
 * handler entered a Delphi modal sub-loop (Application.HandleMessage), the
 * poll thread blocked until the modal was dismissed — meaning subsequent
 * commands in dom_cmd.txt could not be processed (incl. the modal's Yes/No
 * buttons that we need to invoke to drive the modal forward).
 *
 * Refactor: poll thread NEVER calls OnClick directly. Instead it:
 *   1. Parses the invoke args + resolves TMethod (still on poll thread —
 *      these are pure reads, no risk of blocking).
 *   2. Allocates an invoke_request_t with the resolved code/data/sender.
 *   3. PostMessage()s WM_USER+1 to a subclassed UI-thread window with the
 *      request as lParam.
 *   4. Returns immediately.
 *
 * The subclassed window's WndProc — running on the main UI thread — picks
 * the message up either from its own message pump or from the modal sub-loop's
 * pump (Delphi's modal pumps GetMessage from the same queue, so our custom
 * messages get delivered even while a modal is up). It calls the OnClick
 * trampoline. If THAT enters another modal, fine — the next PostMessage we
 * send from the poll thread will land in that modal's pump too.
 *
 * Window subclassing: on first invoke, walk top-level windows of this
 * process to find one whose owning thread has a message queue (most likely
 * the main window). Save its old WndProc with SetWindowLongPtrA(GWLP_WNDPROC)
 * and chain through.
 * --------------------------------------------------------------------------- */

#define WM_DOM_INVOKE  (WM_USER + 1)

typedef struct invoke_request {
    uint32_t code;
    uint32_t data;
    uint32_t sender;
    char     tag[64];   /* trailing '#N' from cmd line, for log correlation */
} invoke_request_t;

static HWND     g_ui_hwnd = NULL;
static WNDPROC  g_ui_orig_wndproc = NULL;
static DWORD    g_ui_tid = 0;

/* Run on UI thread (called from subclass WndProc). */
static void ui_dispatch_invoke(invoke_request_t* req) {
    if (!req) return;
    if (!mem_readable(req->code, 4)) {
        logmsg("ui_dispatch: code 0x%08x not readable — drop %s", req->code, req->tag);
        free(req);
        return;
    }
    g_inv_data = req->data;
    g_inv_code = req->code;
    g_inv_sender = req->sender;
    logmsg("ui_dispatch[%s]: tid=%lu calling code=0x%08x data=0x%08x sender=0x%08x ...",
           req->tag, GetCurrentThreadId(), req->code, req->data, req->sender);
    call_onclick_register_cv();
    logmsg("ui_dispatch[%s]: returned (tid=%lu)", req->tag, GetCurrentThreadId());
    free(req);
}

/* Forward decl — implemented further down (after cmd_call_vmt's struct). */
struct call_vmt_request;
static void ui_dispatch_call_vmt(struct call_vmt_request* req);
struct lua_exec_request;
static void ui_dispatch_lua_exec(struct lua_exec_request* req);
struct lua_diag_request;
static void ui_dispatch_lua_exec_diag(struct lua_diag_request* req);
struct npc_open_request;
static void ui_dispatch_npc_open(struct npc_open_request* req);
struct lua_chunk_probe_request;
static void ui_dispatch_lua_chunk_probe(struct lua_chunk_probe_request* req);

static LRESULT CALLBACK subclass_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_DOM_INVOKE) {
        ui_dispatch_invoke((invoke_request_t*)lp);
        return 0;
    }
    if (msg == (WM_USER + 2)) {  /* WM_DOM_CALL_VMT */
        ui_dispatch_call_vmt((struct call_vmt_request*)lp);
        return 0;
    }
    if (msg == (WM_USER + 3)) {  /* WM_DOM_LUA_EXEC */
        ui_dispatch_lua_exec((struct lua_exec_request*)lp);
        return 0;
    }
    if (msg == (WM_USER + 4)) {  /* WM_DOM_LUA_EXEC_DIAG */
        ui_dispatch_lua_exec_diag((struct lua_diag_request*)lp);
        return 0;
    }
    if (msg == (WM_USER + 5)) {  /* WM_DOM_NPC_OPEN */
        ui_dispatch_npc_open((struct npc_open_request*)lp);
        return 0;
    }
    if (msg == (WM_USER + 6)) {  /* WM_DOM_LUA_CHUNK_PROBE */
        ui_dispatch_lua_chunk_probe((struct lua_chunk_probe_request*)lp);
        return 0;
    }
    if (g_ui_orig_wndproc) return CallWindowProcA(g_ui_orig_wndproc, hwnd, msg, wp, lp);
    return DefWindowProcA(hwnd, msg, wp, lp);
}

/* Picker context: track the LARGEST visible window owned by this process,
 * not just the first match. The game has multiple top-levels (small
 * bootstrap TMainForm + the in-world canvas); we want the canvas. */
typedef struct {
    HWND  best;
    DWORD best_tid;
    LONG  best_area;
} pick_ctx_t;

static BOOL CALLBACK pick_ui_window_proc(HWND hwnd, LPARAM lp) {
    pick_ctx_t* ctx = (pick_ctx_t*)lp;
    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (!IsWindowVisible(hwnd)) return TRUE;
    RECT r;
    if (!GetWindowRect(hwnd, &r)) return TRUE;
    LONG w = r.right - r.left, h = r.bottom - r.top;
    if (w < 50 || h < 50) return TRUE;
    LONG area = w * h;
    if (area > ctx->best_area) {
        ctx->best = hwnd;
        ctx->best_tid = tid;
        ctx->best_area = area;
    }
    return TRUE; /* keep enumerating */
}

/* Diagnostic: log every visible window of this process with its class,
 * dimensions, and parent. Use this to discover the canvas hwnd if
 * pick_ui_window_proc keeps choosing the wrong one. */
static BOOL CALLBACK enum_windows_log_proc(HWND hwnd, LPARAM lp) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    char cls[64] = {0}, title[128] = {0};
    GetClassNameA(hwnd, cls, sizeof(cls)-1);
    GetWindowTextA(hwnd, title, sizeof(title)-1);
    RECT r = {0};
    GetWindowRect(hwnd, &r);
    HWND parent = GetParent(hwnd);
    int vis = IsWindowVisible(hwnd);
    logmsg("enum_windows: hwnd=%p vis=%d cls='%s' title='%s' "
           "rect=(%ld,%ld %ldx%ld) parent=%p",
           hwnd, vis, cls, title, r.left, r.top,
           r.right - r.left, r.bottom - r.top, parent);
    /* Recurse children too. */
    HWND child = GetWindow(hwnd, GW_CHILD);
    while (child) {
        char ccls[64] = {0};
        GetClassNameA(child, ccls, sizeof(ccls)-1);
        RECT cr = {0};
        GetWindowRect(child, &cr);
        logmsg("  child=%p cls='%s' rect=(%ld,%ld %ldx%ld) vis=%d",
               child, ccls, cr.left, cr.top,
               cr.right - cr.left, cr.bottom - cr.top,
               IsWindowVisible(child));
        child = GetWindow(child, GW_HWNDNEXT);
    }
    return TRUE;
}

static void cmd_enum_windows(void) {
    logmsg("enum_windows: enumerating top-levels for pid=%lu",
           GetCurrentProcessId());
    EnumWindows(enum_windows_log_proc, 0);
    logmsg("enum_windows: done");
}

/* One-time install. Returns 1 on success. */
static int ensure_ui_subclass(void) {
    if (g_ui_hwnd && g_ui_orig_wndproc) return 1;
    /* Walk all top-levels, take the largest. The game has a small
     * bootstrap TMainForm (~353x242) plus the in-world canvas top-level;
     * the canvas is much larger and is what we want clicks to land on. */
    pick_ctx_t ctx = {0};
    EnumWindows(pick_ui_window_proc, (LPARAM)&ctx);
    HWND hwnd = ctx.best;
    if (!hwnd) {
        logmsg("ensure_ui_subclass: no visible top-level window yet");
        return 0;
    }
    char cls[64] = {0};
    GetClassNameA(hwnd, cls, sizeof(cls)-1);
    RECT r = {0};
    GetWindowRect(hwnd, &r);
    logmsg("ensure_ui_subclass: picked hwnd=%p cls='%s' size=%ldx%ld area=%ld",
           hwnd, cls, r.right - r.left, r.bottom - r.top, ctx.best_area);
    g_ui_tid = ctx.best_tid;
    LONG_PTR old = SetWindowLongPtrA(hwnd, GWLP_WNDPROC,
        (LONG_PTR)subclass_wndproc);
    if (!old) {
        logmsg("ensure_ui_subclass: SetWindowLongPtrA failed gle=%lu",
               GetLastError());
        return 0;
    }
    g_ui_hwnd = hwnd;
    g_ui_orig_wndproc = (WNDPROC)old;
    logmsg("ensure_ui_subclass: subclassed (orig wndproc=%p)", (void*)old);
    return 1;
}

static int cmd_invoke(const char* args) {
    /* args is the substring after "invoke ". May contain a trailing " #N"
     * tag (added by wave2c_runner / smoke_full_walk to defeat dedupe). */
    /* args: "0xHEAP" or "HEAP" [optional " #N" suffix] */
    char tag[64] = {0};
    const char* hash = strchr(args, '#');
    if (hash) {
        size_t L = strlen(hash);
        if (L >= sizeof(tag)) L = sizeof(tag)-1;
        memcpy(tag, hash, L); tag[L] = 0;
    }
    uintptr_t heap_addr = (uintptr_t)strtoul(args, NULL, 0);
    if (heap_addr == 0) {
        logmsg("invoke: bad arg '%s'", args);
        return -1;
    }
    int ok = 0;
    uint32_t vmt = safe_read_u32(heap_addr, &ok);
    if (!ok || vmt == 0) {
        logmsg("invoke: cannot read VMT at heap=0x%08x", (unsigned)heap_addr);
        return -2;
    }
    int ok_p = 0;
    uint32_t name_ptr = safe_read_u32(vmt - 0x2C, &ok_p);
    if (!ok_p || name_ptr == 0) {
        logmsg("invoke: cannot read class name ptr at vmt-0x2C=0x%08x",
               vmt - 0x2C);
        return -3;
    }
    char cls[128] = {0};
    if (!read_pascal_short_string(name_ptr, cls, sizeof(cls))) {
        logmsg("invoke: cannot read class name shortstring at 0x%08x", name_ptr);
        return -3;
    }
    logmsg("invoke: heap=0x%08x vmt=0x%08x class='%s' tag='%s'",
           (unsigned)heap_addr, vmt, cls, tag);

    const class_onclick_t* entry = NULL;
    for (size_t i = 0; i < N_CLASS_ONCLICKS; i++) {
        if (strcmp(cls, g_class_onclicks[i].class_name) == 0) {
            entry = &g_class_onclicks[i];
            break;
        }
    }
    if (!entry) {
        logmsg("invoke: class '%s' not in OnClick offset table", cls);
        return -4;
    }
    uint32_t off = entry->onclick_offset;
    int ok2 = 0, ok3 = 0;
    uint32_t code = safe_read_u32(heap_addr + off, &ok2);
    uint32_t data = safe_read_u32(heap_addr + off + 4, &ok3);
    if (!ok2 || !ok3) {
        logmsg("invoke: cannot read TMethod at heap+0x%x", off);
        return -5;
    }
    logmsg("invoke: %s+0x%x -> code=0x%08x data=0x%08x",
           cls, off, code, data);
    if (code == 0 || data == 0) {
        logmsg("invoke: NULL code or data — handler not bound");
        return -6;
    }
    if (code < 0x11000 || code >= 0x300000) {
        logmsg("invoke: WARNING code=0x%08x outside expected .text range", code);
    }
    if (!mem_readable(code, 4)) {
        logmsg("invoke: code addr 0x%08x not readable — abort", code);
        return -7;
    }

    /* Phase 1A: post to UI thread instead of calling on poll thread. */
    if (!ensure_ui_subclass()) {
        logmsg("invoke: UI subclass not ready — aborting (will not call on poll thread)");
        return -8;
    }
    invoke_request_t* req = (invoke_request_t*)calloc(1, sizeof(*req));
    if (!req) { logmsg("invoke: OOM"); return -9; }
    req->code = code; req->data = data; req->sender = (uint32_t)heap_addr;
    strncpy(req->tag, tag[0] ? tag : "(no-tag)", sizeof(req->tag)-1);
    if (!PostMessageA(g_ui_hwnd, WM_DOM_INVOKE, 0, (LPARAM)req)) {
        logmsg("invoke: PostMessage failed gle=%lu", GetLastError());
        free(req);
        return -10;
    }
    logmsg("invoke: posted to UI thread (tid=%lu hwnd=%p) — poll thread returning immediately",
           g_ui_tid, g_ui_hwnd);
    return 0;
}

/* ---------------------------------------------------------------------------
 * cmd_set_byte: write a single byte at heap_addr.
 *
 * Args: "<heap_addr_hex> <byte_hex>"
 *
 * Used to flip form-active flags like TDncNPCDialog+0x18 = 0x01 to mimic the
 * VM transition without coord clicks. Verifies the address is in writable
 * memory via VirtualQuery before writing. Logs before/after byte for audit.
 * --------------------------------------------------------------------------- */
static int mem_writable(uintptr_t addr, size_t len) {
    if (addr < 0x10000) return 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & PAGE_GUARD) return 0;
    if (mbi.Protect & PAGE_NOACCESS) return 0;
    DWORD prot = mbi.Protect & 0xFF;
    int writable = (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
                    prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
    if (!writable) return 0;
    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    if (addr + len > region_end) return 0;
    return 1;
}

static int cmd_set_byte(const char* args) {
    /* args: "0xHEAP 0xBYTE" or "HEAP BYTE" */
    char* endp = NULL;
    uintptr_t addr = (uintptr_t)strtoul(args, &endp, 0);
    if (addr == 0 || !endp || endp == args) {
        logmsg("set_byte: bad addr arg '%s'", args);
        return -1;
    }
    /* skip whitespace */
    while (*endp == ' ' || *endp == '\t') endp++;
    if (!*endp) {
        logmsg("set_byte: missing byte arg in '%s'", args);
        return -2;
    }
    unsigned long b = strtoul(endp, NULL, 0);
    if (b > 0xFF) {
        logmsg("set_byte: byte value out of range: 0x%lx", b);
        return -3;
    }
    if (!mem_writable(addr, 1)) {
        logmsg("set_byte: addr 0x%08x not writable", (unsigned)addr);
        return -4;
    }
    uint8_t before = *(uint8_t*)addr;
    *(uint8_t*)addr = (uint8_t)b;
    uint8_t after = *(uint8_t*)addr;
    logmsg("[set_byte] addr=0x%08x before=0x%02x after=0x%02x",
           (unsigned)addr, before, after);
    return 0;
}

/* ---------------------------------------------------------------------------
 * cmd_call_vmt: call *(u32*)(vmt_base + slot) as a Delphi `procedure of
 * object` with Self=heap_addr.
 *
 * Args: "<heap_addr_hex> <vmt_slot_hex>"
 *
 * Used to fire form lifecycle methods (Show, Hide, Init) that aren't
 * exposed as TComponent OnClick TMethods. The slot offset is into the
 * class's VMT table; values come from forms_catalog.json.
 *
 * Posts to UI thread via subclass WndProc so that handlers entering modal
 * sub-loops don't block our poll thread (same pattern as cmd_invoke).
 * --------------------------------------------------------------------------- */

#define WM_DOM_CALL_VMT  (WM_USER + 2)

typedef struct call_vmt_request {
    uint32_t self;
    uint32_t code;
    uint32_t vmt_base;
    uint32_t slot;
} call_vmt_request_t;

/* Run on UI thread (called from subclass WndProc). */
static void ui_dispatch_call_vmt(call_vmt_request_t* req) {
    if (!req) return;
    if (!mem_readable(req->code, 4)) {
        logmsg("ui_dispatch_call_vmt: code 0x%08x not readable — drop", req->code);
        free(req);
        return;
    }
    g_vmt_self = req->self;
    g_vmt_code = req->code;
    logmsg("ui_dispatch_call_vmt: tid=%lu self=0x%08x vmt=0x%08x slot=0x%x code=0x%08x ...",
           GetCurrentThreadId(), req->self, req->vmt_base, req->slot, req->code);
    call_vmt_method();
    logmsg("ui_dispatch_call_vmt: returned (tid=%lu)", GetCurrentThreadId());
    free(req);
}

static int cmd_call_vmt(const char* args) {
    /* args: "0xHEAP 0xSLOT" */
    char* endp = NULL;
    uintptr_t heap_addr = (uintptr_t)strtoul(args, &endp, 0);
    if (heap_addr == 0 || !endp || endp == args) {
        logmsg("call_vmt: bad heap arg '%s'", args);
        return -1;
    }
    while (*endp == ' ' || *endp == '\t') endp++;
    if (!*endp) {
        logmsg("call_vmt: missing slot arg in '%s'", args);
        return -2;
    }
    uint32_t slot = (uint32_t)strtoul(endp, NULL, 0);

    int ok = 0;
    uint32_t vmt = safe_read_u32(heap_addr, &ok);
    if (!ok || vmt == 0) {
        logmsg("call_vmt: cannot read VMT at heap=0x%08x", (unsigned)heap_addr);
        return -3;
    }
    int ok2 = 0;
    uint32_t code = safe_read_u32(vmt + slot, &ok2);
    if (!ok2 || code == 0) {
        logmsg("call_vmt: cannot read code at vmt=0x%08x + slot=0x%x", vmt, slot);
        return -4;
    }
    /* Sanity: code must be inside DXRender.exe text region. PE ImageBase
     * 0x10000 honored; .text is typically up to ~0x300000. Reject obvious
     * heap pointers / nulls / out-of-bounds. */
    if (code < 0x11000 || code >= 0x300000) {
        logmsg("call_vmt: code=0x%08x outside expected .text range — abort",
               code);
        return -5;
    }
    if (!mem_readable(code, 4)) {
        logmsg("call_vmt: code addr 0x%08x not readable — abort", code);
        return -6;
    }
    logmsg("[call_vmt] heap=0x%08x vmt=0x%08x slot=0x%x code=0x%08x",
           (unsigned)heap_addr, vmt, slot, code);

    if (!ensure_ui_subclass()) {
        logmsg("call_vmt: UI subclass not ready — aborting");
        return -7;
    }
    call_vmt_request_t* req = (call_vmt_request_t*)calloc(1, sizeof(*req));
    if (!req) { logmsg("call_vmt: OOM"); return -8; }
    req->self = (uint32_t)heap_addr;
    req->code = code;
    req->vmt_base = vmt;
    req->slot = slot;
    if (!PostMessageA(g_ui_hwnd, WM_DOM_CALL_VMT, 0, (LPARAM)req)) {
        logmsg("call_vmt: PostMessage failed gle=%lu", GetLastError());
        free(req);
        return -9;
    }
    logmsg("[call_vmt] posted to UI thread (tid=%lu hwnd=%p)",
           g_ui_tid, g_ui_hwnd);
    return 0;
}

/* ---------------------------------------------------------------------------
 * cmd_lua_exec: call the engine's ExecLuaScript dispatcher directly to fire
 * an NPC-dialog (or any) Lua script by id.
 *
 * Args: "<script_id>"   (decimal, or 0x-prefixed hex)
 *
 * RE source: v2_re/SELECT_NPC_RE.md "Phase 2 RE writeup" section.
 *   ExecLuaScript VA = 0x00147bb0   (corrected 2026-05-01; was 0x001487b0)
 *   Signature: ExecLuaScript(eax=script_id_u32, dl=invoke_main_flag_u8) -> bool al
 *   Calling conv: Delphi register CV, no stack args.
 *   Pattern at 14 in-binary callsites: `mov eax, <id>; mov dl, 1; call 0x147bb0`.
 *
 * Diagnostic channel: TDncNPCDialog instance at 0x197f160; +0x18 is the u8
 * "visible" flag (0 hidden, 1 shown). MAIN→Init_Show flips this on success.
 *
 * Like cmd_invoke / cmd_call_vmt, posts the trampoline call to the UI thread
 * via the subclass WndProc so a modal/Lua sub-loop entered by the script
 * doesn't block our poll thread.
 * --------------------------------------------------------------------------- */

#define VA_FN_EXEC_LUA_SCRIPT  0x00147bb0   /* corrected 2026-05-01 (was 0x001487b0) */
#define VA_NPC_DIALOG_INSTANCE 0x0197f160   /* live (heap addr — verify with resolver if it drifts) */
#define OFF_NPC_DIALOG_VISIBLE 0x18

#define WM_DOM_LUA_EXEC  (WM_USER + 3)

typedef struct lua_exec_request {
    uint32_t script_id;
    uint8_t  invoke_main;   /* dl byte */
} lua_exec_request_t;

static volatile uint32_t g_lua_script_id;
static volatile uint32_t g_lua_invoke_main; /* full word; only low byte used as dl */
static volatile uint32_t g_lua_fn;          /* runtime addr of ExecLuaScript */
static volatile uint32_t g_lua_ret_al;      /* captured return value (zero-extended u8) */

/* Delphi register CV for ExecLuaScript:
 *   EAX = script_id  (u32)
 *   DL  = invoke_main (u8 — upper bits of edx don't matter; the func reads dl)
 *   no stack args; callee `pop ecx; pop edx; pop esi; pop ebx; ret` (no `ret N`).
 * Save callee-preserved regs (ebx, esi, edi, ebp). Capture al → g_lua_ret_al. */
__attribute__((naked)) static void call_exec_lua_script(void) {
    __asm__ __volatile__(
        "pushl %%ebx\n\t"
        "pushl %%esi\n\t"
        "pushl %%edi\n\t"
        "pushl %%ebp\n\t"
        "movl _g_lua_script_id, %%eax\n\t"   /* EAX = script_id */
        "movl _g_lua_invoke_main, %%edx\n\t" /* EDX (low byte = invoke_main) */
        "xorl %%ecx, %%ecx\n\t"
        "call *_g_lua_fn\n\t"
        "movzbl %%al, %%eax\n\t"             /* zero-extend al */
        "movl %%eax, _g_lua_ret_al\n\t"
        "popl %%ebp\n\t"
        "popl %%edi\n\t"
        "popl %%esi\n\t"
        "popl %%ebx\n\t"
        "ret\n\t"
        : : : );
}

static void ui_dispatch_lua_exec(lua_exec_request_t* req) {
    if (!req) return;
    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("ui_dispatch_lua_exec: ExecLuaScript fn_rt=%p not readable — drop", fn_rt);
        free(req);
        return;
    }
    uint8_t* vis_p = (uint8_t*)(VA_NPC_DIALOG_INSTANCE + OFF_NPC_DIALOG_VISIBLE);
    int vis_ok = mem_readable((uintptr_t)vis_p, 1);
    uint8_t visible_before = vis_ok ? *vis_p : 0xFF;

    g_lua_script_id   = req->script_id;
    g_lua_invoke_main = (uint32_t)req->invoke_main;
    g_lua_fn          = (uint32_t)fn_rt;
    g_lua_ret_al      = 0;

    logmsg("ui_dispatch_lua_exec: tid=%lu script_id=%u (0x%x) invoke_main=%u "
           "fn=0x%08x visible_before=%s0x%02x ...",
           GetCurrentThreadId(), req->script_id, req->script_id, req->invoke_main,
           (unsigned)(uintptr_t)fn_rt,
           vis_ok ? "" : "(unreadable) ", visible_before);

    call_exec_lua_script();

    int vis_ok2 = mem_readable((uintptr_t)vis_p, 1);
    uint8_t visible_after = vis_ok2 ? *vis_p : 0xFF;
    logmsg("ui_dispatch_lua_exec: returned al=%u visible_after=%s0x%02x",
           (unsigned)g_lua_ret_al,
           vis_ok2 ? "" : "(unreadable) ", visible_after);
    free(req);
}

static int cmd_lua_exec(const char* args) {
    /* args: "<script_id>" — decimal or 0x-hex.
     * Optional second token: "0" or "1" to override invoke_main (default 1). */
    while (*args == ' ' || *args == '\t') args++;
    if (!*args) { logmsg("lua_exec: missing script_id"); return -1; }
    char* endp = NULL;
    unsigned long sid = strtoul(args, &endp, 0);
    if (!endp || endp == args) { logmsg("lua_exec: bad script_id '%s'", args); return -2; }
    if (sid > 0xFFFFFFFFul) { logmsg("lua_exec: script_id out of range"); return -3; }

    uint8_t invoke_main = 1;
    while (*endp == ' ' || *endp == '\t') endp++;
    if (*endp) {
        unsigned long im = strtoul(endp, NULL, 0);
        invoke_main = (uint8_t)(im & 0xFF);
    }

    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("lua_exec: ExecLuaScript@VA 0x%x not resolvable/readable",
               VA_FN_EXEC_LUA_SCRIPT);
        return -4;
    }
    logmsg("[lua_exec] script_id=%lu (0x%lx) invoke_main=%u fn_rt=0x%08x "
           "npc_dialog_addr=0x%08x +0x%02x",
           sid, sid, invoke_main, (unsigned)(uintptr_t)fn_rt,
           VA_NPC_DIALOG_INSTANCE, OFF_NPC_DIALOG_VISIBLE);

    if (!ensure_ui_subclass()) {
        logmsg("lua_exec: UI subclass not ready — aborting");
        return -5;
    }
    lua_exec_request_t* req = (lua_exec_request_t*)calloc(1, sizeof(*req));
    if (!req) { logmsg("lua_exec: OOM"); return -6; }
    req->script_id = (uint32_t)sid;
    req->invoke_main = invoke_main;
    if (!PostMessageA(g_ui_hwnd, WM_DOM_LUA_EXEC, 0, (LPARAM)req)) {
        logmsg("lua_exec: PostMessage failed gle=%lu", GetLastError());
        free(req);
        return -7;
    }
    logmsg("[lua_exec] posted to UI thread (tid=%lu hwnd=%p)",
           g_ui_tid, g_ui_hwnd);
    return 0;
}

/* ---------------------------------------------------------------------------
 * cmd_lua_exec_diag: like cmd_lua_exec, but on failure (al==0) reads the Lua
 * error string from the top of the Lua stack via lua_tostring, then pops it
 * with lua_settop(L, -2). Resolves lua_State* dynamically by reading the era
 * cache wrapper class instance in BSS slot [0x2112e4], dereferencing, then
 * reading +0x4 (per disassembly of fn 0xb74a0 which loads `mov eax,[eax+4]`
 * to obtain the lua_State pointer it passes to lua_pcall).
 *
 *   era_cache_class = *(uint32_t*)0x2112e4   // VA in BSS — runtime-resolved
 *   lua_state       = *(uint32_t*)(era_cache_class + 0x4)
 *
 * lua_tostring / lua_settop are imported from lua5.1.dll — we resolve them
 * via GetProcAddress on the loaded module to avoid mapping IAT slot order
 * (the binary has no INT/OFT preserved; only runtime-bound IAT addresses).
 * --------------------------------------------------------------------------- */

#define VA_ERA_CACHE_CLASS_GLOBAL 0x002112e4
#define OFF_LUA_STATE_IN_CACHE     0x4

typedef const char* (__cdecl *lua_tolstring_t)(void* L, int idx, size_t* len);
typedef void        (__cdecl *lua_settop_t)(void* L, int idx);
typedef int         (__cdecl *lua_gettop_t)(void* L);
typedef int         (__cdecl *lua_type_t)(void* L, int idx);

#define WM_DOM_LUA_EXEC_DIAG  (WM_USER + 4)

typedef struct lua_diag_request {
    uint32_t script_id;
    uint8_t  invoke_main;
} lua_diag_request_t;

/* Resolve lua_State* by walking the era-cache wrapper instance. Returns NULL
 * on failure. Logs every step. */
static void* resolve_lua_state(void) {
    uint8_t* slot_p = (uint8_t*)va2rt(VA_ERA_CACHE_CLASS_GLOBAL);
    if (!slot_p || !mem_readable((uintptr_t)slot_p, 4)) {
        logmsg("resolve_lua_state: BSS slot 0x%x not readable (rt=%p)",
               VA_ERA_CACHE_CLASS_GLOBAL, slot_p);
        return NULL;
    }
    uint32_t era_inst = *(uint32_t*)slot_p;
    if (!era_inst || !mem_readable(era_inst, 0x10)) {
        logmsg("resolve_lua_state: era cache instance 0x%x not readable",
               era_inst);
        return NULL;
    }
    uint32_t lua_state = *(uint32_t*)(era_inst + OFF_LUA_STATE_IN_CACHE);
    if (!lua_state || !mem_readable(lua_state, 0x10)) {
        logmsg("resolve_lua_state: era_inst=0x%x +0x%x = 0x%x — not a "
               "readable pointer", era_inst, OFF_LUA_STATE_IN_CACHE, lua_state);
        return NULL;
    }
    logmsg("resolve_lua_state: era_inst=0x%x lua_state=0x%x",
           era_inst, lua_state);
    return (void*)lua_state;
}

/* Resolve a lua API by name; logs and returns NULL on failure. */
static FARPROC resolve_lua_fn(const char* name) {
    HMODULE h = GetModuleHandleA("lua5.1.dll");
    if (!h) {
        /* Try alternate spellings — Wine sometimes case-folds. */
        h = GetModuleHandleA("LUA5.1.DLL");
    }
    if (!h) {
        logmsg("resolve_lua_fn: GetModuleHandleA(\"lua5.1.dll\") failed gle=%lu",
               GetLastError());
        return NULL;
    }
    FARPROC p = GetProcAddress(h, name);
    if (!p) {
        logmsg("resolve_lua_fn: GetProcAddress(%s) failed gle=%lu",
               name, GetLastError());
    }
    return p;
}

static void ui_dispatch_lua_exec_diag(lua_diag_request_t* req) {
    if (!req) return;
    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("ui_dispatch_lua_exec_diag: ExecLuaScript fn_rt=%p not readable — drop", fn_rt);
        free(req);
        return;
    }

    /* Resolve lua API (do this BEFORE calling ExecLuaScript so failure logs
     * are clear about which step broke). */
    lua_tolstring_t lua_tolstring = (lua_tolstring_t)resolve_lua_fn("lua_tolstring");
    lua_settop_t    lua_settop    = (lua_settop_t)resolve_lua_fn("lua_settop");
    lua_gettop_t    lua_gettop    = (lua_gettop_t)resolve_lua_fn("lua_gettop");
    lua_type_t      lua_type_fn   = (lua_type_t)resolve_lua_fn("lua_type");
    if (!lua_tolstring || !lua_settop) {
        logmsg("ui_dispatch_lua_exec_diag: lua API resolve FAILED — "
               "tolstring=%p settop=%p", lua_tolstring, lua_settop);
        free(req);
        return;
    }

    /* Resolve lua_State* — capture before call so we know the value even if
     * the call corrupts something. */
    void* L_before = resolve_lua_state();
    int top_before = (lua_gettop && L_before) ? lua_gettop(L_before) : -1;

    g_lua_script_id   = req->script_id;
    g_lua_invoke_main = (uint32_t)req->invoke_main;
    g_lua_fn          = (uint32_t)fn_rt;
    g_lua_ret_al      = 0;

    logmsg("[lua_exec_diag] tid=%lu script_id=%u (0x%x) invoke_main=%u "
           "fn=0x%08x L_before=%p top_before=%d ...",
           GetCurrentThreadId(), req->script_id, req->script_id, req->invoke_main,
           (unsigned)(uintptr_t)fn_rt, L_before, top_before);

    call_exec_lua_script();

    void* L = resolve_lua_state();
    int top_after = (lua_gettop && L) ? lua_gettop(L) : -1;

    if (g_lua_ret_al == 1) {
        logmsg("[lua_exec_diag] al=1 — no error, ScriptMain succeeded "
               "(L=%p top_after=%d)", L, top_after);
    } else {
        logmsg("[lua_exec_diag] al=0 — failure path. L=%p top_after=%d",
               L, top_after);
        if (!L) {
            logmsg("[lua_exec_diag] cannot fetch error: lua_State* unresolved");
        } else if (top_after > top_before) {
            int t = lua_type_fn ? lua_type_fn(L, -1) : -99;
            logmsg("[lua_exec_diag] lua_type(L,-1) = %d "
                   "(0=nil 1=bool 3=num 4=str 5=tbl 6=fn 7=usrdata)", t);
            size_t slen = 0;
            const char* err = lua_tolstring(L, -1, &slen);
            if (err) {
                /* Truncate to a sane bound to keep log line digestible. */
                char tmp[1024];
                size_t cp = slen < sizeof(tmp) - 1 ? slen : sizeof(tmp) - 1;
                memcpy(tmp, err, cp);
                tmp[cp] = 0;
                logmsg("[lua_exec_diag] LUA_ERROR (len=%zu): %s", slen, tmp);
            } else {
                logmsg("[lua_exec_diag] lua_tostring returned NULL — error "
                       "is not a string (type=%d)", t);
            }
        } else {
            logmsg("[lua_exec_diag] no items added to stack (top_before=%d "
                   "top_after=%d) — error not on top, skipping read",
                   top_before, top_after);
        }
        /* Restore stack to top_before regardless of failure mode. Non-destructive
         * even if al=1 (when top_after == top_before this is a no-op). */
        if (lua_gettop && lua_settop) {
            int cur = lua_gettop(L);
            if (cur > top_before) {
                lua_settop(L, top_before);
                logmsg("[lua_exec_diag] restored stack: top %d -> %d", cur, top_before);
            }
        }
    }
    free(req);
}

static int cmd_lua_exec_diag(const char* args) {
    while (*args == ' ' || *args == '\t') args++;
    if (!*args) { logmsg("lua_exec_diag: missing script_id"); return -1; }
    char* endp = NULL;
    unsigned long sid = strtoul(args, &endp, 0);
    if (!endp || endp == args) { logmsg("lua_exec_diag: bad script_id '%s'", args); return -2; }
    if (sid > 0xFFFFFFFFul) { logmsg("lua_exec_diag: script_id out of range"); return -3; }

    uint8_t invoke_main = 1;
    while (*endp == ' ' || *endp == '\t') endp++;
    if (*endp) {
        unsigned long im = strtoul(endp, NULL, 0);
        invoke_main = (uint8_t)(im & 0xFF);
    }

    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("lua_exec_diag: ExecLuaScript@VA 0x%x not resolvable",
               VA_FN_EXEC_LUA_SCRIPT);
        return -4;
    }
    logmsg("[lua_exec_diag] script_id=%lu (0x%lx) invoke_main=%u fn_rt=0x%08x "
           "era_cache_global=0x%x",
           sid, sid, invoke_main, (unsigned)(uintptr_t)fn_rt,
           VA_ERA_CACHE_CLASS_GLOBAL);

    if (!ensure_ui_subclass()) {
        logmsg("lua_exec_diag: UI subclass not ready");
        return -5;
    }
    lua_diag_request_t* req = (lua_diag_request_t*)calloc(1, sizeof(*req));
    if (!req) { logmsg("lua_exec_diag: OOM"); return -6; }
    req->script_id = (uint32_t)sid;
    req->invoke_main = invoke_main;
    if (!PostMessageA(g_ui_hwnd, WM_DOM_LUA_EXEC_DIAG, 0, (LPARAM)req)) {
        logmsg("lua_exec_diag: PostMessage failed gle=%lu", GetLastError());
        free(req);
        return -7;
    }
    logmsg("[lua_exec_diag] posted to UI thread");
    return 0;
}

/* ---------------------------------------------------------------------------
 * cmd_npc_open: open an NPC dialog by directly invoking the script's
 * Init_Show + goStart Lua entrypoints, using the engine's ExecLuaScript
 * to register the chunk's globals first.
 *
 * Args: "<script_id> <npc_name>" — script_id decimal/hex, npc_name remainder
 *       optional 3rd token: hex npc_dialog_addr (overrides hardcoded const)
 *
 * 4-step sequence (all on UI thread):
 *   1. top_before = lua_gettop(L); visible_before = *(u8*)(npc_dialog+0x18)
 *   2. ExecLuaScript(id, 1) — loads chunk + invokes ScriptMain (expected al=0
 *      for scripts like 44401 that don't define ScriptMain; side-effect:
 *      chunk's globals are registered).
 *   3. lua_settop(L, top_before) — clean any leftover (errors, return vals).
 *   4. Init_Show: getglobal "Init_Show" -> pushstring(npc_name) -> pcall(1,0,0).
 *      goStart:   getglobal "goStart"  -> pcall(0,0,0).
 *   5. Capture errors via lua_tostring; restore stack to top_before.
 *   6. visible_after = *(u8*)(npc_dialog+0x18); log.
 * --------------------------------------------------------------------------- */

#define WM_DOM_NPC_OPEN  (WM_USER + 5)

typedef struct npc_open_request {
    uint32_t script_id;
    uint32_t npc_dialog_addr;  /* 0 -> use VA_NPC_DIALOG_INSTANCE default */
    char     npc_name[64];
} npc_open_request_t;

/* Lua API typedefs not already declared above. */
typedef int  (__cdecl *lua_pcall_t)(void* L, int nargs, int nresults, int errfunc);
typedef void (__cdecl *lua_getfield_t)(void* L, int idx, const char* k);
typedef void (__cdecl *lua_pushstring_t)(void* L, const char* s);

#define LUA_GLOBALSINDEX (-10002)

/* Helper: pop and return Lua error string from top of stack (as malloc'd copy
 * up to bound). Caller frees. Returns NULL if no string. */
static char* drain_lua_error(void* L,
                             lua_tolstring_t lua_tolstring,
                             lua_type_t lua_type_fn,
                             int* out_type)
{
    int t = lua_type_fn ? lua_type_fn(L, -1) : -99;
    if (out_type) *out_type = t;
    size_t slen = 0;
    const char* err = lua_tolstring(L, -1, &slen);
    if (!err) return NULL;
    size_t cp = slen < 1023 ? slen : 1023;
    char* buf = (char*)malloc(cp + 1);
    if (!buf) return NULL;
    memcpy(buf, err, cp);
    buf[cp] = 0;
    return buf;
}

static void ui_dispatch_npc_open(npc_open_request_t* req) {
    if (!req) return;

    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("ui_dispatch_npc_open: ExecLuaScript fn_rt=%p not readable — drop", fn_rt);
        free(req);
        return;
    }

    /* Resolve Lua API. */
    lua_tolstring_t  lua_tolstring  = (lua_tolstring_t) resolve_lua_fn("lua_tolstring");
    lua_settop_t     lua_settop     = (lua_settop_t)    resolve_lua_fn("lua_settop");
    lua_gettop_t     lua_gettop     = (lua_gettop_t)    resolve_lua_fn("lua_gettop");
    lua_type_t       lua_type_fn    = (lua_type_t)      resolve_lua_fn("lua_type");
    lua_pcall_t      lua_pcall      = (lua_pcall_t)     resolve_lua_fn("lua_pcall");
    lua_getfield_t   lua_getfield   = (lua_getfield_t)  resolve_lua_fn("lua_getfield");
    lua_pushstring_t lua_pushstring = (lua_pushstring_t)resolve_lua_fn("lua_pushstring");
    if (!lua_tolstring || !lua_settop || !lua_gettop || !lua_type_fn ||
        !lua_pcall || !lua_getfield || !lua_pushstring) {
        logmsg("ui_dispatch_npc_open: lua API resolve FAILED — "
               "tolstring=%p settop=%p gettop=%p type=%p pcall=%p "
               "getfield=%p pushstring=%p",
               lua_tolstring, lua_settop, lua_gettop, lua_type_fn,
               lua_pcall, lua_getfield, lua_pushstring);
        free(req);
        return;
    }

    void* L = resolve_lua_state();
    if (!L) {
        logmsg("ui_dispatch_npc_open: lua_State* unresolved — abort");
        free(req);
        return;
    }
    int top_before = lua_gettop(L);

    uintptr_t npc_addr = req->npc_dialog_addr ? req->npc_dialog_addr : VA_NPC_DIALOG_INSTANCE;
    uint8_t* vis_p = (uint8_t*)(npc_addr + OFF_NPC_DIALOG_VISIBLE);
    int vis_ok_b = mem_readable((uintptr_t)vis_p, 1);
    uint8_t visible_before = vis_ok_b ? *vis_p : 0xFF;

    logmsg("[npc_open] tid=%lu script_id=%u (0x%x) npc_name='%s' "
           "npc_dialog_addr=0x%08x +0x%02x L=%p top_before=%d "
           "visible_before=%s0x%02x ...",
           GetCurrentThreadId(), req->script_id, req->script_id, req->npc_name,
           (unsigned)npc_addr, OFF_NPC_DIALOG_VISIBLE, L, top_before,
           vis_ok_b ? "" : "(unreadable) ", visible_before);

    /* === Step 2: register chunk globals via Lua-level Lua.ExecLuaScript(id, false)
     * Rationale: the C-level ExecLuaScript at 0x147bb0 with dl=1 calls ScriptMain
     * (which scripts like 44401 don't define -> al=0 + chunk discarded; goStart
     * not registered). With dl=0 it only does luaL_loadbuffer. Neither path
     * runs the loaded chunk to register the script's named functions.
     *
     * The Lua-side `Lua.ExecLuaScript(id, false)` binding is the API that
     * scripts use to load+execute other scripts (see e.g. script 27 line 38).
     * It must internally pcall the chunk to register globals (otherwise script
     * inclusion wouldn't work). Use that path instead.
     *
     * Sequence: getglobal "Lua" -> getfield "ExecLuaScript" -> pushinteger id
     * -> pushboolean false -> pcall(2,0|N,0). */
    int top_after_exec = top_before;
    {
        /* Resolve a couple more lua API fns. */
        typedef void (__cdecl *lua_pushinteger_t)(void* L, ptrdiff_t n);
        typedef void (__cdecl *lua_pushboolean_t)(void* L, int b);
        typedef void (__cdecl *lua_pop_helper_t)(void* L, int idx); /* same sig as settop */
        lua_pushinteger_t lua_pushinteger =
            (lua_pushinteger_t)resolve_lua_fn("lua_pushinteger");
        lua_pushboolean_t lua_pushboolean =
            (lua_pushboolean_t)resolve_lua_fn("lua_pushboolean");
        if (!lua_pushinteger || !lua_pushboolean) {
            logmsg("[npc_open] step1: lua_pushinteger=%p lua_pushboolean=%p — "
                   "FAIL", lua_pushinteger, lua_pushboolean);
            free(req);
            return;
        }
        /* Lua.ExecLuaScript */
        lua_getfield(L, LUA_GLOBALSINDEX, "Lua");
        int t_lua = lua_type_fn(L, -1);
        if (t_lua != 5 /* LUA_TTABLE */) {
            logmsg("[npc_open] step1: 'Lua' global type=%d (expected 5=table) "
                   "— FAIL", t_lua);
            lua_settop(L, top_before);
            free(req);
            return;
        }
        lua_getfield(L, -1, "ExecLuaScript");
        int t_exec = lua_type_fn(L, -1);
        if (t_exec != 6 /* LUA_TFUNCTION */) {
            logmsg("[npc_open] step1: Lua.ExecLuaScript type=%d (expected "
                   "6=function) — FAIL", t_exec);
            lua_settop(L, top_before);
            free(req);
            return;
        }
        /* Stack: [Lua_table][ExecLuaScript fn]. Pcall wants fn at top, then args.
         * Move fn under Lua_table? Easier: just call with fn+args, pop the
         * leftover Lua_table afterwards. Push args first. */
        lua_pushinteger(L, (ptrdiff_t)req->script_id);
        lua_pushboolean(L, 0); /* invoke_main = false */
        /* Stack: [Lua][ExecLuaScript][id][false]; lua_pcall(L, 2, 0, 0) calls
         * ExecLuaScript with 2 args, popping fn+args, leaving [Lua] on stack. */
        int rc = lua_pcall(L, 2, 0, 0);
        if (rc != 0) {
            int t = -99;
            char* errstr = drain_lua_error(L, lua_tolstring, lua_type_fn, &t);
            if (errstr) {
                logmsg("[npc_open] step1: Lua.ExecLuaScript(%u,false) FAILED "
                       "rc=%d type=%d err=%s",
                       req->script_id, rc, t, errstr);
                free(errstr);
            } else {
                logmsg("[npc_open] step1: Lua.ExecLuaScript(%u,false) FAILED "
                       "rc=%d type=%d (no string)",
                       req->script_id, rc, t);
            }
            lua_settop(L, top_before);
            free(req);
            int vis_ok2 = mem_readable((uintptr_t)vis_p, 1);
            uint8_t va = vis_ok2 ? *vis_p : 0xFF;
            logmsg("[npc_open] DONE (script load err): visible %s0x%02x -> %s0x%02x",
                   vis_ok_b ? "" : "(?) ", visible_before,
                   vis_ok2 ? "" : "(?) ", va);
            return;
        }
        /* Pop leftover Lua table. */
        lua_settop(L, top_before);
        top_after_exec = lua_gettop(L);
        logmsg("[npc_open] step1: Lua.ExecLuaScript(%u,false) OK top=%d->%d",
               req->script_id, top_before, top_after_exec);
    }

    /* === Step 3: Init_Show(npc_name) === */
    {
        lua_getfield(L, LUA_GLOBALSINDEX, "Init_Show");
        int t_init = lua_type_fn(L, -1);
        logmsg("[npc_open] step2: lua_getglobal(Init_Show) type=%d "
               "(6=function, 0=nil)", t_init);
        if (t_init != 6 /* LUA_TFUNCTION */) {
            logmsg("[npc_open] step2: Init_Show NOT REGISTERED — globals not "
                   "loaded (chunk-eval did not run). FATAL.");
            lua_settop(L, top_before);
            free(req);
            /* Read post-state for log even on failure. */
            int vis_ok2 = mem_readable((uintptr_t)vis_p, 1);
            uint8_t va = vis_ok2 ? *vis_p : 0xFF;
            logmsg("[npc_open] DONE (Init_Show missing): visible %s0x%02x -> %s0x%02x",
                   vis_ok_b ? "" : "(?) ", visible_before,
                   vis_ok2 ? "" : "(?) ", va);
            return;
        }
        lua_pushstring(L, req->npc_name);
        int rc = lua_pcall(L, 1, 0, 0);
        if (rc == 0) {
            logmsg("[npc_open] step2: Init_Show('%s') OK", req->npc_name);
        } else {
            int t = -99;
            char* errstr = drain_lua_error(L, lua_tolstring, lua_type_fn, &t);
            if (errstr) {
                logmsg("[npc_open] step2: Init_Show pcall FAILED rc=%d type=%d err=%s",
                       rc, t, errstr);
                free(errstr);
            } else {
                logmsg("[npc_open] step2: Init_Show pcall FAILED rc=%d type=%d "
                       "(no string)", rc, t);
            }
            lua_settop(L, top_before);
            /* Continue to goStart anyway? No — Init_Show binds OldNPC; without
             * it goStart's calls (SetMsg / OldNPC.AddButton) may fail too.
             * Bail out. */
            free(req);
            int vis_ok2 = mem_readable((uintptr_t)vis_p, 1);
            uint8_t va = vis_ok2 ? *vis_p : 0xFF;
            logmsg("[npc_open] DONE (Init_Show err): visible %s0x%02x -> %s0x%02x",
                   vis_ok_b ? "" : "(?) ", visible_before,
                   vis_ok2 ? "" : "(?) ", va);
            return;
        }
    }

    /* === Step 4: goStart() === */
    {
        lua_getfield(L, LUA_GLOBALSINDEX, "goStart");
        int t_go = lua_type_fn(L, -1);
        logmsg("[npc_open] step3: lua_getglobal(goStart) type=%d", t_go);
        if (t_go != 6 /* LUA_TFUNCTION */) {
            logmsg("[npc_open] step3: goStart NOT REGISTERED — chunk for "
                   "script %u did not define it (or ExecLuaScript didn't "
                   "register globals). Init_Show ran but no message will display.",
                   req->script_id);
            lua_settop(L, top_before);
        } else {
            int rc = lua_pcall(L, 0, 0, 0);
            if (rc == 0) {
                logmsg("[npc_open] step3: goStart() OK");
            } else {
                int t = -99;
                char* errstr = drain_lua_error(L, lua_tolstring, lua_type_fn, &t);
                if (errstr) {
                    logmsg("[npc_open] step3: goStart pcall FAILED rc=%d type=%d err=%s",
                           rc, t, errstr);
                    free(errstr);
                } else {
                    logmsg("[npc_open] step3: goStart pcall FAILED rc=%d type=%d "
                           "(no string)", rc, t);
                }
                lua_settop(L, top_before);
            }
        }
    }

    /* === Step 5: defensive stack restore + post-state read === */
    int top_final = lua_gettop(L);
    if (top_final != top_before) {
        logmsg("[npc_open] cleanup: top %d != top_before %d, restoring",
               top_final, top_before);
        lua_settop(L, top_before);
    }
    int vis_ok2 = mem_readable((uintptr_t)vis_p, 1);
    uint8_t visible_after = vis_ok2 ? *vis_p : 0xFF;
    logmsg("[npc_open] DONE: top %d -> %d  visible %s0x%02x -> %s0x%02x  "
           "(0x18 flip 0->1 = dialog opened)",
           top_before, lua_gettop(L),
           vis_ok_b ? "" : "(?) ", visible_before,
           vis_ok2 ? "" : "(?) ", visible_after);

    free(req);
}

static int cmd_npc_open(const char* args) {
    /* args: "<script_id> <npc_name> [npc_dialog_addr_hex]" */
    while (*args == ' ' || *args == '\t') args++;
    if (!*args) { logmsg("npc_open: missing script_id"); return -1; }
    char* endp = NULL;
    unsigned long sid = strtoul(args, &endp, 0);
    if (!endp || endp == args) { logmsg("npc_open: bad script_id '%s'", args); return -2; }
    if (sid > 0xFFFFFFFFul) { logmsg("npc_open: script_id out of range"); return -3; }

    while (*endp == ' ' || *endp == '\t') endp++;
    if (!*endp) { logmsg("npc_open: missing npc_name"); return -4; }

    /* npc_name = remainder until end OR until trailing token that parses as
     * a number (npc_dialog_addr override). To keep parsing simple, grab the
     * full remaining string, then if its last whitespace-separated token
     * is hex/numeric, peel it off as npc_dialog_addr. */
    char rest[256];
    size_t rlen = strlen(endp);
    if (rlen >= sizeof(rest)) rlen = sizeof(rest) - 1;
    memcpy(rest, endp, rlen);
    rest[rlen] = 0;

    uintptr_t npc_addr_override = 0;
    /* Find last token. */
    char* last_space = NULL;
    for (size_t i = rlen; i > 0; i--) {
        if (rest[i-1] == ' ' || rest[i-1] == '\t') {
            last_space = rest + i - 1;
            break;
        }
    }
    if (last_space) {
        char* tok = last_space + 1;
        char* end2 = NULL;
        unsigned long v = strtoul(tok, &end2, 0);
        if (end2 && *end2 == 0 && end2 != tok && v > 0x10000) {
            npc_addr_override = (uintptr_t)v;
            /* Trim trailing whitespace+token from rest. */
            *last_space = 0;
            while (last_space > rest &&
                   (last_space[-1] == ' ' || last_space[-1] == '\t')) {
                last_space--;
                *last_space = 0;
            }
        }
    }

    /* rest now holds the npc_name (may have internal spaces, e.g. "Solstice Guide") */
    char* nm = rest;
    while (*nm == ' ' || *nm == '\t') nm++;
    size_t nm_len = strlen(nm);
    /* Strip trailing whitespace. */
    while (nm_len > 0 && (nm[nm_len-1] == ' ' || nm[nm_len-1] == '\t' ||
                          nm[nm_len-1] == '\r' || nm[nm_len-1] == '\n')) {
        nm[--nm_len] = 0;
    }
    if (nm_len == 0) { logmsg("npc_open: empty npc_name"); return -5; }

    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("npc_open: ExecLuaScript@VA 0x%x not resolvable",
               VA_FN_EXEC_LUA_SCRIPT);
        return -6;
    }

    logmsg("[npc_open] script_id=%lu (0x%lx) npc_name='%s' "
           "npc_dialog_addr=0x%08x (override=%s) fn_rt=0x%08x",
           sid, sid, nm,
           (unsigned)(npc_addr_override ? npc_addr_override : VA_NPC_DIALOG_INSTANCE),
           npc_addr_override ? "yes" : "no",
           (unsigned)(uintptr_t)fn_rt);

    if (!ensure_ui_subclass()) {
        logmsg("npc_open: UI subclass not ready");
        return -7;
    }
    npc_open_request_t* req = (npc_open_request_t*)calloc(1, sizeof(*req));
    if (!req) { logmsg("npc_open: OOM"); return -8; }
    req->script_id = (uint32_t)sid;
    req->npc_dialog_addr = (uint32_t)npc_addr_override;
    size_t cp = nm_len < sizeof(req->npc_name) - 1 ? nm_len : sizeof(req->npc_name) - 1;
    memcpy(req->npc_name, nm, cp);
    req->npc_name[cp] = 0;

    if (!PostMessageA(g_ui_hwnd, WM_DOM_NPC_OPEN, 0, (LPARAM)req)) {
        logmsg("npc_open: PostMessage failed gle=%lu", GetLastError());
        free(req);
        return -9;
    }
    logmsg("[npc_open] posted to UI thread");
    return 0;
}

/* Phase 1A: noop heartbeat, used to verify poll thread liveness while a
 * modal is up on the UI thread. Runs entirely on the poll thread. */
static int cmd_noop(const char* args) {
    logmsg("noop[%s]: poll_thread tid=%lu alive @ %lu ms",
           args ? args : "", GetCurrentThreadId(), GetTickCount());
    return 0;
}

static int cmd_click_addr(const char* args) {
    /* args: "0xHEAP" or "HEAP" */
    uintptr_t addr = (uintptr_t)strtoul(args, NULL, 0);
    if (addr == 0) {
        logmsg("click_addr: bad arg '%s'", args);
        return -1;
    }
    return do_click_addr(addr);
}

static int cmd_click_path(const char* args) {
    uintptr_t addr = resolve_path(args);
    if (!addr) {
        logmsg("click_path: resolution failed for '%s'", args);
        return -1;
    }
    logmsg("click_path: resolved '%s' -> 0x%08x", args, (unsigned)addr);
    return do_click_addr(addr);
}

static int cmd_click_xy(const char* args) {
    /* args: "<form_vmt_hex> <x> <y>" */
    char* endp = NULL;
    uint32_t form_vmt = (uint32_t)strtoul(args, &endp, 0);
    if (!endp || form_vmt == 0) { logmsg("click_xy: bad form_vmt '%s'", args); return -1; }
    int x = (int)strtol(endp, &endp, 10);
    int y = (int)strtol(endp, &endp, 10);

    const form_vmt_t* fv = lookup_form_vmt(form_vmt);
    if (!fv) { logmsg("click_xy: unknown form vmt 0x%08x", form_vmt); return -2; }

    uintptr_t form_addr = find_instance_by_vmt(fv->instance_vmt);
    if (!form_addr) { logmsg("click_xy: no live instance of %s", fv->name); return -3; }

    uintptr_t ci_rt = (uintptr_t)va2rt(fv->class_info_va);
    int ok3 = 0;
    uint32_t handler_va = safe_read_u32(ci_rt + 0x3C, &ok3);
    if (!ok3 || !handler_va) { logmsg("click_xy: cannot read handler"); return -4; }

    uint32_t xy_packed = ((uint32_t)(x & 0xFFFF) << 16) | (uint32_t)(y & 0xFFFF);
    logmsg("click_xy: form=%s@0x%08x xy=(%d,%d) handler=0x%08x",
        fv->name, (unsigned)form_addr, x, y, (unsigned)handler_va);

    g_call_handler = (void*)handler_va;
    g_call_self = (uint32_t)form_addr;
    g_call_xy = xy_packed;
    g_call_btn = 1;

    g_call_flags = 0x08;
    call_handle_mouse(); logmsg("click_xy: DOWN OK");
    Sleep(50);
    g_call_flags = 0x10;
    call_handle_mouse(); logmsg("click_xy: UP OK");
    return 0;
}

/* Find the game's actual canvas window: visible, class starts with
 * "TMainForm" (Delphi VCL main form), owned by this process. Falls back
 * to the largest visible top-level if no class match. Re-runs on every
 * call so we never get stuck on a stale handle (e.g., the TSplash that
 * is visible at startup and goes invisible later). */
typedef struct {
    HWND  best;          /* largest visible top-level (fallback)         */
    LONG  best_area;
    HWND  preferred;     /* visible top-level with TMainForm* class      */
} click_pick_ctx_t;

static BOOL CALLBACK click_pick_proc(HWND hwnd, LPARAM lp) {
    click_pick_ctx_t* ctx = (click_pick_ctx_t*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (!IsWindowVisible(hwnd)) return TRUE;
    RECT r;
    if (!GetWindowRect(hwnd, &r)) return TRUE;
    LONG w = r.right - r.left, h = r.bottom - r.top;
    if (w < 50 || h < 50) return TRUE;
    char cls[64] = {0};
    GetClassNameA(hwnd, cls, sizeof(cls)-1);
    if (strncmp(cls, "TMainForm", 9) == 0) {
        ctx->preferred = hwnd;
        return FALSE; /* found it; stop */
    }
    LONG area = w * h;
    if (area > ctx->best_area) {
        ctx->best = hwnd;
        ctx->best_area = area;
    }
    return TRUE;
}

static HWND find_canvas_hwnd(void) {
    click_pick_ctx_t ctx = {0};
    EnumWindows(click_pick_proc, (LPARAM)&ctx);
    return ctx.preferred ? ctx.preferred : ctx.best;
}

/* cmd_resize: force the canvas window to a specific CLIENT-AREA size.
 * The recording's clicks are fractions of recorded cw×ch (e.g. 1440×975).
 * If the live wine window is a different size, those fractions land on
 * the wrong UI elements. AdjustWindowRectEx computes the outer-window
 * rect that yields the requested client size; we then SetWindowPos to it.
 * args: "<w> <h>"
 */
static int cmd_resize(const char* args) {
    char* endp = NULL;
    int w = (int)strtol(args, &endp, 10);
    int h = (int)strtol(endp, &endp, 10);
    HWND target = find_canvas_hwnd();
    if (!target) {
        logmsg("resize: no canvas window yet");
        return -1;
    }
    DWORD style = (DWORD)GetWindowLongA(target, GWL_STYLE);
    DWORD ex_style = (DWORD)GetWindowLongA(target, GWL_EXSTYLE);
    BOOL has_menu = GetMenu(target) != NULL;
    RECT desired = {0, 0, w, h};
    if (!AdjustWindowRectEx(&desired, style, has_menu, ex_style)) {
        logmsg("resize: AdjustWindowRectEx failed gle=%lu", GetLastError());
        return -2;
    }
    int outer_w = desired.right - desired.left;
    int outer_h = desired.bottom - desired.top;
    if (!SetWindowPos(target, NULL, 0, 0, outer_w, outer_h,
                      SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE)) {
        logmsg("resize: SetWindowPos failed gle=%lu", GetLastError());
        return -3;
    }
    RECT got = {0};
    GetClientRect(target, &got);
    logmsg("resize: hwnd=%p client now %ldx%ld (requested %dx%d)",
           target, got.right, got.bottom, w, h);
    return 0;
}

/* cmd_click_post: PostMessage WM_LBUTTONDOWN/UP to the game's canvas at
 * given client-area coords. The game's normal Win32 dispatch handles
 * child hit-testing on the UI thread, so the click reaches whatever form
 * is on top — login, char-select, in-world — uniformly. No DLL-side VMT
 * dispatch, no thread races, no form detection.
 *
 * args: "<x> <y>" (decimal client-area pixels)
 */
static int cmd_click_post(const char* args) {
    char* endp = NULL;
    int x = (int)strtol(args, &endp, 10);
    int y = (int)strtol(endp, &endp, 10);
    HWND target = find_canvas_hwnd();
    if (!target) {
        logmsg("click_post: no canvas window yet (still loading?)");
        return -1;
    }
    char cls[64] = {0};
    GetClassNameA(target, cls, sizeof(cls)-1);
    LPARAM xy = (LPARAM)((y & 0xFFFF) << 16 | (x & 0xFFFF));
    if (!PostMessageA(target, WM_MOUSEMOVE, 0, xy) ||
        !PostMessageA(target, WM_LBUTTONDOWN, MK_LBUTTON, xy)) {
        logmsg("click_post: DOWN PostMessage failed gle=%lu",
               GetLastError());
        return -2;
    }
    Sleep(50);
    if (!PostMessageA(target, WM_LBUTTONUP, 0, xy)) {
        logmsg("click_post: UP PostMessage failed gle=%lu",
               GetLastError());
        return -3;
    }
    logmsg("click_post: posted (%d,%d) to hwnd=%p cls='%s'",
           x, y, target, cls);
    return 0;
}

/* cmd_click_dbl: double-click via PostMessage. Sequence is
 * DOWN/UP/DBLCLK/UP — Win32's "WM_LBUTTONDBLCLK fires on the second DOWN
 * when within DOUBLE_CLICK_TIME". Hardware events are auto-promoted by
 * the OS; synthetic PostMessage events are not, so we explicitly emit
 * WM_LBUTTONDBLCLK ourselves. Required for in-game UIs that gate
 * "enter world" / "open item" on a double-click. */
static int cmd_click_dbl(const char* args) {
    char* endp = NULL;
    int x = (int)strtol(args, &endp, 10);
    int y = (int)strtol(endp, &endp, 10);
    HWND target = find_canvas_hwnd();
    if (!target) {
        logmsg("click_dbl: no canvas window yet");
        return -1;
    }
    LPARAM xy = (LPARAM)((y & 0xFFFF) << 16 | (x & 0xFFFF));
    PostMessageA(target, WM_MOUSEMOVE, 0, xy);
    PostMessageA(target, WM_LBUTTONDOWN, MK_LBUTTON, xy);
    Sleep(20);
    PostMessageA(target, WM_LBUTTONUP, 0, xy);
    Sleep(40);
    PostMessageA(target, WM_LBUTTONDBLCLK, MK_LBUTTON, xy);
    Sleep(20);
    PostMessageA(target, WM_LBUTTONUP, 0, xy);
    logmsg("click_dbl: posted (%d,%d) to hwnd=%p", x, y, target);
    return 0;
}

static void* va2rt(uintptr_t va) {
    HMODULE h = GetModuleHandleA(NULL);
    if (!h) return NULL;
    return (void*)((uintptr_t)h + (va - IMG_BASE));
}

static void logmsg(const char* fmt, ...) {
    if (!logf) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(logf, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    vfprintf(logf, fmt, ap);
    va_end(ap);
    fputc('\n', logf);
    fflush(logf);
}

static void* get_active_widget(void) {
    void** p = (void**)va2rt(VA_ACTIVE_WIDGET);
    if (!p) return NULL;
    /* Be defensive — global may be NULL if char-select not currently active. */
    return *p;
}

/* Heap-scan for instances whose first u32 is one of the known class_info VAs.
 * Scans all committed, readable, R/W (non-executable) regions of the process. */
static void cmd_scan(void) {
    /* Three class_info VAs we care about (from forms_catalog.json) */
    uintptr_t targets[] = {
        0x000EE694,  /* TDncCharSelectShow */
        0x00152488,  /* TDncServerSelectForm */
        0x001499D4,  /* TDncCharCreateForm */
        0x00154CD4,  /* TDncRootWidget */
        0x000F3ABC,  /* TDncGameMainMenu */
        0x0011A444,  /* TMainForm */
    };
    const char* tnames[] = {
        "TDncCharSelectShow", "TDncServerSelectForm", "TDncCharCreateForm",
        "TDncRootWidget", "TDncGameMainMenu", "TMainForm",
    };
    int ntargets = sizeof(targets)/sizeof(targets[0]);
    SYSTEM_INFO si; GetSystemInfo(&si);
    logmsg("scan: scanning %p..%p for known VMT pointers...",
        si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress);
    BYTE* p = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* end = (BYTE*)0x7FFE0000;
    if (end > (BYTE*)si.lpMaximumApplicationAddress) end = (BYTE*)si.lpMaximumApplicationAddress;
    int hits[16] = {0};
    int regions_scanned = 0;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) break;
        BYTE* nxt = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        /* Mask out modifier bits: PAGE_GUARD=0x100, PAGE_NOCACHE=0x200, PAGE_WRITECOMBINE=0x400 */
        DWORD prot = mbi.Protect & 0xFF;
        int readable = (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                        prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                        prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        int has_guard = (mbi.Protect & PAGE_GUARD) != 0;
        /* Only scan MEM_PRIVATE (heap), skip MEM_IMAGE/MEM_MAPPED — widgets live on heap */
        if (mbi.State == MEM_COMMIT && readable && !has_guard &&
            mbi.Type == MEM_PRIVATE) {
            BYTE* rp = (BYTE*)mbi.BaseAddress;
            BYTE* re = nxt;
            regions_scanned++;
            for (BYTE* x = rp; x + 4 <= re; x += 4) {
                uint32_t v = *(uint32_t*)x;
                for (int i = 0; i < ntargets; i++) {
                    if (v == targets[i]) {
                        if (hits[i] < 5) {
                            logmsg("scan: instance @ %p VMT=0x%08x -> %s", x, v, tnames[i]);
                        }
                        hits[i]++;
                    }
                }
            }
        }
        p = nxt;
        if (nxt < (BYTE*)mbi.BaseAddress) break;
    }
    logmsg("scan: %d MEM_PRIVATE regions scanned", regions_scanned);
    for (int i = 0; i < ntargets; i++) {
        logmsg("scan: %s total hits=%d", tnames[i], hits[i]);
    }
}

static int cmd_probe(void) {
    void* widget = get_active_widget();
    logmsg("probe: VA_ACTIVE_WIDGET runtime=%p, *value=%p", va2rt(VA_ACTIVE_WIDGET), widget);
    if (!widget) {
        logmsg("probe: no active widget — char-select may not be open");
        return -1;
    }
    BYTE* slot_p = (BYTE*)widget + OFF_SLOT_BYTE;
    BYTE slot = *slot_p;
    logmsg("probe: widget=%p, [+0x7d]=%u (current slot)", widget, slot);

    BYTE* gidx_p = (BYTE*)va2rt(VA_ACTIVE_CHAR_IDX);
    logmsg("probe: global active-idx ptr=%p, *=%u", gidx_p, gidx_p ? *gidx_p : 0xFF);

    /* Dump 6 child slot pointers (button strip) */
    for (int off = 0x60; off <= 0x74; off += 4) {
        void* child = *(void**)((BYTE*)widget + off);
        logmsg("probe: widget+0x%02x = %p", off, child);
    }

    /* Dump first 0x100 bytes of widget for visual inspection */
    fprintf(logf, "    widget hexdump (first 0x100):\n");
    BYTE* b = (BYTE*)widget;
    for (int i = 0; i < 0x100; i += 16) {
        fprintf(logf, "    +%04x:", i);
        for (int j = 0; j < 16; j++) fprintf(logf, " %02x", b[i+j]);
        fprintf(logf, "\n");
    }
    fflush(logf);
    return 0;
}

static int cmd_pick_slot(int n) {
    void* widget = get_active_widget();
    if (!widget) { logmsg("pick_slot: no active widget"); return -1; }
    BYTE* slot_p = (BYTE*)widget + OFF_SLOT_BYTE;
    BYTE prev = *slot_p;
    *slot_p = (BYTE)n;
    /* VA 0x001C1678 holds a *pointer* to the active-slot byte (per
     * decomp of 0xf236c: `mov ecx, [0x1c1678]; mov [ecx], al`).
     * Earlier code treated it as the byte address directly which silently
     * corrupted a u32 at 0x1c1678 instead of the real slot global.
     * Dereference once to get the byte, then write. */
    uint32_t* gidx_pp = (uint32_t*)va2rt(VA_ACTIVE_CHAR_IDX);
    BYTE* gidx_p = NULL;
    if (gidx_pp) gidx_p = (BYTE*)(uintptr_t)*gidx_pp;
    if (gidx_p) {
        BYTE gprev = *gidx_p;
        *gidx_p = (BYTE)n;
        logmsg("pick_slot: %u -> %d (widget+0x7d); global *(*0x%08x)=%u -> %d",
               prev, n, (unsigned)VA_ACTIVE_CHAR_IDX, gprev, n);
    } else {
        logmsg("pick_slot: %u -> %d (widget+0x7d); WARN: global ptr at 0x%08x is NULL",
               prev, n, (unsigned)VA_ACTIVE_CHAR_IDX);
    }
    return 0;
}

static int cmd_start_game(void) {
    void* widget = get_active_widget();
    if (!widget) { logmsg("start_game: no active widget"); return -1; }

    /* Strategy: invoke the centred Start-Game button child via the per-child
     * dispatcher. Pack a synthetic message: low 16=x, high 16=y, both pointing
     * inside the centred button rect. Since we don't know exact rect yet,
     * use widget centre as a reasonable fallback (button is at the bottom). */
    void* child = *(void**)((BYTE*)widget + OFF_BTN_CHILD);
    logmsg("start_game: widget=%p, btn child @ +0x70 = %p", widget, child);

    fn_child_disp_t fn = (fn_child_disp_t)va2rt(VA_FN_CHILD_DISP);
    /* Default: dispatch with msg 0; this routes to the child by index path.
     * If that's a no-op we'll iterate. */
    int rc = fn(widget, 0);
    logmsg("start_game: FUN_000F1244(self, 0) -> %d", rc);

    /* Fallback A: use the InitCursorAndDispatch helper which seeds cursor and
     * re-enters the big switch. This may directly fire the "confirm" leaf. */
    fn_init_disp_t fn_init = (fn_init_disp_t)va2rt(VA_FN_INIT_DISP);
    rc = fn_init(widget);
    logmsg("start_game: FUN_000FE808(self) -> %d", rc);

    return 0;
}

/* ---------------------------------------------------------------------------
 * cmd_lua_chunk_probe: distinguish "decoder bug" vs "per-script env" hypothesis
 * for why goStart isn't reachable via lua_getglobal after ExecLuaScript.
 *
 * Snapshots the string keys of _G (LUA_GLOBALSINDEX) before and after calling
 * the engine's ExecLuaScript(script_id, false) at 0x147bb0 (load buffer only,
 * does NOT invoke ScriptMain). Diffs the two sets and logs new keys. Then
 * explicitly probes a fixed list of candidate names for type info.
 *
 * If the chunk DOES register globals into _G (we'll see new keys), then the
 * decoder may be wrong about goStart being a top-level function, OR something
 * else is interfering. If NO new keys appear, the engine likely uses
 * setfenv(chunk, per_script_env) before pcall, so chunk locals/funcs land in
 * a different environment table.
 *
 * Read-only Lua API: lua_next, lua_pushvalue, lua_pushnil, lua_tolstring,
 * lua_type, lua_settop, lua_gettop, lua_getfield. None mutate _G itself.
 * --------------------------------------------------------------------------- */

#define WM_DOM_LUA_CHUNK_PROBE  (WM_USER + 6)

#define LUA_CHUNK_PROBE_MAX_KEYS  4096
#define LUA_CHUNK_PROBE_KEY_BYTES 65536  /* pool for null-terminated key strings */

typedef struct lua_chunk_probe_request {
    uint32_t script_id;
} lua_chunk_probe_request_t;

typedef int  (__cdecl *lua_next_t)(void* L, int idx);
typedef void (__cdecl *lua_pushvalue_t)(void* L, int idx);
typedef void (__cdecl *lua_pushnil_t)(void* L);

typedef struct {
    char*   pool;
    size_t  pool_used;
    size_t  pool_cap;
    char**  keys;     /* array of pointers into pool */
    int     count;
    int     truncated;
} keyset_t;

static int keyset_init(keyset_t* ks) {
    ks->pool = (char*)malloc(LUA_CHUNK_PROBE_KEY_BYTES);
    ks->keys = (char**)malloc(sizeof(char*) * LUA_CHUNK_PROBE_MAX_KEYS);
    if (!ks->pool || !ks->keys) {
        free(ks->pool); free(ks->keys);
        ks->pool = NULL; ks->keys = NULL;
        return 0;
    }
    ks->pool_used = 0;
    ks->pool_cap = LUA_CHUNK_PROBE_KEY_BYTES;
    ks->count = 0;
    ks->truncated = 0;
    return 1;
}
static void keyset_free(keyset_t* ks) {
    free(ks->pool); free(ks->keys);
    ks->pool = NULL; ks->keys = NULL;
}
static int keyset_add(keyset_t* ks, const char* s, size_t slen) {
    if (ks->count >= LUA_CHUNK_PROBE_MAX_KEYS) { ks->truncated = 1; return 0; }
    if (ks->pool_used + slen + 1 > ks->pool_cap) { ks->truncated = 1; return 0; }
    char* dst = ks->pool + ks->pool_used;
    memcpy(dst, s, slen);
    dst[slen] = 0;
    ks->keys[ks->count++] = dst;
    ks->pool_used += slen + 1;
    return 1;
}
static int keyset_contains(const keyset_t* ks, const char* s) {
    for (int i = 0; i < ks->count; i++) {
        if (strcmp(ks->keys[i], s) == 0) return 1;
    }
    return 0;
}

/* Enumerate string keys of _G into ks. Stack-neutral: the iteration uses
 * lua_pushvalue(LUA_GLOBALSINDEX) + lua_pushnil + (lua_next+pop value) loop.
 * On return, stack is at top_before. */
static int snapshot_globals(void* L,
                            lua_pushvalue_t lua_pushvalue,
                            lua_pushnil_t lua_pushnil,
                            lua_next_t lua_next,
                            lua_type_t lua_type_fn,
                            lua_tolstring_t lua_tolstring,
                            lua_settop_t lua_settop,
                            lua_gettop_t lua_gettop,
                            keyset_t* ks)
{
    int t0 = lua_gettop(L);
    /* Push _G as a table on top so we can use relative index -2 inside loop. */
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    lua_pushnil(L);  /* initial key */
    /* Loop: lua_next(L, -2) pops the previous key and pushes (key,val) if any.
     * Returns 0 when done (key already popped). */
    int iters = 0;
    while (lua_next(L, -2) != 0) {
        iters++;
        if (iters > 100000) {
            /* paranoia: extreme upper bound to avoid spinning */
            lua_settop(L, t0);
            return -1;
        }
        /* Stack: [_G][key][val] (top). Read the key WITHOUT calling
         * lua_tolstring directly on a non-string — that would coerce numeric
         * keys to strings and break iteration. Filter on lua_type first. */
        int kt = lua_type_fn(L, -2);
        if (kt == 4 /* LUA_TSTRING */) {
            size_t slen = 0;
            const char* ks_str = lua_tolstring(L, -2, &slen);
            if (ks_str) keyset_add(ks, ks_str, slen);
        }
        /* Pop val, keep key for next iteration. */
        lua_settop(L, lua_gettop(L) - 1);
    }
    /* lua_next returned 0 — already popped the key. Pop _G. */
    lua_settop(L, t0);
    return 0;
}

static void ui_dispatch_lua_chunk_probe(lua_chunk_probe_request_t* req) {
    if (!req) return;

    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("ui_dispatch_lua_chunk_probe: ExecLuaScript fn_rt=%p not readable — drop", fn_rt);
        free(req);
        return;
    }

    /* Resolve all needed Lua APIs. */
    lua_tolstring_t  lua_tolstring  = (lua_tolstring_t) resolve_lua_fn("lua_tolstring");
    lua_settop_t     lua_settop     = (lua_settop_t)    resolve_lua_fn("lua_settop");
    lua_gettop_t     lua_gettop     = (lua_gettop_t)    resolve_lua_fn("lua_gettop");
    lua_type_t       lua_type_fn    = (lua_type_t)      resolve_lua_fn("lua_type");
    lua_next_t       lua_next       = (lua_next_t)      resolve_lua_fn("lua_next");
    lua_pushvalue_t  lua_pushvalue  = (lua_pushvalue_t) resolve_lua_fn("lua_pushvalue");
    lua_pushnil_t    lua_pushnil    = (lua_pushnil_t)   resolve_lua_fn("lua_pushnil");
    lua_getfield_t   lua_getfield   = (lua_getfield_t)  resolve_lua_fn("lua_getfield");
    if (!lua_tolstring || !lua_settop || !lua_gettop || !lua_type_fn ||
        !lua_next || !lua_pushvalue || !lua_pushnil || !lua_getfield) {
        logmsg("[lua_chunk_probe] lua API resolve FAILED — "
               "tolstring=%p settop=%p gettop=%p type=%p next=%p pushvalue=%p "
               "pushnil=%p getfield=%p",
               lua_tolstring, lua_settop, lua_gettop, lua_type_fn,
               lua_next, lua_pushvalue, lua_pushnil, lua_getfield);
        free(req);
        return;
    }

    void* L = resolve_lua_state();
    if (!L) {
        logmsg("[lua_chunk_probe] lua_State* unresolved — abort");
        free(req);
        return;
    }
    int top_before = lua_gettop(L);
    logmsg("[lua_chunk_probe] tid=%lu script_id=%u (0x%x) L=%p top_before=%d",
           GetCurrentThreadId(), req->script_id, req->script_id, L, top_before);

    keyset_t before, after;
    if (!keyset_init(&before)) {
        logmsg("[lua_chunk_probe] keyset_init(before) OOM");
        free(req); return;
    }
    if (!keyset_init(&after)) {
        logmsg("[lua_chunk_probe] keyset_init(after) OOM");
        keyset_free(&before);
        free(req); return;
    }

    /* === Snapshot BEFORE === */
    int rc = snapshot_globals(L, lua_pushvalue, lua_pushnil, lua_next,
                              lua_type_fn, lua_tolstring, lua_settop, lua_gettop,
                              &before);
    if (rc != 0) {
        logmsg("[lua_chunk_probe] snapshot BEFORE bailed (iter cap)");
        keyset_free(&before); keyset_free(&after);
        lua_settop(L, top_before);
        free(req); return;
    }
    logmsg("[lua_chunk_probe] BEFORE: %d string keys%s",
           before.count, before.truncated ? " [TRUNCATED]" : "");

    /* === Call ExecLuaScript(script_id, false) — load buffer, no ScriptMain.
     * Identical trampoline as cmd_lua_exec. */
    g_lua_script_id   = req->script_id;
    g_lua_invoke_main = 0;  /* dl=0 -> just luaL_loadbuffer, no ScriptMain pcall */
    g_lua_fn          = (uint32_t)fn_rt;
    g_lua_ret_al      = 0;

    logmsg("[lua_chunk_probe] calling ExecLuaScript(%u, dl=0) ...", req->script_id);
    call_exec_lua_script();
    logmsg("[lua_chunk_probe] ExecLuaScript returned al=%u", g_lua_ret_al);

    /* The buffer-load path leaves the loaded chunk as a function on the Lua
     * stack (that's how luaL_loadbuffer works). To register top-level globals,
     * the chunk must be pcall'd. ScriptMain wasn't invoked because dl=0.
     *
     * For this probe we have two snapshots to take:
     *   (a) RIGHT AFTER load (no chunk pcall) — should be identical to before;
     *       confirms that load alone doesn't register any globals.
     *   (b) AFTER also pcall'ing the loaded chunk — that's what would actually
     *       register top-level functions per Lua semantics (`function goStart()`
     *       is sugar for `goStart = function() ... end` which executes at
     *       chunk eval time).
     *
     * Use Lua-level Lua.ExecLuaScript(id, false) instead — same as npc_open
     * step1 — because that DOES pcall the chunk (per script 27's usage). */

    /* Restore stack from any leftover from the C-level call. */
    int top_after_c = lua_gettop(L);
    if (top_after_c != top_before) {
        logmsg("[lua_chunk_probe] stack drift after C ExecLuaScript: top %d -> %d, restoring",
               top_before, top_after_c);
        lua_settop(L, top_before);
    }

    /* Now do the Lua-level Lua.ExecLuaScript(id, false) which pcalls the chunk. */
    typedef void (__cdecl *lua_pushinteger_t)(void* L, ptrdiff_t n);
    typedef void (__cdecl *lua_pushboolean_t)(void* L, int b);
    typedef int  (__cdecl *lua_pcall_t2)(void* L, int nargs, int nresults, int errfunc);
    lua_pushinteger_t lua_pushinteger = (lua_pushinteger_t)resolve_lua_fn("lua_pushinteger");
    lua_pushboolean_t lua_pushboolean = (lua_pushboolean_t)resolve_lua_fn("lua_pushboolean");
    lua_pcall_t2      lua_pcall       = (lua_pcall_t2)     resolve_lua_fn("lua_pcall");
    if (!lua_pushinteger || !lua_pushboolean || !lua_pcall) {
        logmsg("[lua_chunk_probe] missing pushinteger/pushboolean/pcall");
        keyset_free(&before); keyset_free(&after);
        lua_settop(L, top_before);
        free(req); return;
    }

    lua_getfield(L, LUA_GLOBALSINDEX, "Lua");
    int t_lua = lua_type_fn(L, -1);
    if (t_lua != 5 /* TABLE */) {
        logmsg("[lua_chunk_probe] 'Lua' global type=%d (expected 5) — abort",
               t_lua);
        keyset_free(&before); keyset_free(&after);
        lua_settop(L, top_before);
        free(req); return;
    }
    lua_getfield(L, -1, "ExecLuaScript");
    int t_exec = lua_type_fn(L, -1);
    if (t_exec != 6 /* FN */) {
        logmsg("[lua_chunk_probe] Lua.ExecLuaScript type=%d (expected 6) — abort",
               t_exec);
        keyset_free(&before); keyset_free(&after);
        lua_settop(L, top_before);
        free(req); return;
    }
    lua_pushinteger(L, (ptrdiff_t)req->script_id);
    lua_pushboolean(L, 0);
    int prc = lua_pcall(L, 2, 0, 0);
    if (prc != 0) {
        int t = -99;
        char* errstr = drain_lua_error(L, lua_tolstring, lua_type_fn, &t);
        logmsg("[lua_chunk_probe] Lua.ExecLuaScript(%u,false) FAILED rc=%d type=%d err=%s",
               req->script_id, prc, t, errstr ? errstr : "(none)");
        if (errstr) free(errstr);
        keyset_free(&before); keyset_free(&after);
        lua_settop(L, top_before);
        free(req); return;
    }
    /* Pop the leftover Lua-table that lua_pcall didn't consume. */
    lua_settop(L, top_before);
    logmsg("[lua_chunk_probe] Lua.ExecLuaScript(%u,false) OK — chunk pcall'd",
           req->script_id);

    /* === Snapshot AFTER === */
    rc = snapshot_globals(L, lua_pushvalue, lua_pushnil, lua_next,
                          lua_type_fn, lua_tolstring, lua_settop, lua_gettop,
                          &after);
    if (rc != 0) {
        logmsg("[lua_chunk_probe] snapshot AFTER bailed (iter cap)");
        keyset_free(&before); keyset_free(&after);
        lua_settop(L, top_before);
        free(req); return;
    }
    logmsg("[lua_chunk_probe] AFTER: %d string keys%s",
           after.count, after.truncated ? " [TRUNCATED]" : "");

    /* === Diff: keys in AFTER not in BEFORE === */
    int new_count = 0;
    /* Log up to 64 new keys; rest just counted. */
    char joined[1024]; size_t jpos = 0; joined[0] = 0;
    for (int i = 0; i < after.count; i++) {
        if (!keyset_contains(&before, after.keys[i])) {
            new_count++;
            if (new_count <= 64) {
                size_t klen = strlen(after.keys[i]);
                if (jpos + klen + 3 < sizeof(joined)) {
                    if (jpos > 0) { joined[jpos++] = ','; joined[jpos++] = ' '; }
                    memcpy(joined + jpos, after.keys[i], klen);
                    jpos += klen;
                    joined[jpos] = 0;
                }
            }
        }
    }
    logmsg("[lua_chunk_probe] DIFF: %d new globals after chunk eval", new_count);
    if (new_count > 0) {
        logmsg("[lua_chunk_probe] DIFF first<=64 keys: %s%s",
               joined, new_count > 64 ? " ...[truncated]" : "");
    }

    /* Also log a few keys in BEFORE that are NOT in AFTER (would indicate
     * something cleared globals — diagnostic completeness). */
    int gone_count = 0;
    char gone_joined[512]; size_t gpos = 0; gone_joined[0] = 0;
    for (int i = 0; i < before.count; i++) {
        if (!keyset_contains(&after, before.keys[i])) {
            gone_count++;
            if (gone_count <= 16) {
                size_t klen = strlen(before.keys[i]);
                if (gpos + klen + 3 < sizeof(gone_joined)) {
                    if (gpos > 0) { gone_joined[gpos++] = ','; gone_joined[gpos++] = ' '; }
                    memcpy(gone_joined + gpos, before.keys[i], klen);
                    gpos += klen;
                    gone_joined[gpos] = 0;
                }
            }
        }
    }
    if (gone_count > 0) {
        logmsg("[lua_chunk_probe] keys REMOVED from _G: %d (first<=16: %s)",
               gone_count, gone_joined);
    } else {
        logmsg("[lua_chunk_probe] keys REMOVED from _G: 0");
    }

    /* === Probe candidate names explicitly === */
    static const char* kCandidates[] = {
        "goStart", "XenGuide", "goGuide", "Item_Info",
        "Map_Guide", "goMilk", "goQuest", "Finish",
        "Init_Show", "SetMsg", "ScriptMain", "MAIN",
        NULL
    };
    for (int i = 0; kCandidates[i]; i++) {
        lua_getfield(L, LUA_GLOBALSINDEX, kCandidates[i]);
        int t = lua_type_fn(L, -1);
        logmsg("[lua_chunk_probe] candidate '%s' type=%d (0=nil 4=str 5=tbl 6=fn)",
               kCandidates[i], t);
        lua_settop(L, lua_gettop(L) - 1);  /* pop */
    }

    /* === Restore stack === */
    int top_final = lua_gettop(L);
    if (top_final != top_before) {
        logmsg("[lua_chunk_probe] cleanup: top %d != top_before %d, restoring",
               top_final, top_before);
        lua_settop(L, top_before);
    }
    logmsg("[lua_chunk_probe] DONE: top %d -> %d  before=%d after=%d new=%d removed=%d",
           top_before, lua_gettop(L), before.count, after.count, new_count, gone_count);

    keyset_free(&before);
    keyset_free(&after);
    free(req);
}

static int cmd_lua_chunk_probe(const char* args) {
    while (*args == ' ' || *args == '\t') args++;
    if (!*args) { logmsg("lua_chunk_probe: missing script_id"); return -1; }
    char* endp = NULL;
    unsigned long sid = strtoul(args, &endp, 0);
    if (!endp || endp == args) {
        logmsg("lua_chunk_probe: bad script_id '%s'", args); return -2;
    }
    if (sid > 0xFFFFFFFFul) { logmsg("lua_chunk_probe: script_id out of range"); return -3; }

    void* fn_rt = va2rt(VA_FN_EXEC_LUA_SCRIPT);
    if (!fn_rt || !mem_readable((uintptr_t)fn_rt, 4)) {
        logmsg("lua_chunk_probe: ExecLuaScript@VA 0x%x not resolvable",
               VA_FN_EXEC_LUA_SCRIPT);
        return -4;
    }
    logmsg("[lua_chunk_probe] script_id=%lu (0x%lx) fn_rt=0x%08x",
           sid, sid, (unsigned)(uintptr_t)fn_rt);
    if (!ensure_ui_subclass()) {
        logmsg("lua_chunk_probe: UI subclass not ready");
        return -5;
    }
    lua_chunk_probe_request_t* req =
        (lua_chunk_probe_request_t*)calloc(1, sizeof(*req));
    if (!req) { logmsg("lua_chunk_probe: OOM"); return -6; }
    req->script_id = (uint32_t)sid;
    if (!PostMessageA(g_ui_hwnd, WM_DOM_LUA_CHUNK_PROBE, 0, (LPARAM)req)) {
        logmsg("lua_chunk_probe: PostMessage failed gle=%lu", GetLastError());
        free(req);
        return -7;
    }
    logmsg("[lua_chunk_probe] posted to UI thread");
    return 0;
}

static void process_command(const char* line) {
    if (strncmp(line, "enum_windows", 12) == 0) {
        cmd_enum_windows();
    } else if (strncmp(line, "resize ", 7) == 0) {
        cmd_resize(line + 7);
    } else if (strncmp(line, "scan", 4) == 0) {
        cmd_scan();
    } else if (strncmp(line, "probe", 5) == 0) {
        cmd_probe();
    } else if (strncmp(line, "pick_slot ", 10) == 0) {
        int n = atoi(line + 10);
        cmd_pick_slot(n);
    } else if (strncmp(line, "start_game", 10) == 0) {
        cmd_start_game();
    } else if (strncmp(line, "click_addr ", 11) == 0) {
        cmd_click_addr(line + 11);
    } else if (strncmp(line, "click_path ", 11) == 0) {
        cmd_click_path(line + 11);
    } else if (strncmp(line, "click_xy ", 9) == 0) {
        cmd_click_xy(line + 9);
    } else if (strncmp(line, "click_post ", 11) == 0) {
        cmd_click_post(line + 11);
    } else if (strncmp(line, "click_dbl ", 10) == 0) {
        cmd_click_dbl(line + 10);
    } else if (strncmp(line, "invoke ", 7) == 0) {
        cmd_invoke(line + 7);
    } else if (strncmp(line, "set_byte ", 9) == 0) {
        cmd_set_byte(line + 9);
    } else if (strncmp(line, "call_vmt ", 9) == 0) {
        cmd_call_vmt(line + 9);
    } else if (strncmp(line, "lua_chunk_probe ", 16) == 0) {
        cmd_lua_chunk_probe(line + 16);
    } else if (strncmp(line, "lua_exec_diag ", 14) == 0) {
        cmd_lua_exec_diag(line + 14);
    } else if (strncmp(line, "lua_exec ", 9) == 0) {
        cmd_lua_exec(line + 9);
    } else if (strncmp(line, "npc_open ", 9) == 0) {
        cmd_npc_open(line + 9);
    } else if (strncmp(line, "noop", 4) == 0) {
        cmd_noop(line + 4);
    } else {
        logmsg("unknown cmd: '%s'", line);
    }
}

static DWORD WINAPI poll_loop(LPVOID arg) {
    char last_seen[512] = {0};
    char buf[512];
    logmsg("poll_loop: started; watching C:\\dom_cmd.txt");
    while (!stop_flag) {
        Sleep(200);
        FILE* f = fopen("C:\\dom_cmd.txt", "r");
        if (!f) continue;
        if (!fgets(buf, sizeof(buf), f)) { fclose(f); continue; }
        fclose(f);
        size_t n = strlen(buf);
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' ')) buf[--n] = 0;
        if (n == 0) continue;
        if (strcmp(buf, last_seen) == 0) continue;
        strncpy(last_seen, buf, sizeof(last_seen)-1);
        logmsg("cmd received: '%s'", buf);
        process_command(buf);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(hModule);
    logf = fopen("C:\\dom_replay.log", "a");
    if (logf) {
        HMODULE h = GetModuleHandleA(NULL);
        logmsg("=== dom_replay.dll attached ===");
        logmsg("DXRender module base = %p (preferred 0x%x)", h, IMG_BASE);
        logmsg("VAs adjusted: ACTIVE_WIDGET=%p MOUSE=%p CHILD_DISP=%p INIT_DISP=%p",
            va2rt(VA_ACTIVE_WIDGET), va2rt(VA_FN_MOUSE),
            va2rt(VA_FN_CHILD_DISP), va2rt(VA_FN_INIT_DISP));
    }
    poll_thread = CreateThread(NULL, 0, poll_loop, NULL, 0, NULL);
    return TRUE;
}
