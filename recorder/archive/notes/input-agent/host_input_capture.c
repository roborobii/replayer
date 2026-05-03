#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static HHOOK g_mh, g_kh;
static SOCKET g_sock = INVALID_SOCKET;
static char g_relay_host[64] = "192.168.12.148";
static int g_relay_port = 19998;
static HWND g_vm_hwnd = NULL;
static CRITICAL_SECTION g_lock;

static uint64_t now_ms(void) {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ULL) / 10000ULL;
}

static int proc_is_vmconnect(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    char name[MAX_PATH] = {0};
    DWORD sz = MAX_PATH;
    int ok = 0;
    if (QueryFullProcessImageNameA(h, 0, name, &sz)) {
        char *base = strrchr(name, '\\');
        base = base ? base + 1 : name;
        if (_stricmp(base, "vmconnect.exe") == 0) ok = 1;
    }
    CloseHandle(h);
    return ok;
}

static BOOL CALLBACK enum_cb(HWND hwnd, LPARAM lp) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    char title[256] = {0}, cls[128] = {0};
    GetWindowTextA(hwnd, title, sizeof(title));
    GetClassNameA(hwnd, cls, sizeof(cls));
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    int title_match = (strstr(title, "Virtual Machine") != NULL) ||
                      (strstr(title, "Hyper-V") != NULL) ||
                      (strstr(title, "Elf") != NULL && strstr(title, "Connection") != NULL);
    if (title_match && proc_is_vmconnect(pid)) {
        *(HWND *)lp = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND find_vm_window(void) {
    HWND found = NULL;
    EnumWindows(enum_cb, (LPARAM)&found);
    return found;
}

static void try_connect(void) {
    if (g_sock != INVALID_SOCKET) return;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(g_relay_port);
    inet_pton(AF_INET, g_relay_host, &sa.sin_addr);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        return;
    }
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
    g_sock = s;
    fprintf(stderr, "[capture] connected to %s:%d\n", g_relay_host, g_relay_port);
}

static void send_line(const char *buf, int len) {
    EnterCriticalSection(&g_lock);
    try_connect();
    if (g_sock != INVALID_SOCKET) {
        int n = send(g_sock, buf, len, 0);
        if (n <= 0) {
            closesocket(g_sock);
            g_sock = INVALID_SOCKET;
        }
    }
    LeaveCriticalSection(&g_lock);
}

static void emit_mouse(const char *action, const char *btn, int x, int y) {
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
        "{\"type\":\"mouse\",\"action\":\"%s\",\"button\":\"%s\",\"x\":%d,\"y\":%d,\"ts\":%llu}\n",
        action, btn, x, y, (unsigned long long)now_ms());
    send_line(buf, n);
}

static void emit_key(const char *action, int vk) {
    char buf[160];
    int n = snprintf(buf, sizeof(buf),
        "{\"type\":\"key\",\"action\":\"%s\",\"vk\":%d,\"ts\":%llu}\n",
        action, vk, (unsigned long long)now_ms());
    send_line(buf, n);
}

static int foreground_is_vm(void) {
    HWND fg = GetForegroundWindow();
    if (!fg) return 0;
    if (g_vm_hwnd && fg == g_vm_hwnd) return 1;
    HWND root = GetAncestor(fg, GA_ROOT);
    return (g_vm_hwnd && root == g_vm_hwnd);
}

static LRESULT CALLBACK mouse_proc(int code, WPARAM w, LPARAM l) {
    if (code == HC_ACTION && foreground_is_vm()) {
        MSLLHOOKSTRUCT *m = (MSLLHOOKSTRUCT *)l;
        POINT pt = m->pt;
        ScreenToClient(g_vm_hwnd, &pt);
        switch (w) {
            case WM_LBUTTONDOWN: emit_mouse("down", "L", pt.x, pt.y); break;
            case WM_LBUTTONUP:   emit_mouse("up",   "L", pt.x, pt.y); break;
            case WM_RBUTTONDOWN: emit_mouse("down", "R", pt.x, pt.y); break;
            case WM_RBUTTONUP:   emit_mouse("up",   "R", pt.x, pt.y); break;
            case WM_MBUTTONDOWN: emit_mouse("down", "M", pt.x, pt.y); break;
            case WM_MBUTTONUP:   emit_mouse("up",   "M", pt.x, pt.y); break;
            case WM_MOUSEMOVE:   emit_mouse("move", "L", pt.x, pt.y); break;
        }
    }
    return CallNextHookEx(NULL, code, w, l);
}

static LRESULT CALLBACK key_proc(int code, WPARAM w, LPARAM l) {
    if (code == HC_ACTION && foreground_is_vm()) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)l;
        if (w == WM_KEYDOWN || w == WM_SYSKEYDOWN) emit_key("down", (int)k->vkCode);
        else if (w == WM_KEYUP || w == WM_SYSKEYUP) emit_key("up", (int)k->vkCode);
    }
    return CallNextHookEx(NULL, code, w, l);
}

static DWORD WINAPI refresh_thread(LPVOID arg) {
    (void)arg;
    for (;;) {
        HWND h = find_vm_window();
        if (h && h != g_vm_hwnd) {
            g_vm_hwnd = h;
            char title[256] = {0};
            GetWindowTextA(h, title, sizeof(title));
            fprintf(stderr, "[capture] VM hwnd=%p title=\"%s\"\n", (void *)h, title);
        } else if (!h && g_vm_hwnd) {
            fprintf(stderr, "[capture] VM hwnd lost\n");
            g_vm_hwnd = NULL;
        }
        Sleep(3000);
    }
}

int main(int argc, char **argv) {
    if (argc >= 2) strncpy(g_relay_host, argv[1], sizeof(g_relay_host) - 1);
    if (argc >= 3) g_relay_port = atoi(argv[2]);
    fprintf(stderr, "[capture] relay=%s:%d\n", g_relay_host, g_relay_port);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&g_lock);

    g_vm_hwnd = find_vm_window();
    if (g_vm_hwnd) {
        char title[256] = {0};
        GetWindowTextA(g_vm_hwnd, title, sizeof(title));
        fprintf(stderr, "[capture] found VM hwnd=%p title=\"%s\"\n", (void *)g_vm_hwnd, title);
    } else {
        fprintf(stderr, "[capture] no VM window yet; will keep retrying\n");
    }
    CreateThread(NULL, 0, refresh_thread, NULL, 0, NULL);

    g_mh = SetWindowsHookEx(WH_MOUSE_LL, mouse_proc, GetModuleHandle(NULL), 0);
    g_kh = SetWindowsHookEx(WH_KEYBOARD_LL, key_proc, GetModuleHandle(NULL), 0);
    if (!g_mh || !g_kh) {
        fprintf(stderr, "[capture] SetWindowsHookEx failed: %lu\n", GetLastError());
        return 1;
    }
    fprintf(stderr, "[capture] hooks installed; running message loop\n");

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
