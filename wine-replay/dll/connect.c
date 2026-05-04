#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * connect.dll - Installs a socket into the game's ConnMgr and sends D3 login.
 *
 * Reads token from C:\token.txt (written by reload script before injection).
 * Connects to SVC server at 127.0.0.1:1819.
 *
 * ConnMgr layout:
 *   [0x54D228] -> ptr -> ConnMgr object
 *   mgr+0x14  = socket
 *   mgr+0x18  = recv poll list (count + socket array)
 *   mgr+0x492C = connected flag
 */

static FILE* g_log = NULL;

static int read_token(char* buf, int maxlen) {
    FILE* f = fopen("C:\\token.txt", "r");
    if (!f) return 0;
    int len = (int)fread(buf, 1, maxlen - 1, f);
    fclose(f);
    // Strip trailing whitespace/newlines
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' '))
        len--;
    buf[len] = '\0';
    return len;
}

void CALLBACK ConnectTimer(HWND hwnd, UINT msg, UINT_PTR id, DWORD tick) {
    KillTimer(hwnd, id);
    g_log = fopen("C:\\connect.log", "a");
    if (!g_log) return;
    fprintf(g_log, "\n=== ConnectTimer on main thread ===\n");

    // Read token
    char token[17] = {0};
    int token_len = read_token(token, sizeof(token));
    fprintf(g_log, "Token: '%s' (len=%d)\n", token, token_len);
    if (token_len == 0) {
        fprintf(g_log, "ERROR: No token in C:\\token.txt\n");
        fclose(g_log); return;
    }

    void** p_mgr_var = (void**)0x54D228;
    unsigned char* mgr = (unsigned char*)*(void**)*p_mgr_var;
    if (!mgr) { fprintf(g_log, "No mgr!\n"); fclose(g_log); return; }

    // Close old socket
    int old = *(int*)(mgr + 0x14);
    if (old > 0) { closesocket((SOCKET)old); }

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    fprintf(g_log, "socket=%d\n", (int)sock);

    // Set socket options (match game exactly)
    int zero = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&zero, sizeof(zero));
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));

    // Connect to SVC server (blocking)
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1819);
    addr.sin_addr.s_addr = 0x0200007F;  // 127.0.0.2

    fprintf(g_log, "Connecting to 127.0.0.2:1819...\n"); fflush(g_log);
    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0) {
        fprintf(g_log, "FAILED: %d\n", WSAGetLastError());
        closesocket(sock); fclose(g_log); return;
    }
    fprintf(g_log, "Connected!\n");

    // Send D3 login with real token
    // Packet: [size_lo][size_hi][0xD3][20 zero bytes][16-byte token]
    // Total = 2 (size) + 1 (opcode) + 20 (padding) + 16 (token) = 39
    unsigned char d3_pkt[39];
    memset(d3_pkt, 0, sizeof(d3_pkt));
    d3_pkt[0] = 37; d3_pkt[1] = 0;  // payload size = 37
    d3_pkt[2] = 0xD3;               // opcode
    // Bytes 3-22: zeros (padding/username field)
    // Bytes 23-38: token (16 bytes max)
    int copy_len = token_len > 16 ? 16 : token_len;
    memcpy(d3_pkt + 23, token, copy_len);
    send(sock, (char*)d3_pkt, 39, 0);
    fprintf(g_log, "Sent D3 with token\n");

    // Switch to non-blocking (matching game's connect method)
    unsigned long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);
    fprintf(g_log, "Set non-blocking\n");

    // Install socket in manager
    *(int*)(mgr + 0x14) = (int)sock;

    // Add socket to recv poll list at [mgr+0x18]
    unsigned int* recv_list = (unsigned int*)(mgr + 0x18);
    unsigned int count = recv_list[0];
    if (count < 64) {
        recv_list[count + 1] = (unsigned int)sock;
        recv_list[0] = count + 1;
        fprintf(g_log, "Added socket to recv list (count=%d)\n", count + 1);
    }

    // Clear state
    *(int*)(mgr + 0x10) = 0;
    *(int*)(mgr + 0x491C) = 0;
    *(int*)(mgr + 0x4920) = 0;

    // Set connected flags
    mgr[0x4948] = 0;
    mgr[0x492C] = 1;  // CONNECTED
    *(unsigned int*)(mgr + 0x4930) = GetTickCount() - 50;

    fprintf(g_log, "Done! socket=%d, connected=%d\n",
            *(int*)(mgr+0x14), mgr[0x492C]);
    fprintf(g_log, "Recv list count=%d\n", *(unsigned int*)(mgr + 0x18));

    fclose(g_log); g_log = NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    g_log = fopen("C:\\connect.log", "w");
    if (!g_log) return TRUE;
    fprintf(g_log, "=== connect.dll loaded ===\n");

    HWND hwnd = FindWindowA("TMainForm", "Secret of the Solstice");
    if (hwnd) {
        fprintf(g_log, "hwnd=0x%08x\n", (unsigned)hwnd);
        SetTimer(hwnd, 9999, 200, ConnectTimer);
    } else {
        fprintf(g_log, "ERROR: Game window not found!\n");
    }
    fclose(g_log); g_log = NULL;
    return TRUE;
}
