#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * chatcmd.dll - Send a chat command to the game server via the world socket.
 *
 * Reads command from C:\cmd.txt (written before injection).
 * Finds the world socket (connected to 127.0.0.1:18123) by scanning fds.
 * Builds a chat packet (opcode 0xBA) and sends it.
 * Writes result to C:\chatcmd.log.
 *
 * Packet layout (client -> server, opcode 0xBA = 186):
 *   [0-1]  u16 LE  payload_size = msg_len + 8
 *   [2]    0xBA    opcode
 *   [3-7]  5 bytes session header (zeros work fine)
 *   [8]    0x11    chat_type = 17 (general chat)
 *   [9]    u8      msg_len
 *   [10+]  bytes   message text (ASCII)
 */

static int find_world_socket(FILE* f) {
    /* Scan fd range 1..4096 looking for a connected TCP socket to 127.0.0.1:18123 */
    for (int fd = 1; fd < 4096; fd++) {
        struct sockaddr_in addr;
        int addrlen = sizeof(addr);
        if (getpeername((SOCKET)fd, (struct sockaddr*)&addr, &addrlen) == 0) {
            if (addr.sin_family == AF_INET &&
                ntohs(addr.sin_port) == 18123 &&
                addr.sin_addr.s_addr == 0x0200007F) {
                fprintf(f, "Found world socket: fd=%d (127.0.0.2:18123)\n", fd);
                return fd;
            }
        }
    }
    return -1;
}

static int read_cmd(char* buf, int maxlen) {
    FILE* f = fopen("C:\\cmd.txt", "r");
    if (!f) return 0;
    int len = (int)fread(buf, 1, maxlen - 1, f);
    fclose(f);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' '))
        len--;
    buf[len] = '\0';
    return len;
}

void CALLBACK SendTimer(HWND hwnd, UINT msg, UINT_PTR id, DWORD tick) {
    KillTimer(hwnd, id);
    FILE* f = fopen("C:\\chatcmd.log", "w");
    if (!f) return;
    fprintf(f, "=== chatcmd.dll ===\n");

    char cmd[256] = {0};
    int cmd_len = read_cmd(cmd, sizeof(cmd));
    if (cmd_len <= 0) {
        fprintf(f, "ERROR: C:\\cmd.txt is empty or missing\n");
        fclose(f); return;
    }
    fprintf(f, "Command: '%s' (%d bytes)\n", cmd, cmd_len);

    int world_fd = find_world_socket(f);
    if (world_fd < 0) {
        fprintf(f, "ERROR: World socket not found (port 18123)\n");
        fclose(f); return;
    }

    /* Build chat packet */
    int pkt_size = 10 + cmd_len;
    unsigned char* pkt = (unsigned char*)malloc(pkt_size);
    if (!pkt) { fprintf(f, "malloc failed\n"); fclose(f); return; }
    memset(pkt, 0, pkt_size);

    /* [0-1] = payload size (total - 2) */
    unsigned short payload = (unsigned short)(pkt_size - 2);
    pkt[0] = (unsigned char)(payload & 0xFF);
    pkt[1] = (unsigned char)((payload >> 8) & 0xFF);

    pkt[2] = 0xBA;     /* opcode: chat message */
    /* [3-7] = 0 (session header, server doesn't validate for chat) */
    pkt[8] = 0x11;     /* chat_type = 17 = general chat */
    pkt[9] = (unsigned char)cmd_len;
    memcpy(pkt + 10, cmd, cmd_len);

    fprintf(f, "Packet (%d bytes):", pkt_size);
    for (int i = 0; i < pkt_size; i++) fprintf(f, " %02x", pkt[i]);
    fprintf(f, "\n");

    int sent = send((SOCKET)world_fd, (char*)pkt, pkt_size, 0);
    fprintf(f, "send() = %d (expected %d)\n", sent, pkt_size);
    if (sent == pkt_size)
        fprintf(f, "OK: command sent\n");
    else
        fprintf(f, "WARN: partial send or error (WSAGetLastError=%d)\n", WSAGetLastError());

    free(pkt);
    fclose(f);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    HWND hwnd = FindWindowA("TMainForm", "Secret of the Solstice");
    if (hwnd)
        SetTimer(hwnd, 6001, 100, SendTimer);
    return TRUE;
}
