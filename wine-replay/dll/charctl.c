#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * charctl.dll - Sends D5 (create character) on the game's existing socket.
 * Only creates if no characters exist (checks char count at 0x59F450).
 * Then sends D7 (load into game) after a short delay.
 */

static FILE* g_log = NULL;

void CALLBACK LoadGameTimer(HWND hwnd, UINT msg, UINT_PTR id, DWORD tick);

void CALLBACK CharTimer(HWND hwnd, UINT msg, UINT_PTR id, DWORD tick) {
    KillTimer(hwnd, id);
    g_log = fopen("C:\\charctl.log", "w");
    if (!g_log) return;

    void** p_mgr_var = (void**)0x54D228;
    unsigned char* mgr = (unsigned char*)*(void**)*p_mgr_var;
    if (!mgr) { fprintf(g_log, "No mgr!\n"); fclose(g_log); return; }

    SOCKET sock = (SOCKET)*(int*)(mgr + 0x14);
    fprintf(g_log, "Socket=%d, connected_flag=%d\n", (int)sock, mgr[0x492C]);

    // Note: after connect.dll sends D3 and the game processes the response,
    // the game's own handler may reset 0x492C. The socket is still valid.
    // So we only check the socket, not the connected flag.
    if (sock <= 0) {
        fprintf(g_log, "No socket!\n");
        fclose(g_log); return;
    }

    // Check if characters already exist
    unsigned char char_count = *(unsigned char*)0x59F450;
    fprintf(g_log, "Existing char count: %d\n", char_count);

    if (char_count == 0) {
        // Send D5 - Create character
        unsigned char d5_pkt[46];
        memset(d5_pkt, 0, sizeof(d5_pkt));
        d5_pkt[0] = 44; d5_pkt[1] = 0;      // size = 44
        d5_pkt[2] = 0xD5;                     // opcode
        d5_pkt[3] = 0;                         // char_id = 0 (first slot)
        memcpy(d5_pkt + 4, "Hero", 4);        // name
        d5_pkt[17] = 1;                        // level
        d5_pkt[18] = 127; d5_pkt[19] = 0;     // world IP
        d5_pkt[20] = 0;   d5_pkt[21] = 1;
        d5_pkt[22] = 10;                       // POW
        d5_pkt[23] = 10;                       // STA
        d5_pkt[24] = 10;                       // AGI
        d5_pkt[25] = 10;                       // INT
        d5_pkt[26] = 10;                       // MEN
        d5_pkt[27] = 10;                       // WIS
        d5_pkt[28] = 128;                      // sex = male
        d5_pkt[31] = 11;                       // hair

        int sent = send(sock, (char*)d5_pkt, 46, 0);
        fprintf(g_log, "Sent D5 create character (%d bytes)\n", sent);
        fprintf(g_log, "Will send D7 (load game) after delay...\n");
    } else {
        fprintf(g_log, "Character exists, skipping D5 create\n");
    }

    // Schedule D7 (load game) after 1 second to let D4 response arrive
    SetTimer(hwnd, 7777, 1000, LoadGameTimer);

    fclose(g_log); g_log = NULL;
}

void CALLBACK LoadGameTimer(HWND hwnd, UINT msg, UINT_PTR id, DWORD tick) {
    KillTimer(hwnd, id);
    FILE* f = fopen("C:\\charctl.log", "a");
    if (!f) return;

    void** p_mgr_var = (void**)0x54D228;
    unsigned char* mgr = (unsigned char*)*(void**)*p_mgr_var;
    if (!mgr) { fprintf(f, "No mgr for D7!\n"); fclose(f); return; }

    SOCKET sock = (SOCKET)*(int*)(mgr + 0x14);
    fprintf(f, "Socket=%d for D7\n", (int)sock);
    if (sock <= 0) {
        fprintf(f, "No socket for D7!\n");
        fclose(f); return;
    }

    // Send D7 - Load into game (slot 0)
    unsigned char d7_pkt[3] = {0x01, 0x00, 0xD7};
    int sent = send(sock, (char*)d7_pkt, 3, 0);
    fprintf(f, "Sent D7 load game (%d bytes)\n", sent);
    fprintf(f, "Game should transition to world\n");

    fclose(f);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    g_log = fopen("C:\\charctl.log", "w");
    if (!g_log) return TRUE;
    fprintf(g_log, "=== charctl.dll loaded ===\n");

    HWND hwnd = FindWindowA("TMainForm", "Secret of the Solstice");
    if (hwnd) {
        // Wait 2 seconds for D3 response (D4 char list) to arrive first
        SetTimer(hwnd, 8888, 2000, CharTimer);
        fprintf(g_log, "Timer set (2s delay for D3 response)\n");
    }
    fclose(g_log); g_log = NULL;
    return TRUE;
}
