#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

/*
 * probe.dll - Reads game state and writes to C:\probe.log.
 * Useful for debugging: char slots, ConnMgr state, etc.
 */

void CALLBACK ProbeTimer(HWND hwnd, UINT msg, UINT_PTR id, DWORD tick) {
    KillTimer(hwnd, id);
    FILE* f = fopen("C:\\probe.log", "w");
    if (!f) return;

    // Character data array at 0x59F52C (5 slots x 43 bytes)
    unsigned char* chars = (unsigned char*)0x59F52C;
    fprintf(f, "=== Character slots at 0x59F52C ===\n");
    for (int slot = 0; slot < 5; slot++) {
        unsigned char* c = chars + slot * 43;
        int has_data = 0;
        for (int j = 0; j < 43; j++) if (c[j]) { has_data = 1; break; }
        if (has_data) {
            fprintf(f, "Slot %d:", slot);
            for (int j = 0; j < 43; j++) fprintf(f, " %02x", c[j]);
            fprintf(f, "\n");
            char name[14] = {0};
            memcpy(name, c, 13);
            fprintf(f, "  name='%s' level=%d\n", name, c[14]);
            fprintf(f, "  IP=%d.%d.%d.%d\n", c[15], c[16], c[17], c[18]);
            fprintf(f, "  POW=%d STA=%d AGI=%d INT=%d MEN=%d WIS=%d\n",
                    c[19], c[20], c[21], c[22], c[23], c[24]);
            fprintf(f, "  sex=%d body=%d hair=%d head=%d face=%d\n",
                    c[25], c[26], c[27], c[28], c[29]);
        }
    }

    unsigned char count = *(unsigned char*)0x59F450;
    fprintf(f, "\nChar count at 0x59F450 = %d\n", count);

    fprintf(f, "\n=== Connection manager state ===\n");
    void** p = (void**)0x54D228;
    unsigned char* mgr = *p ? (unsigned char*)*(void**)*p : NULL;
    if (mgr) {
        fprintf(f, "socket=%d connected=%d\n", *(int*)(mgr+0x14), mgr[0x492C]);
        fprintf(f, "recv_list_count=%d\n", *(unsigned int*)(mgr + 0x18));
    } else {
        fprintf(f, "No ConnMgr found\n");
    }

    fclose(f);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    HWND hwnd = FindWindowA("TMainForm", "Secret of the Solstice");
    if (hwnd) SetTimer(hwnd, 5555, 200, ProbeTimer);
    return TRUE;
}
