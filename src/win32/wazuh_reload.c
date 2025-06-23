#ifdef WIN32

#include "wazuh_reload.h"
#include "client-agent/agentd.h"
#include "shared.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

static HANDLE h_control_thread = NULL;

// Thread: waits on control pipe for "reload"
DWORD WINAPI reload_control_thread(LPVOID param) {
    const char *agent_path = (const char *)param;
    for (;;) {
        HANDLE hPipe = CreateNamedPipeA(
            RELOAD_PIPE_CONTROL,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 256, 256, 0, NULL
        );
        if (hPipe == INVALID_HANDLE_VALUE) {
            plain_merror("Cannot create reload control pipe: %d", GetLastError());
            Sleep(1000);
            continue;
        }
        if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }
        char cmd[32] = {0};
        DWORD bytesRead = 0;
        if (ReadFile(hPipe, cmd, sizeof(cmd)-1, &bytesRead, NULL)) {
            cmd[bytesRead] = 0;
            if (strcmp(cmd, "reload") == 0) {
                CloseHandle(hPipe);
                handle_reload_command(agent_path);
                // Stop the service and exit
                os_stop_service();
                ExitProcess(0);
            }
        }
        CloseHandle(hPipe);
    }
    return 0;
}

void start_reload_control_thread(const char *agent_path) {
    // Create a thread to listen for reload commands
    h_control_thread = CreateThread(
        NULL, 0, reload_control_thread, (LPVOID)agent_path, 0, NULL
    );
    if (!h_control_thread) {
        plain_merror("Cannot start reload control thread");
    }
}

// Function to handle the reload command
void handle_reload_command(const char *agent_path) {
    SOCKET sock = agt ? agt->sock : INVALID_SOCKET;
    if (sock == INVALID_SOCKET) {
        plain_merror("Reload requested but agent socket invalid.");
        return;
    }

    // Create a named pipe for the child process to receive the socket
    HANDLE hPipe = CreateNamedPipeA(
        RELOAD_PIPE_SOCKET,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, sizeof(WSAPROTOCOL_INFO), sizeof(WSAPROTOCOL_INFO), 0, NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        plain_merror("Cannot create reload socket pipe: %d", GetLastError());
        return;
    }

    // Duplicate the socket using WSADuplicateSocket
    WSAPROTOCOL_INFO protoInfo;
    if (WSADuplicateSocket(sock, GetCurrentProcessId(), &protoInfo) != 0) {
        plain_merror("WSADuplicateSocket failed: %d", WSAGetLastError());
        CloseHandle(hPipe);
        return;
    }

    // Create the child process that will handle the reload
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmdLine[512];
    // snprintf(cmdLine, sizeof(cmdLine), "\"%s\" child %s", __argv[0], PIPE_NAME);
    plain_minfo("agent_path: %s", agent_path);
    snprintf(cmdLine, sizeof(cmdLine), "%s --reload-child %s", agent_path, RELOAD_PIPE_SOCKET);
    plain_minfo("CreateProcess command line: %s", cmdLine);

    if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        plain_merror("CreateProcess failed: %d", GetLastError());
        CloseHandle(hPipe);
        return;
    }

    // Wait for the child process to finish
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        plain_merror("ConnectNamedPipe failed: %d", GetLastError());
        CloseHandle(hPipe);
        return;
    }

    // Write the WSAPROTOCOL_INFO to the pipe
    DWORD written;
    if (!WriteFile(hPipe, &protoInfo, sizeof(protoInfo), &written, NULL)) {
        plain_merror("WriteFile failed: %d", GetLastError());
        CloseHandle(hPipe);
        return;
    }

    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    plain_minfo("Reload: socket handed to child, exiting parent.");
}

// Child: receives the WSAPROTOCOL_INFO, recreates the socket, and assigns it to agt->sock
int handle_reload_child(const char *pipe_name) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        plain_merror("Reload child: WSAStartup failed: %d", WSAGetLastError());
        return 1;
    }

    HANDLE hPipe = CreateFileA(
        pipe_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        plain_merror("Reload child: CreateFile failed: %d", GetLastError());
        return 1;
    }
    WSAPROTOCOL_INFO protoInfo;
    DWORD bytesRead;
    if (!ReadFile(hPipe, &protoInfo, sizeof(protoInfo), &bytesRead, NULL)) {
        plain_merror("Reload child: ReadFile failed: %d", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    CloseHandle(hPipe);

    SOCKET newSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, &protoInfo, 0, 0);
    if (newSocket == INVALID_SOCKET) {
        plain_merror("Reload child: WSASocket failed: %d", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    if (!agt) os_calloc(1, sizeof(agent), agt);
    if (agt) agt->sock = newSocket;
    plain_minfo("Reload child: socket restored.");
    return 0;
}

#endif