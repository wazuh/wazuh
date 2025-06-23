#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include "socket_reload.h"
#include "client-agent/agentd.h"
#include "shared.h"

#define RELOAD_PIPE_NAME "\\\\.\\pipe\\WazuhSocketReloadPipe"
#define RELOAD_CMD_ARG "--reload-child"

static int duplicate_and_pass_socket(SOCKET sock, const char* agent_path, char** out_cmdline);

int wazuh_agent_reload(const char *agent_path) {
    // Assume that agt->sock is the active TCP socket.
    SOCKET sock = agt->sock;
    char *cmdline = NULL;
    int ret = duplicate_and_pass_socket(sock, agent_path, &cmdline);
    if (ret != 0) {
        plain_merror("Failed to duplicate socket or launch child process.");
        return 1;
    }
    // The parent exits after launching the child.
    plain_minfo("Agent reload: socket handed off, exiting parent.");
    os_free(cmdline);
    return 0;
}

// Logic for duplicating and passing the socket.
static int duplicate_and_pass_socket(SOCKET sock, const char* agent_path, char** out_cmdline) {
    // 1. Create a named pipe for communication with the child process.
    HANDLE hPipe = CreateNamedPipeA(
        RELOAD_PIPE_NAME,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        sizeof(WSAPROTOCOL_INFO),
        sizeof(WSAPROTOCOL_INFO),
        0,
        NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        plain_merror("CreateNamedPipe failed: %d", GetLastError());
        return 1;
    }

    // 2. Duplicate the socket using WSADuplicateSocket.
    WSAPROTOCOL_INFO protoInfo;
    if (WSADuplicateSocket(sock, GetCurrentProcessId(), &protoInfo) != 0) {
        plain_merror("WSADuplicateSocket failed: %d", WSAGetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // 3. Create the child process that will handle the reload.
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    // Prepare the command line for the child process.
    size_t cmdline_len = strlen(agent_path) + strlen(RELOAD_CMD_ARG) + strlen(RELOAD_PIPE_NAME) + 16;
    *out_cmdline = (char *)calloc(1, cmdline_len);
    snprintf(*out_cmdline, cmdline_len, "\"%s\" %s %s", agent_path, RELOAD_CMD_ARG, RELOAD_PIPE_NAME);

    if (!CreateProcessA(NULL, *out_cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        plain_merror("CreateProcess failed: %d", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // 4. Wait for the child process to connect to the pipe.
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        plain_merror("ConnectNamedPipe failed: %d", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // 5. Write the WSAPROTOCOL_INFO to the pipe.
    DWORD bytesWritten;
    if (!WriteFile(hPipe, &protoInfo, sizeof(protoInfo), &bytesWritten, NULL)) {
        plain_merror("WriteFile failed: %d", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // Clean
    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// --- Child ---
int wazuh_agent_reload_child() {
    // 1. Connect to the named pipe created by the parent.
    HANDLE hPipe = CreateFileA(
        RELOAD_PIPE_NAME,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        plain_merror("Reload child: CreateFile failed: %d", GetLastError());
        return 1;
    }

    // 2. Read the WSAPROTOCOL_INFO from the pipe.
    WSAPROTOCOL_INFO protoInfo;
    DWORD bytesRead;
    if (!ReadFile(hPipe, &protoInfo, sizeof(protoInfo), &bytesRead, NULL)) {
        plain_merror("Reload child: ReadFile failed: %d", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    CloseHandle(hPipe);

    // 3. Create a new socket using the WSAPROTOCOL_INFO.
    SOCKET newSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, &protoInfo, 0, WSA_FLAG_OVERLAPPED);
    if (newSocket == INVALID_SOCKET) {
        plain_merror("Reload child: WSASocket failed: %d", WSAGetLastError());
        return 1;
    } else {
        plain_minfo("Reload child: new socket value is %d", (int)newSocket);
    }

    // 4. Restore the socket in the global agent structure.
    agt->sock = newSocket;
    plain_minfo("Reload child: socket restored successfully.");
    return 0;
}