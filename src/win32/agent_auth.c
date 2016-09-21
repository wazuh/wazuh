#define SECURITY_WIN32
#include <windef.h>
#include <sspi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <schannel.h>
#include <unistd.h>
#include <stdarg.h>
#include "headers/shared.h"
#include "debug_op.h"
#include "file_op.h"
#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "defs.h"
#include "addagent/manage_agents.h"

#define IO_BUFFER_SIZE  0x10000

void report_help()
{
    printf("\nOSSEC HIDS %s: Connects to the manager to extract the agent key.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h                  This help message.\n");
    printf("\t-m <manager ip>     Manager IP Address.\n");
    printf("\t-p <port>           Manager port (default 1515).\n");
    printf("\t-A <agent name>     Agent name (default is the hostname).\n");
    printf("\t-P <pass>           Authorization password.\n");
    exit(1);
}

void SendSecurityToken(const int socket, SecBuffer *OutBuffers)
{
    int sent = 0;

    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
        sent = send(socket, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
        if (sent <= 0)
            ErrorExit("%s: Could not send security token to server (is ossec-authd running ?)", ARGV0);

        // Free Output Buffer
        FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
        OutBuffers[0].cbBuffer = 0;
    }
}

void CreateSecureConnection(char *manager, int port, int *socket, CtxtHandle *context, CredHandle *cred)
{
    SECURITY_STATUS status;
    SCHANNEL_CRED auth_cred;
    DWORD input_flags = 0;
    DWORD output_flags = 0;
    DWORD read = 0;
    DWORD total_read = 0;
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    SecBufferDesc InBuffer;
    SecBuffer InBuffers[2];
    PCHAR buffer = NULL;

    // Get manager IP address
    manager = OS_GetHost(manager, 3);
    if (manager == NULL)
        ErrorExit("%s: Could not resolve manager's hostname", ARGV0);

    // Connect via TCP
    *socket = OS_ConnectTCP(port, manager, 0);
    if (socket == 0)
        ErrorExit("%s: Unable to connect to %s:%d", ARGV0, manager, port);

    // Setting authentication credentials
    ZeroMemory(&auth_cred, sizeof (auth_cred));
    auth_cred.dwVersion = SCHANNEL_CRED_VERSION;
    auth_cred.dwSessionLifespan = 60000;
    auth_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;

    status = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &auth_cred, NULL, NULL, cred, NULL);
    if (status != SEC_E_OK)
        ErrorExit("%s: Could not acquire credentials (AcquireCredentialsHandle failed with error code 0x%lX", ARGV0, status);

    //
    // Initialize security context
    //
    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    InBuffers[1].pvBuffer = NULL;
    InBuffers[1].cbBuffer = 0;
    InBuffers[1].BufferType = SECBUFFER_EMPTY;

    buffer = LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
    if (buffer == NULL)
        ErrorExit("%s: out of memory !", ARGV0);

    input_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    status = InitializeSecurityContext(cred, NULL, NULL, input_flags, 0, 0, NULL, 0, context, &OutBuffer, &output_flags, NULL);

    while (status != SEC_E_OK)
    {
        // See if we have a token to send to the server
        if (status == SEC_I_CONTINUE_NEEDED)
        {
            SendSecurityToken(*socket, OutBuffers);
            total_read = 0;
        }

        // See if we have data to retrieve from server
        if ((total_read == 0) || (status == SEC_E_INCOMPLETE_MESSAGE))
        {
            read = recv(*socket, buffer + total_read, IO_BUFFER_SIZE - total_read, 0);
            if (read <= 0)
                ErrorExit("%s: Could not get security token from server", ARGV0);

            total_read += read;
        }

        InBuffers[0].pvBuffer = buffer;
        InBuffers[0].cbBuffer = total_read;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer = NULL;
        InBuffers[1].cbBuffer = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers = 2;
        InBuffer.pBuffers = InBuffers;
        InBuffer.ulVersion = SECBUFFER_VERSION;

        status = InitializeSecurityContext(cred, context, NULL, input_flags, 0, 0, &InBuffer, 0, context, &OutBuffer, &output_flags, NULL);
    }

    // Send remaining tokens if any
    SendSecurityToken(*socket, OutBuffers);

    printf("INFO: Connected to %s:%d\n", manager, port);
    LocalFree(buffer);
}

void SendSecureMessage(const int socket, CtxtHandle *context, const char *format, ...)
{
    va_list args;
    char *buffer;
    unsigned int buffer_length = 0;
    unsigned int msg_length = 0;
    int sent = 0;
    SecPkgContext_StreamSizes sizes;
    SECURITY_STATUS status;
    SecBufferDesc msg;
    SecBuffer msg_buffers[4];

    va_start(args, format);

    // Get sizes for given context
    status = QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (status != SEC_E_OK)
        ErrorExit("%s: Could not get message sizes (QueryContextAttributes failed with error code 0x%lX)", ARGV0, status);

    // Construct message
    buffer_length = sizes.cbHeader + sizes.cbMaximumMessage + sizes.cbTrailer;
    buffer = LocalAlloc(LMEM_FIXED, buffer_length);
    if (buffer == NULL)
        ErrorExit("%s: out of memory !", ARGV0);
    vsnprintf(buffer + sizes.cbHeader, buffer_length - sizes.cbHeader, format, args);
    msg_length = strlen(buffer + sizes.cbHeader);

    // Encrypt message in place
    msg_buffers[0].pvBuffer = buffer;
    msg_buffers[0].cbBuffer = sizes.cbHeader;
    msg_buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    msg_buffers[1].pvBuffer = buffer + sizes.cbHeader;
    msg_buffers[1].cbBuffer = msg_length;
    msg_buffers[1].BufferType = SECBUFFER_DATA;

    msg_buffers[2].pvBuffer = buffer + sizes.cbHeader + msg_length;
    msg_buffers[2].cbBuffer = sizes.cbTrailer;
    msg_buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    msg_buffers[3].BufferType = SECBUFFER_EMPTY;

    msg.ulVersion = SECBUFFER_VERSION;
    msg.cBuffers = 4;
    msg.pBuffers = msg_buffers;

    status = EncryptMessage(context, 0, &msg, 0);
    if (status != SEC_E_OK)
        ErrorExit("%s: Could not encrypt message (EncryptMessage failed with error code %lX)", ARGV0, status);

    sent = send(socket, buffer, msg_buffers[0].cbBuffer + msg_buffers[1].cbBuffer + msg_buffers[2].cbBuffer, 0);
    if (sent <= 0)
            ErrorExit("%s: Could not send message to server", ARGV0);

    va_end(args);
}

char *ReceiveSecureMessage(const int socket, CtxtHandle *context)
{
    char *buffer;
    unsigned int buffer_length = 0;
    int read = 0;
    int i = 0;
    char has_extra_data = 0;
    SECURITY_STATUS status = SEC_E_INCOMPLETE_MESSAGE;
    SecBufferDesc msg;
    SecBuffer msg_buffers[4];

    buffer = LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);

    while ((status == SEC_E_INCOMPLETE_MESSAGE) || (has_extra_data))
    {
        if (status == SEC_E_INCOMPLETE_MESSAGE)
        {
            read = recv(socket, buffer + buffer_length, IO_BUFFER_SIZE - buffer_length, 0);
            if (read <= 0)
                ErrorExit("%s: Could not receive message from server (or invalid password)", ARGV0);

            buffer_length += read;
        }

        msg_buffers[0].pvBuffer = buffer;
        msg_buffers[0].cbBuffer = buffer_length;
        msg_buffers[0].BufferType = SECBUFFER_DATA;

        msg_buffers[1].BufferType = SECBUFFER_EMPTY;
        msg_buffers[2].BufferType = SECBUFFER_EMPTY;
        msg_buffers[3].BufferType = SECBUFFER_EMPTY;

        msg.ulVersion = SECBUFFER_VERSION;
        msg.cBuffers = 4;
        msg.pBuffers = msg_buffers;

        status = DecryptMessage(context, &msg, 0, NULL);

        if ((status != SEC_E_OK) && (status != SEC_E_INCOMPLETE_MESSAGE))
            ErrorExit("%s: Could not decrypt received message (DecryptMessage failed with error code 0x%lX)", ARGV0, status);

        if (status == SEC_E_OK)
        {
            has_extra_data = 0;
            for (i = 1; i < 4; ++i)
                if (msg_buffers[i].BufferType == SECBUFFER_EXTRA)
                {
                    has_extra_data = 1;
                    memcpy(buffer, msg_buffers[i].pvBuffer, msg_buffers[i].cbBuffer);
                    buffer_length = msg_buffers[i].cbBuffer;
                }
        }
    }

    for (i = 1; i < 4; ++i)
        if (msg_buffers[i].BufferType == SECBUFFER_DATA)
            return msg_buffers[i].pvBuffer;

    return NULL;
}

void InstallAuthKeys(char *msg)
{
    if (strncmp(msg, "ERROR", 5) == 0)
        ErrorExit("%s: %s (from manager)", ARGV0, msg);
    else if (strncmp(msg, "OSSEC K:'", 9) == 0)
    {
        char *key;
        char *tmpstr;
        char **entry;
        FILE *fp;

        printf("INFO: Received response with agent key\n");

        key = msg + 9;
        tmpstr = strchr(key, '\'');

        if (!tmpstr)
            ErrorExit("%s: Invalid key received. Closing connection.", ARGV0);

        *tmpstr = '\0';
        entry = OS_StrBreak(' ', key, 4);

        if (!OS_IsValidID(entry[0]) || !OS_IsValidName(entry[1]) ||
            !OS_IsValidName(entry[2]) || !OS_IsValidName(entry[3]))
            ErrorExit("%s: Invalid key received (2). Closing connection.", ARGV0);

        fp = fopen(KEYSFILE_PATH, "w");

        if (!fp)
            ErrorExit("%s: Unable to open key file: %s", ARGV0, KEYSFILE_PATH);

        fprintf(fp, "%s\n", key);
        fclose(fp);

        printf("INFO: Valid key created. Finished.\n");
    }
    else
        ErrorExit("%s: Unknown message received (%s)", ARGV0, msg);
}

void DisconnectFromServer(const int socket, CtxtHandle *context, CredHandle *cred)
{
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    DWORD dwType;
    SECURITY_STATUS status;
    DWORD input_flags;
    DWORD output_flags;
    int sent = 0;

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    status = ApplyControlToken(context, &OutBuffer);
    if (status != SEC_E_OK)
        ErrorExit("%s: Could not correclty close connection", ARGV0);

    input_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    status = InitializeSecurityContext(cred, context, NULL, input_flags, 0, 0, NULL, 0, context, &OutBuffer, &output_flags, NULL);
    if (status != SEC_E_OK)
        ErrorExit("%s: Could not correclty close connection (2)", ARGV0);

    sent = send(socket, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
    if (sent <= 0)
        ErrorExit("%s: Could not correclty close connection (3)", ARGV0);

    FreeContextBuffer(OutBuffers[0].pvBuffer);
    DeleteSecurityContext(context);
    close(socket);
}

int main(int argc, char **argv)
{
    int error = 0;
    int socket = 0;
    int port = 1515;
    char c = 0;
    char *manager = NULL;
    char *agentname = NULL;
    char hostname[512];
    char *msg = NULL;
    char *authpass = NULL;
    char buf[4096 + 1] = { '\0' };
    WSADATA wsa;
    CtxtHandle context;
    CredHandle cred;

    /* Setting the name */
    OS_SetName(ARGV0);

    while((c = getopt(argc, argv, "hm:p:A:P:")) != -1)
    {
        switch(c){
            case 'h':
                report_help();
                break;
            case 'm':
               if(!optarg)
                    ErrorExit("%s: -%c needs an argument",ARGV0, c);
                manager = optarg;
                break;
            case 'A':
               if(!optarg)
                    ErrorExit("%s: -%c needs an argument",ARGV0, c);
                agentname = optarg;
                break;
            case 'p':
               if(!optarg)
                    ErrorExit("%s: -%c needs an argument",ARGV0, c);
                port = atoi(optarg);
                if(port <= 0 || port >= 65536)
                {
                    ErrorExit("%s: Invalid port: %s", ARGV0, optarg);
                }
                break;
            case 'P':
                if (!optarg)
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);

                authpass = optarg;
                break;
            default:
                report_help();
                break;
        }
    }

    // Initialize Windows Networking
    error = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (error)
        ErrorExit("%s: Could not initialize networking (WSAStartup failed with error code %u)", ARGV0, error);

    // Determine agent_name
    if(agentname == NULL)
    {
        if(gethostname(hostname, 512) != 0)
            ErrorExit("%s: ERROR: Unable to extract hostname. Custom agent name not set.", ARGV0);

        agentname = hostname;
    }

    /* Checking if there is a custom password file */
    if (authpass == NULL) {
        FILE *fp;
        fp = fopen(AUTHDPASS_PATH, "r");
        buf[0] = '\0';

        if (fp) {
            buf[4096] = '\0';
            char *ret = fgets(buf, 4095, fp);

            if (ret && strlen(buf) > 2) {
                authpass = buf;
            }

            fclose(fp);
            printf("INFO: Using password specified on file: %s\n", AUTHDPASS_PATH);
        }
    }
    if (!authpass) {
        printf("WARN: No authentication password provided. Insecure mode started.\n");
    }

    // Connect to socket and init security context
    CreateSecureConnection(manager, port, &socket, &context, &cred);

    printf("INFO: Using agent name as: %s\n", agentname);

    // Send request

    if (authpass)
        SendSecureMessage(socket, &context, "OSSEC PASS: %s OSSEC A:'%s'\n", authpass, agentname);
    else
        SendSecureMessage(socket, &context, "OSSEC A:'%s'\n", agentname);

    printf("INFO: Sent request to manager. Waiting for reply.\n");

    // Get response
    msg = ReceiveSecureMessage(socket, &context);

    // Install received keys
    InstallAuthKeys(msg);

    // Disconnect
    DisconnectFromServer(socket, &context, &cred);

    return (0);
}
