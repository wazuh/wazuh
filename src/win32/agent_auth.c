/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Contributed by Gael Muller (@gaelmuller)
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

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
    printf("\n%s %s: Connects to the manager to extract the agent key.\n", __ossec_name, ARGV0);
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
            merror_exit("Could not send security token to server.");

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
        merror_exit("Could not resolve manager's hostname");

    // Connect via TCP
    *socket = OS_ConnectTCP(port, manager, 0);
    if (*socket < 0)
        merror_exit("Unable to connect to %s:%d", manager, port);

    // Setting authentication credentials
    ZeroMemory(&auth_cred, sizeof (auth_cred));
    auth_cred.dwVersion = SCHANNEL_CRED_VERSION;
    auth_cred.dwSessionLifespan = 60000;
    auth_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;

    status = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &auth_cred, NULL, NULL, cred, NULL);
    if (status != SEC_E_OK)
        merror_exit("Could not acquire credentials (AcquireCredentialsHandle failed with error code 0x%lX", status);

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
        merror_exit("Out of memory!");

    input_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    status = InitializeSecurityContext(cred, NULL, NULL, input_flags, 0, 0, NULL, 0, context, &OutBuffer, &output_flags, NULL);

    while (status != SEC_E_OK)
    {
        switch (status) {
        case SEC_I_CONTINUE_NEEDED:      // 0x00090312
            SendSecurityToken(*socket, OutBuffers);
            total_read = 0;
            break;
        case SEC_E_INSUFFICIENT_MEMORY:  // 0x80090300
            merror_exit("Insufficient memory.");
            break;
        case SEC_E_UNSUPPORTED_FUNCTION: // 0x80090302
            merror_exit("Couldn't negotiate encryption protocol. Try to run ossec-authd with \"-a\" option.");
            break;
        case SEC_E_INTERNAL_ERROR:  // 0x80090304
            merror_exit("Internal error.");
            break;
        case SEC_E_INCOMPLETE_MESSAGE:   // 0x80090318
            break;
        case SEC_E_ILLEGAL_MESSAGE:      // 0x80090326
            merror_exit("Illegal message: maybe the manager requested certificate verification (unsupported).");
            break;
        default:
            mwarn("Unexpected status (0x%lx).", status);
        }

        // See if we have data to retrieve from server
        if ((total_read == 0) || (status == SEC_E_INCOMPLETE_MESSAGE))
        {
            read = recv(*socket, buffer + total_read, IO_BUFFER_SIZE - total_read, 0);
            if (read <= 0)
                merror_exit("Could not get security token from server. Run ossec-authd with \"-a\" option and enable RC4 or 3DES cipher.");

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
        merror_exit("Could not get message sizes (QueryContextAttributes failed with error code 0x%lX)", status);

    // Construct message
    buffer_length = sizes.cbHeader + sizes.cbMaximumMessage + sizes.cbTrailer;
    buffer = LocalAlloc(LMEM_FIXED, buffer_length);
    if (buffer == NULL)
        merror_exit("Out of memory!");
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
        merror_exit("Could not encrypt message (EncryptMessage failed with error code %lX)", status);

    sent = send(socket, buffer, msg_buffers[0].cbBuffer + msg_buffers[1].cbBuffer + msg_buffers[2].cbBuffer, 0);
    if (sent <= 0)
            merror_exit("Could not send message to server");

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
                merror_exit("Could not receive message from server (or invalid password)");

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
            merror_exit("Could not decrypt received message (DecryptMessage failed with error code 0x%lX)", status);

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
        merror_exit("%s (from manager)", msg);
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
            merror_exit("Invalid key received. Closing connection.");

        *tmpstr = '\0';
        entry = OS_StrBreak(' ', key, 4);

        if (!OS_IsValidID(entry[0]) || !OS_IsValidName(entry[1]) ||
            !OS_IsValidName(entry[2]) || !OS_IsValidName(entry[3]))
            merror_exit("Invalid key received (2). Closing connection.");

        fp = fopen(KEYSFILE_PATH, "w");

        if (!fp)
            merror_exit("Unable to open key file: %s", KEYSFILE_PATH);

        fprintf(fp, "%s\n", key);
        fclose(fp);

        printf("INFO: Valid key created. Finished.\n");
    }
    else
        merror_exit("Unknown message received (%s)", msg);
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
        merror_exit("Could not correctly close connection");

    input_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    status = InitializeSecurityContext(cred, context, NULL, input_flags, 0, 0, NULL, 0, context, &OutBuffer, &output_flags, NULL);
    if (status != SEC_E_OK)
        merror_exit("Could not correctly close connection (2)");

    sent = send(socket, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
    if (sent <= 0)
        merror_exit("Could not correctly close connection (3)");

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
                    merror_exit("-%c needs an argument", c);
                manager = optarg;
                break;
            case 'A':
               if(!optarg)
                    merror_exit("-%c needs an argument", c);
                agentname = optarg;
                break;
            case 'p':
               if(!optarg)
                    merror_exit("-%c needs an argument", c);
                port = atoi(optarg);
                if(port <= 0 || port >= 65536)
                {
                    merror_exit("Invalid port: %s", optarg);
                }
                break;
            case 'P':
                if (!optarg)
                    merror_exit("-%c needs an argument", c);

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
        merror_exit("Could not initialize networking (WSAStartup failed with error code %u)", error);

    // Determine agent_name
    if(agentname == NULL)
    {
        if(gethostname(hostname, 512) != 0)
            merror_exit("Unable to extract hostname. Custom agent name not set.");

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
        printf("INFO: No authentication password provided. Insecure mode started.\n");
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
