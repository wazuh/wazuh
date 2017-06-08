/* Remote request listener
 * Copyright (C) 2017 Wazuh Inc.
 * Jun 07, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include <pthread.h>
#include "os_net/os_net.h"
#include "execd.h"
#include "os_crypto/sha1/sha1_op.h"
#include "wazuh_modules/wmodules.h"

// Current opened file

static struct {
    char path[PATH_MAX + 1];
    FILE * fp;
} file;

size_t wcom_dispatch(char *command, size_t length, char *output){

    char *rcv_comm = command;
    char *rcv_args = NULL;

    char *path = NULL;
    char *mode = NULL;
    char *data = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    } else {
        merror("WCOM bad command.");
        strcpy(output, "err Bad command");
        return strlen(output);
    }

    if (strcmp(rcv_comm, "open") == 0){
        // open [rw file_path]
        mode = rcv_args;
        if (path = strchr(mode, ' '), path){
            *path = '\0';
            path++;
            return wcom_open(path, mode, output);
        }else {
            merror("Bad WCOM open message.");
            strcpy(output, "err Open file");
            return strlen(output);
        }

    }else if (strcmp(rcv_comm, "write") == 0){
        // write [length file_path data]
        ssize_t data_length = (ssize_t)strtol(rcv_args, &path, 10);

        if (*path != ' ' || data_length < 0) {
            merror("Bad WCOM write message.");
            strcpy(output, "err Write file");
            return strlen(output);
        }
        // write length[ file_path data]
        path++;
        // write length [file_path data]
        if ((command + length - data_length - path) <= 0){
            merror("Bad size WCOM path message.");
            strcpy(output, "err Write file");
            return strlen(output);
        }
        char *ptr = &command[length - data_length - 1];
        // write length file_path[ data]
        if (*ptr == ' '){
            data = ptr + 1;
            *ptr = '\0';
        }else{
            merror("Bad WCOM write message.");
            strcpy(output, "err Write file");
            return strlen(output);
        }

        return wcom_write(path, data, (size_t)data_length, output);

    }else if (strcmp(rcv_comm, "close") == 0){
        // close [file_path]
        return wcom_close(rcv_args, output);

    }else if (strcmp(rcv_comm, "sha1") == 0){
        // sha1 [file_path]
        return wcom_sha1(rcv_args, output);

    }else if (strcmp(rcv_comm, "unmerge") == 0){
        // unmerge [file_path]
        return wcom_unmerge(rcv_args, output);

    }else if (strcmp(rcv_comm, "exec") == 0){
        // exec [command]
        return wcom_exec(rcv_args, output);

    }else {
        merror("WCOM Unrecognized command.");
        strcpy(output, "err Unrecognized command");
        return strlen(output);
    }
}

size_t wcom_open(const char *file_path, const char *mode, char *output) {
    if (*file.path) {
        merror("File '%s' was opened. Closing.", file.path);
        fclose(file.fp);
    }

    if (file.fp = fopen(file_path, mode), file.fp) {
        strncpy(file.path, file_path, PATH_MAX);
        strcpy(output, "ok");
        return 2;
    } else {
        merror(FOPEN_ERROR, file_path, errno, strerror(errno));
        snprintf(output, OS_MAXSTR + 1, "err %s", strerror(errno));
        return strlen(output);
    }
}

size_t wcom_write(const char *file_path, char *buffer, size_t length, char *output) {
    if (!*file.path) {
        merror("At wcom_write(): No file is opened.");
        strcpy(output, "err No file opened.");
        return 2;
    }

    if (strcmp(file.path, file_path) != 0) {
        merror("At wcom_write(): No file is opened.");
        strcpy(output, "err No file opened.");
        return 2;
    }

    if (fwrite(buffer, 1, length, file.fp) == length) {
        strcpy(output, "ok");
        return 2;
    } else {
        merror("At wcom_write(): Cannot write on '%s'", file_path);
        strcpy(output, "err Cannot write");
        return strlen(output);
    }

    return 0;
}
size_t wcom_close(const char *file_path, char *output){
    if (!*file.path) {
        merror("At wcom_close(): No file is opened.");
        strcpy(output, "err No file opened");
        return 2;
    }

    if (strcmp(file.path, file_path) != 0) {
        merror("At wcom_close(): No file is opened.");
        strcpy(output, "err No file opened");
        return 2;
    }

    *file.path = '\0';

    if (fclose(file.fp)) {
        merror("At wcom_close(): %s", strerror(errno));
        strcpy(output, "err Cannot close");
    } else {
        strcpy(output, "ok");
        return 2;
    }
    return 0;
}
size_t wcom_sha1(const char *file_path, char *output){

    os_sha1 sha1;
    if (OS_SHA1_File(file_path, sha1, OS_BINARY) < 0){
        merror("At wcom_sha1(): Error generating SHA1.");
        strcpy(output, "err Cannot generate SHA1");
        return strlen(output);
    } else {
        strncpy(output, sha1, 64);
        return strlen(output);
    }
}
size_t wcom_unmerge(const char *file_path, char *output){

    if (UnmergeFiles(file_path, NULL) == 0){
        merror("At wcom_unmerge(): Error unmerging file.");
        strcpy(output, "err Cannot unmerge file");
        return strlen(output);
    } else {
        strcpy(output, "ok");
        return 2;
    }
}
size_t wcom_exec(char *command, char *output){
    static int timeout = 0;
    int status;
    char *out;

    if (timeout == 0) {
        timeout = getDefine_Int("execd", "request_timeout", 1, 3600);
    }

    if (wm_exec(command, &out, &status, timeout) < 0) {
        merror("At wcom_exec(): Error executing command [%s]", command);
        strcpy(output, "err Cannot execute command");
        return strlen(output);
    } else {
        int offset = snprintf(output, OS_MAXSTR, "ok %d ", status);
        strncpy(output + offset, out, OS_MAXSTR - offset + 1);
        free(out);
        return strlen(output);
    }
}

#ifndef WIN32

void * wcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char buffer[OS_MAXSTR + 1];
    char response[OS_MAXSTR + 1];
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(DEFAULTDIR COM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s'. Closing local server.", AUTH_LOCAL_SOCK);
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At wcom_main(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At wcom_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        switch (length = recv(peer, buffer, OS_MAXSTR, 0), length) {
        case -1:
            merror("At wcom_main(): recv(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        default:
            buffer[length] = '\0';
            length = wcom_dispatch(buffer, length, response);
            send(peer, response, length, 0);
            close(peer);
        }
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}

#endif
