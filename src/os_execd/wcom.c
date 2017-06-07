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
#include "execd.h"

size_t wcom_dispatch(char *command, size_t length, char *output){

    char *rcv_comm = command;
    char *rcv_args = NULL;

    char *path = NULL;
    char *mode = NULL;
    char *data = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "open") == 0){
        // open [rw file_path]
        mode = rcv_args;
        path = strchr(mode, ' ');
        *path = '\0';
        path++;

        return wcom_open(path, mode, output);

    }else if (strcmp(rcv_comm, "write") == 0){
        // write [length file_path data]
        ssize_t data_length = (ssize_t)strtol(rcv_args, &path, 10);

        if (*path != ' ' || data_length < 0) {
            merror("%s: ERROR: Bad WCOM write message.", __local_name);
            strcpy(output, "err Write file");
            return strlen(output);
        }
        // write length[ file_path data]
        path++;
        // write length [file_path data]
        if ((command + length - data_length - path) <= 0){
            merror("%s: ERROR: Bad size WCOM path message.", __local_name);
            strcpy(output, "err Write file");
            return strlen(output);
        }
        char *ptr = &command[length - data_length - 1];
        // write length file_path[ data]
        if (*ptr == ' '){
            data = ptr + 1;
            *ptr = '\0';
        }else{
            merror("%s: ERROR: Bad WCOM write message.", __local_name);
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
        merror("%s: ERROR: WCOM Unrecognized command.", __local_name);
        strcpy(output, "err Unrecognized command");
        return strlen(output);
    }
}

size_t wcom_open(const char *file_path, const char *mode, char *output){
    return 0;
}
size_t wcom_write(const char *file_path, char *buffer, size_t length, char *output){
    return 0;
}
size_t wcom_close(const char *file_path, char *output){
    return 0;
}
size_t wcom_sha1(const char *file_path, char *output){
    return 0;
}
size_t wcom_unmerge(const char *file_path, char *output){
    return 0;
}
size_t wcom_exec(const char *command, char *output){
    return 0;
}
