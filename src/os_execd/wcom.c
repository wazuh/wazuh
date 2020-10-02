/* Remote request listener
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Jun 07, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include <pthread.h>
#include "os_net/os_net.h"
#include "execd.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/signature/signature.h"
#include "wazuh_modules/wmodules.h"
#include "external/zlib/zlib.h"
#include "client-agent/agentd.h"
#include "logcollector/logcollector.h"
#include "syscheckd/syscheck.h"
#include "rootcheck/rootcheck.h"

// Current opened file

static struct {
    char path[PATH_MAX + 1];
    FILE * fp;
} file;

static int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);
int req_timeout;
int max_restart_lock;

size_t wcom_dispatch(char *command, size_t length, char ** output){

    char *rcv_comm = command;
    char *rcv_args = NULL;

    char *path = NULL;
    char *mode = NULL;
    char *data = NULL;
    char * source;
    char * target;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "open") == 0){
        if (!rcv_args){
            mdebug1("WCOM open needs arguments.");
            os_strdup("err WCOM open needs arguments", *output);
            return strlen(*output);
        }
        // open [rw file_path]
        mode = rcv_args;
        if (path = strchr(mode, ' '), path){
            *path = '\0';
            path++;
            return wcom_open(path, mode, output);
        }else {
            mdebug1("Bad WCOM open message.");
            os_strdup("err Open file", *output);
            return strlen(*output);
        }

    }else if (strcmp(rcv_comm, "write") == 0){
        if (!rcv_args){
            mdebug1("WCOM write needs arguments.");
            os_strdup("err WCOM write needs arguments", *output);
            return strlen(*output);
        }
        // write [length file_path data]
        ssize_t data_length = (ssize_t)strtol(rcv_args, &path, 10);

        if (*path != ' ' || data_length < 0) {
            mdebug1("Bad WCOM write message.");
            os_strdup("err Write file", *output);
            return strlen(*output);
        }
        // write length[ file_path data]
        path++;
        // write length [file_path data]
        if ((command + length - data_length - path) <= 0){
            mdebug1("Bad size WCOM path message.");
            os_strdup("err Write file", *output);
            return strlen(*output);
        }
        char *ptr = &command[length - data_length - 1];
        // write length file_path[ data]
        if (*ptr == ' '){
            data = ptr + 1;
            *ptr = '\0';
        }else{
            mdebug1("Bad WCOM write message.");
            os_strdup("err Write file", *output);
            return strlen(*output);
        }

        return wcom_write(path, data, (size_t)data_length, output);

    }else if (strcmp(rcv_comm, "close") == 0){
        if (!rcv_args){
            mdebug1("WCOM close needs arguments.");
            os_strdup("err WCOM close needs arguments", *output);
            return strlen(*output);
        }
        // close [file_path]
        return wcom_close(rcv_args, output);

    }else if (strcmp(rcv_comm, "sha1") == 0){
        if (!rcv_args) {
            mdebug1("WCOM sha1 needs arguments.");
            os_strdup("err WCOM sha1 needs arguments", *output);
            return strlen(*output);
        }
        // sha1 [file_path]
        return wcom_sha1(rcv_args, output);

    }else if (strcmp(rcv_comm, "unmerge") == 0){
        if (!rcv_args){
            mdebug1("WCOM unmerge needs arguments.");
            os_strdup("err WCOM unmerge needs arguments", *output);
            return strlen(*output);
        }
        // unmerge [file_path]
        return wcom_unmerge(rcv_args, output);

    } else if (strcmp(rcv_comm, "upgrade_result") == 0) {
        // upgrade_result
        return wcom_upgrade_result(output);

    } else if (strcmp(rcv_comm, "clear_upgrade_result") == 0){
        // upgrade_result
        return wcom_clear_upgrade_result(output);

    } else if (strcmp(rcv_comm, "uncompress") == 0){
        if (!rcv_args){
            mdebug1("WCOM uncompress needs arguments.");
            os_strdup("err WCOM uncompress needs arguments", *output);
            return strlen(*output);
        }
        // uncompress [file_path]
        source = rcv_args;

        if (target = strchr(rcv_args, ' '), target) {
            *(target++) = '\0';
            return wcom_uncompress(source, target, output);
        } else {
            mdebug1("Bad WCOM uncompress message.");
            os_strdup("err Too few commands", *output);
            return strlen(*output);
        }

    } else if (strcmp(rcv_comm, "restart") == 0) {
        return wcom_restart(output);
    } else if (strcmp(rcv_comm, "lock_restart") == 0) {
        max_restart_lock = 0;
        int timeout = -2;

        if (!max_restart_lock) {
            max_restart_lock = getDefine_Int("execd", "max_restart_lock", 0, 3600);
        }

        if (rcv_args) {
            timeout = atoi(rcv_args);
        }

        if (timeout < -1) {
            os_strdup("err Invalid timeout", *output);
        } else {
            os_strdup("ok ", *output);
            if (timeout == -1 || timeout > max_restart_lock) {
                if (timeout > max_restart_lock) {
                    mwarn("Timeout exceeds the maximum allowed.");
                }
                timeout = max_restart_lock;
            }
        }
        lock_restart(timeout);

        return strlen(*output);

    } else if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            mdebug1("WCOM getconfig needs arguments.");
            os_strdup("err WCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return wcom_getconfig(rcv_args, output);

    } else {
        mdebug1("WCOM Unrecognized command '%s'.", rcv_comm);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

size_t wcom_open(const char *file_path, const char *mode, char ** output) {
    char final_path[PATH_MAX + 1];

    if (*file.path) {
        merror("File '%s' was opened. Closing.", file.path);
        fclose(file.fp);
        *file.path = '\0';
    }

    if (strcmp(mode, "w") && strcmp(mode, "wb")) {
        merror("At WCOM open: Unsupported mode '%s'", mode);
        os_strdup("err Unsupported mode", *output);
        return strlen(*output);
    }

    if (_jailfile(final_path, INCOMING_DIR, file_path) < 0) {
        merror("At WCOM open: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (file.fp = fopen(final_path, mode), file.fp) {
        strncpy(file.path, final_path, PATH_MAX);
        os_strdup("ok ", *output);
        return strlen(*output);
    } else {
        merror(FOPEN_ERROR, file_path, errno, strerror(errno));
        os_malloc(OS_MAXSTR + 1, *output);
        snprintf(*output, OS_MAXSTR + 1, "err %s", strerror(errno));
        return strlen(*output);
    }
}

size_t wcom_write(const char *file_path, char *buffer, size_t length, char ** output) {
    char final_path[PATH_MAX + 1];

    if (!*file.path) {
        if (file_path) {
            merror("At WCOM write: File not opened. Agent might have been auto-restarted during upgrade.");
            os_strdup("err File not opened. Agent might have been auto-restarted during upgrade", *output);
            return strlen(*output);
        }
        merror("At WCOM write: No file is opened.");
        os_strdup("err No file opened", *output);
        return strlen(*output);
    }

    if (_jailfile(final_path, INCOMING_DIR, file_path) < 0) {
        merror("At WCOM write: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (strcmp(file.path, final_path) != 0) {
        merror("At WCOM write: The target file doesn't match the opened file (%s).", file.path);
        os_strdup("err The target file doesn't match the opened file", *output);
        return strlen(*output);
    }

    if (fwrite(buffer, 1, length, file.fp) == length) {
        os_strdup("ok ", *output);
        return strlen(*output);
    } else {
        merror("At WCOM write: Cannot write on '%s'", final_path);
        os_strdup("err Cannot write", *output);
        return strlen(*output);
    }
}

size_t wcom_close(const char *file_path, char ** output){
    char final_path[PATH_MAX + 1];

    if (!*file.path) {
        merror("At WCOM close: No file is opened.");
        os_strdup("err No file opened", *output);
        return strlen(*output);
    }

    if (_jailfile(final_path, INCOMING_DIR, file_path) < 0) {
        merror("At WCOM close: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (strcmp(file.path, final_path) != 0) {
        merror("At WCOM close: The target file doesn't match the opened file (%s).", file.path);
        os_strdup("err The target file doesn't match the opened file", *output);
        return strlen(*output);
    }

    *file.path = '\0';

    if (fclose(file.fp)) {
        merror("At WCOM close: %s", strerror(errno));
        os_strdup("err Cannot close", *output);
        return strlen(*output);
    } else {
        os_strdup("ok ", *output);
        return strlen(*output);
    }
}

size_t wcom_sha1(const char *file_path, char ** output){
    char final_path[PATH_MAX + 1];
    os_sha1 sha1;

    if (_jailfile(final_path, INCOMING_DIR, file_path) < 0) {
        merror("At WCOM sha1: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (OS_SHA1_File(final_path, sha1, OS_BINARY) < 0){
        merror("At WCOM sha1: Error generating SHA1.");
        os_strdup("err Cannot generate SHA1", *output);
        return strlen(*output);
    } else {
        os_malloc(OS_MAXSTR + 1, *output);
        snprintf(*output, OS_MAXSTR + 1, "ok %s", sha1);
        return strlen(*output);
    }
}
size_t wcom_unmerge(const char *file_path, char ** output){
    char final_path[PATH_MAX + 1];

    if (_jailfile(final_path, INCOMING_DIR, file_path) < 0) {
        merror("At WCOM unmerge: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (UnmergeFiles(final_path, isChroot() ? INCOMING_DIR : DEFAULTDIR INCOMING_DIR, OS_BINARY) == 0){
        merror("At WCOM unmerge: Error unmerging file '%s.'", final_path);
        os_strdup("err Cannot unmerge file", *output);
        return strlen(*output);
    } else {
        os_strdup("ok ", *output);
        return strlen(*output);
    }
}

size_t wcom_uncompress(const char * source, const char * target, char ** output) {
    char final_source[PATH_MAX + 1];
    char final_target[PATH_MAX + 1];
    char buffer[4096];
    gzFile fsource;
    FILE *ftarget;
    int length;

    if (_jailfile(final_source, INCOMING_DIR, source) < 0) {
        merror("At WCOM uncompress: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (_jailfile(final_target, INCOMING_DIR, target) < 0) {
        merror("At WCOM uncompress: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (fsource = gzopen(final_source, "rb"), !fsource) {
        merror("At WCOM uncompress: Unable to open '%s'", final_source);
        os_strdup("err Unable to open source", *output);
        return strlen(*output);
    }

    if (ftarget = fopen(final_target, "wb"), !ftarget) {
        gzclose(fsource);
        merror("At WCOM uncompress: Unable to open '%s'", final_target);
        os_strdup("err Unable to open target", *output);
        return strlen(*output);
    }

    while (length = gzread(fsource, buffer, 4096), length > 0) {
        if ((int)fwrite(buffer, 1, length, ftarget) != length) {
            gzclose(fsource);
            fclose(ftarget);
            merror("At WCOM uncompress: Unable to write '%s'", final_target);
            os_strdup("err Unable to write target", *output);
            return strlen(*output);
        }
    }

    if (length < 0) {
        merror("At WCOM uncompress: Unable to read '%s'", final_source);
        os_strdup("err Unable to read source", *output);
    } else {
        unlink(final_source);
        os_strdup("ok ", *output);
    }

    gzclose(fsource);
    fclose(ftarget);
    return strlen(*output);
}

size_t wcom_upgrade_result(char ** output){
    char buffer[20];

#ifndef WIN32
    const char * PATH = isChroot() ? UPGRADE_DIR "/upgrade_result" : DEFAULTDIR UPGRADE_DIR "/upgrade_result";
#else
    const char * PATH = UPGRADE_DIR "\\upgrade_result";
#endif

    FILE * result_file;

    if (result_file = fopen(PATH, "r"), result_file) {
        if (fgets(buffer,20,result_file)){
            os_malloc(OS_MAXSTR + 1, *output);
            snprintf(*output, OS_MAXSTR, "ok %s", buffer);
            fclose(result_file);
            return strlen(*output);
        }
        fclose(result_file);
    }
    os_malloc(OS_MAXSTR + 1, *output);
    snprintf(*output, OS_MAXSTR, "err Cannot read upgrade_result file due to [(%d)-(%s)]", errno, strerror(errno));
    mdebug1("At WCOM upgrade_result: Cannot read file '%s'.", PATH);
    return strlen(*output);
}

size_t wcom_clear_upgrade_result(char **output) {
#ifndef WIN32
    const char * PATH = isChroot() ? UPGRADE_DIR "/upgrade_result" : DEFAULTDIR UPGRADE_DIR "/upgrade_result";
#else
    const char * PATH = UPGRADE_DIR "\\upgrade_result";
#endif
    if (remove(PATH) == 0) {
        os_strdup("ok ", *output);
    } else {
        os_strdup("err Could not erase upgrade_result file", *output);
        mdebug1("At WCOM clear_upgrade_result: Could not erase file '%s'.", PATH);
    }
    return strlen(*output);
}

size_t wcom_restart(char ** output) {
    time_t lock = pending_upg - time(NULL);

    if (lock <= 0) {
#ifndef WIN32
        char *exec_cmd[3] = { DEFAULTDIR "/bin/ossec-control", "restart", NULL};
        if (isChroot()) {
            strcpy(exec_cmd[0], "/bin/ossec-control");
        }

        switch (fork()) {
            case -1:
                merror("At WCOM restart: Cannot fork");
                os_strdup("err Cannot fork", *output);
            break;
            case 0:
                sleep(1);
                if (execv(exec_cmd[0], exec_cmd) < 0) {
                    merror(EXEC_CMDERROR, *exec_cmd, strerror(errno));
                    _exit(1);
                }
            break;
            default:
                os_strdup("ok ", *output);
            break;
        }
#else
        char exec_cm[] = {"\"" AR_BINDIR "/restart-ossec.cmd\" add \"-\" \"null\" \"(from_the_server) (no_rule_id)\""};
        ExecCmd_Win32(exec_cm);
#endif
    } else {
        minfo(LOCK_RES, (int)lock);
    }

    if (!*output) os_strdup("ok ", *output);
    return strlen(*output);
}


size_t wcom_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "active-response") == 0){
        if (cfg = getARConfig(), cfg) {
            os_strdup("ok ", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "logging") == 0){
        if (cfg = getLoggingConfig(), cfg) {
            os_strdup("ok ", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getExecdInternalOptions(), cfg) {
            os_strdup("ok ", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "cluster") == 0){
#ifndef WIN32
        /* Check socket connection with cluster first */
        int sock = -1;
        char sockname[PATH_MAX + 1] = {0};

        if (isChroot()) {
            strcpy(sockname, CLUSTER_SOCK);
        } else {
            strcpy(sockname, DEFAULTDIR CLUSTER_SOCK);
        }

        if (sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR), sock < 0) {
            os_strdup("err Unable to connect with socket. The component might be disabled", *output);
            return strlen(*output);
        }
        else {
            close(sock);

            if (cfg = getClusterConfig(), cfg) {
                os_strdup("ok ", *output);
                json_str = cJSON_PrintUnformatted(cfg);
                wm_strcat(output, json_str, ' ');
                free(json_str);
                cJSON_Delete(cfg);
                return strlen(*output);
            } else {
                goto error;
            }
        }
#endif
    }else {
        goto error;
    }
error:
    mdebug1("At WCOM getconfig: Could not get '%s' section", section);
    os_strdup("err Could not get requested section", *output);
    return strlen(*output);
}

#ifndef WIN32
void * wcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(DEFAULTDIR COM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", COM_LOCAL_SOCK, errno, strerror(errno));
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

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At wcom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("At wcom_main(): OS_RecvSecureTCP(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        case OS_MAXLEN:
            merror("Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            length = wcom_dispatch(buffer, length, &response);
            OS_SendSecureTCP(peer, length, response);
            os_free(response);
            close(peer);
        }
        os_free(buffer);
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}

#endif

int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename) {

    if (w_ref_parent_folder(filename)) {
        return -1;
    }

#ifndef WIN32
    return snprintf(finalpath, PATH_MAX + 1, "%s/%s/%s", isChroot() ? "" : DEFAULTDIR, basedir, filename) > PATH_MAX ? -1 : 0;
#else
    return snprintf(finalpath, PATH_MAX + 1, "%s\\%s", basedir, filename) > PATH_MAX ? -1 : 0;
#endif
}

size_t lock_restart(int timeout) {
    pending_upg = time(NULL) + (time_t) timeout;
    return 0;
}
