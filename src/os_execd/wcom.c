/* Remote request listener
 * Copyright (C) 2015-2019, Wazuh Inc.
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
static int _unsign(const char * source, char dest[PATH_MAX + 1]);
static int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]);
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
    char * package;
    char * installer;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "open") == 0){
        if (!rcv_args){
            mdebug1("WCOM open needs arguments.");
            *output = strdup("err WCOM open needs arguments");
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
            *output = strdup("err Open file");
            return strlen(*output);
        }

    }else if (strcmp(rcv_comm, "write") == 0){
        if (!rcv_args){
            mdebug1("WCOM write needs arguments.");
            *output = strdup("err WCOM write needs arguments");
            return strlen(*output);
        }
        // write [length file_path data]
        ssize_t data_length = (ssize_t)strtol(rcv_args, &path, 10);

        if (*path != ' ' || data_length < 0) {
            mdebug1("Bad WCOM write message.");
            *output = strdup("err Write file");
            return strlen(*output);
        }
        // write length[ file_path data]
        path++;
        // write length [file_path data]
        if ((command + length - data_length - path) <= 0){
            mdebug1("Bad size WCOM path message.");
            *output = strdup("err Write file");
            return strlen(*output);
        }
        char *ptr = &command[length - data_length - 1];
        // write length file_path[ data]
        if (*ptr == ' '){
            data = ptr + 1;
            *ptr = '\0';
        }else{
            mdebug1("Bad WCOM write message.");
            *output = strdup("err Write file");
            return strlen(*output);
        }

        return wcom_write(path, data, (size_t)data_length, output);

    }else if (strcmp(rcv_comm, "close") == 0){
        if (!rcv_args){
            mdebug1("WCOM close needs arguments.");
            *output = strdup("err WCOM close needs arguments");
            return strlen(*output);
        }
        // close [file_path]
        return wcom_close(rcv_args, output);

    }else if (strcmp(rcv_comm, "sha1") == 0){
        if (!rcv_args){
            mdebug1("WCOM sha1 needs arguments.");
            *output = strdup("err WCOM sha1 needs arguments");
            return strlen(*output);
        }
        // sha1 [file_path]
        return wcom_sha1(rcv_args, output);

    }else if (strcmp(rcv_comm, "unmerge") == 0){
        if (!rcv_args){
            mdebug1("WCOM unmerge needs arguments.");
            *output = strdup("err WCOM unmerge needs arguments");
            return strlen(*output);
        }
        // unmerge [file_path]
        return wcom_unmerge(rcv_args, output);

    }else if (strcmp(rcv_comm, "upgrade_result") == 0){
        // upgrade_result
        return wcom_upgrade_result(output);

    } else if (strcmp(rcv_comm, "uncompress") == 0){
        if (!rcv_args){
            mdebug1("WCOM uncompress needs arguments.");
            *output = strdup("err WCOM uncompress needs arguments");
            return strlen(*output);
        }
        // uncompress [file_path]
        source = rcv_args;

        if (target = strchr(rcv_args, ' '), target) {
            *(target++) = '\0';
            return wcom_uncompress(source, target, output);
        } else {
            mdebug1("Bad WCOM uncompress message.");
            *output = strdup("err Too few commands");
            return strlen(*output);
        }

    } else if (strcmp(rcv_comm, "upgrade") == 0) {
        // upgrade <package> <installer>
        if (!rcv_args){
            mdebug1("WCOM upgrade needs arguments.");
            *output = strdup("err WCOM upgrade needs arguments");
            return strlen(*output);
        }

        package = rcv_args;

        if (installer = strchr(rcv_args, ' '), installer) {
            *(installer++) = '\0';
            return wcom_upgrade(package, installer, output);
        } else {
            mdebug1("Bad WCOM upgrade message.");
            *output = strdup("err Too few commands");
            return strlen(*output);
        }
    } else if (strcmp(rcv_comm, "restart") == 0) {
        return wcom_restart(output);
    } else if (strcmp(rcv_comm, "lock_restart") == 0) {
        max_restart_lock = 0;
        int timeout;

        if (!max_restart_lock) {
                max_restart_lock = getDefine_Int("execd", "max_restart_lock", 0, 3600);
        };
        timeout = atoi(rcv_args);

        if (timeout < -1) {
            *output = strdup("err Invalid timeout");
        } else {
            *output = strdup("ok");
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
            *output = strdup("err WCOM getconfig needs arguments");
            return strlen(*output);
        }
        return wcom_getconfig(rcv_args, output);

    } else {
        mdebug1("WCOM Unrecognized command '%s'.", rcv_comm);
        *output = strdup("err Unrecognized command");
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
        *output = strdup("err Unsupported mode");
        return strlen(*output);
    }

    if (_jailfile(final_path, INCOMING_DIR, file_path) > PATH_MAX) {
        merror("At WCOM open: Invalid file name");
        *output = strdup("err Invalid file name");
        return strlen(*output);
    }

    if (file.fp = fopen(final_path, mode), file.fp) {
        strncpy(file.path, final_path, PATH_MAX);
        *output = strdup("ok");
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
        merror("At WCOM write: No file is opened.");
        *output = strdup("err No file opened");
        return strlen(*output);
    }

    if (_jailfile(final_path, INCOMING_DIR, file_path) > PATH_MAX) {
        merror("At WCOM write: Invalid file name");
        *output = strdup("err Invalid file name");
        return strlen(*output);
    }

    if (strcmp(file.path, final_path) != 0) {
        merror("At WCOM write: The target file doesn't match the opened file (%s).", file.path);
        *output = strdup("err The target file doesn't match the opened file");
        return strlen(*output);
    }

    if (fwrite(buffer, 1, length, file.fp) == length) {
        *output = strdup("ok");
        return strlen(*output);
    } else {
        merror("At WCOM write: Cannot write on '%s'", final_path);
        *output = strdup("err Cannot write");
        return strlen(*output);
    }
}

size_t wcom_close(const char *file_path, char ** output){
    char final_path[PATH_MAX + 1];

    if (!*file.path) {
        merror("At WCOM close: No file is opened.");
        *output = strdup("err No file opened");
        return strlen(*output);
    }

    if (_jailfile(final_path, INCOMING_DIR, file_path) > PATH_MAX) {
        merror("At WCOM close: Invalid file name");
        *output = strdup("err Invalid file name");
        return strlen(*output);
    }

    if (strcmp(file.path, final_path) != 0) {
        merror("At WCOM close: The target file doesn't match the opened file (%s).", file.path);
        *output = strdup("err The target file doesn't match the opened file");
        return strlen(*output);
    }

    *file.path = '\0';

    if (fclose(file.fp)) {
        merror("At WCOM close: %s", strerror(errno));
        *output = strdup("err Cannot close");
        return strlen(*output);
    } else {
        *output = strdup("ok");
        return strlen(*output);
    }
}

size_t wcom_sha1(const char *file_path, char ** output){
    char final_path[PATH_MAX + 1];
    os_sha1 sha1;

    if (_jailfile(final_path, INCOMING_DIR, file_path) > PATH_MAX) {
        merror("At WCOM sha1: Invalid file name");
        *output = strdup("err Invalid file name");
        return strlen(*output);
    }

    if (OS_SHA1_File(final_path, sha1, OS_BINARY) < 0){
        merror("At WCOM sha1: Error generating SHA1.");
        *output = strdup("err Cannot generate SHA1");
        return strlen(*output);
    } else {
        os_malloc(OS_MAXSTR + 1, *output);
        snprintf(*output, OS_MAXSTR + 1, "ok %s", sha1);
        return strlen(*output);
    }
}
size_t wcom_unmerge(const char *file_path, char ** output){
    char final_path[PATH_MAX + 1];

    if (_jailfile(final_path, INCOMING_DIR, file_path) > PATH_MAX) {
        merror("At WCOM unmerge: Invalid file name");
        *output = strdup("err Invalid file name");
        return strlen(*output);
    }

    if (UnmergeFiles(final_path, isChroot() ? INCOMING_DIR : DEFAULTDIR INCOMING_DIR, OS_BINARY) == 0){
        merror("At WCOM unmerge: Error unmerging file '%s.'", final_path);
        *output = strdup("err Cannot unmerge file");
        return strlen(*output);
    } else {
        *output = strdup("ok");
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

    if (_jailfile(final_source, INCOMING_DIR, source) > PATH_MAX) {
        merror("At WCOM uncompress: Invalid file name");
        *output = strdup("err Invalid file name");
        return strlen(*output);
    }

    if (_jailfile(final_target, INCOMING_DIR, target) > PATH_MAX) {
        merror("At WCOM uncompress: Invalid file name");
        *output = strdup("err Invalid file name");
        return strlen(*output);
    }

    if (fsource = gzopen(final_source, "rb"), !fsource) {
        merror("At WCOM uncompress: Unable to open '%s'", final_source);
        *output = strdup("err Unable to open source");
        return strlen(*output);
    }

    if (ftarget = fopen(final_target, "wb"), !ftarget) {
        gzclose(fsource);
        merror("At WCOM uncompress: Unable to open '%s'", final_target);
        *output = strdup("err Unable to open target");
        return strlen(*output);
    }

    while (length = gzread(fsource, buffer, 4096), length > 0) {
        if ((int)fwrite(buffer, 1, length, ftarget) != length) {
            gzclose(fsource);
            fclose(ftarget);
            merror("At WCOM uncompress: Unable to write '%s'", final_target);
            *output = strdup("err Unable to write target");
            return strlen(*output);
        }
    }

    if (length < 0) {
        merror("At WCOM uncompress: Unable to read '%s'", final_source);
        *output = strdup("err Unable to read source");
    } else {
        unlink(final_source);
        *output = strdup("ok");
    }

    gzclose(fsource);
    fclose(ftarget);
    return strlen(*output);
}

size_t wcom_upgrade(const char * package, const char * installer, char ** output) {
    char installer_j[PATH_MAX + 1];
    char compressed[PATH_MAX + 1];
    char merged[PATH_MAX + 1];
    req_timeout = 0;
    int status;
    char *out;

    if (req_timeout == 0) {
        req_timeout = getDefine_Int("execd", "request_timeout", 1, 3600);
    }

    // Unsign

    if (_unsign(package, compressed) < 0) {
        *output = strdup("err Could not verify signature");
        return strlen(*output);
    }

    // Uncompress

    if (_uncompress(compressed, package, merged) < 0) {
        unlink(compressed);
        *output = strdup("err Could not uncompress package");
        return strlen(*output);
    }

    // Clean up upgrade folder

#ifndef WIN32
    if (cldir_ex(isChroot() ? UPGRADE_DIR : DEFAULTDIR UPGRADE_DIR)) {
#else
    if (cldir_ex(UPGRADE_DIR)) {
#endif
        merror("At WCOM upgrade: Could not clean up upgrade directory");
        *output = strdup("err Cannot clean up directory");
        return strlen(*output);
    }
    // Unmerge

#ifndef WIN32
    if (UnmergeFiles(merged, isChroot() ? UPGRADE_DIR : DEFAULTDIR UPGRADE_DIR, OS_BINARY) == 0) {
#else
    if (UnmergeFiles(merged, UPGRADE_DIR, OS_BINARY) == 0) {
#endif
        unlink(merged);
        merror("At WCOM upgrade: Error unmerging file '%s.'", merged);
        *output = strdup("err Cannot unmerge file");
        return strlen(*output);
    }

    unlink(merged);

    // Installer executable file

    if (_jailfile(installer_j, UPGRADE_DIR, installer) > PATH_MAX) {
        merror("At WCOM upgrade: Invalid file name '%s'", installer);
        *output = strdup("err Invalid installer name");
        return strlen(*output);
    }

    // Execute

#ifndef WIN32
    if (chmod(installer_j, 0750) < 0) {
        merror("At WCOM upgrade: Could not chmod '%s'", installer_j);
        *output = strdup("err Could not chmod");
        return strlen(*output);
    }
#endif

    if (wm_exec(installer_j, &out, &status, req_timeout, NULL) < 0) {
        merror("At WCOM upgrade: Error executing command [%s]", installer_j);
        *output = strdup("err Cannot execute installer");
        return strlen(*output);
    } else {
        os_malloc(OS_MAXSTR + 1, *output);
        int offset = snprintf(*output, OS_MAXSTR, "ok %d ", status);
        strncpy(*output + offset, out, OS_MAXSTR - offset + 1);
        free(out);
        return strlen(*output);
    }
}

size_t wcom_upgrade_result(char ** output){
    char buffer[20];

#ifndef WIN32
    const char * PATH = isChroot() ? UPGRADE_DIR "/upgrade_result" : DEFAULTDIR UPGRADE_DIR "/upgrade_result";
#else
    const char * PATH = UPGRADE_DIR "\\upgrade_result";
#endif

    FILE * result_file;

#ifndef WIN32
    if (result_file = fopen(PATH, "r"), result_file) {
#else
    if (result_file = fopen(PATH, "rb"), result_file) {
#endif
        if (fgets(buffer,20,result_file)){
            os_malloc(OS_MAXSTR + 1, *output);
            snprintf(*output, OS_MAXSTR, "ok %s", buffer);
            fclose(result_file);
            return strlen(*output);
        }
        fclose(result_file);
    }
    *output = strdup("err Cannot read upgrade_result file.");
    mdebug1("At WCOM upgrade_result: Cannot read file '%s'.", PATH);
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
                merror("At WCOM upgrade_result: Cannot fork");
            break;
            case 0:
                sleep(1);
                if (execv(exec_cmd[0], exec_cmd) < 0) {
                    merror(EXEC_CMDERROR, *exec_cmd, strerror(errno));
                    _exit(1);
                }
            break;
            default:
                *output = strdup("ok");
            break;
        }
#else
        char exec_cm[] = {"\"" AR_BINDIR "/restart-ossec.cmd\" add \"-\" \"null\" \"(from_the_server) (no_rule_id)\""};
        ExecCmd_Win32(exec_cm);
        if (!*output) *output = strdup("ok");
#endif
    } else {
        minfo(LOCK_RES, (int)lock);
    }

    return strlen(*output);
}


size_t wcom_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "active-response") == 0){
        if (cfg = getARConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "logging") == 0){
        if (cfg = getLoggingConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getExecdInternalOptions(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
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
            *output = strdup("err Unable to connect with socket. The component might be disabled");
            return strlen(*output);
        }
        else {
            close(sock);

            if (cfg = getClusterConfig(), cfg) {
                *output = strdup("ok");
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
    *output = strdup("err Could not get requested section");
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
            free(response);
            close(peer);
        }
        free(buffer);
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

int _unsign(const char * source, char dest[PATH_MAX + 1]) {
    const char TEMPLATE[] = ".gz.XXXXXX";
    char source_j[PATH_MAX + 1];
    size_t length;
    int output = 0;

    if (_jailfile(source_j, INCOMING_DIR, source) > PATH_MAX) {
        merror("At unsign(): Invalid file name '%s'", source);
        return -1;
    }

    if (_jailfile(dest, TMP_DIR, source) > PATH_MAX) {
        merror("At unsign(): Invalid file name '%s'", source);
        return -1;
    }

    if (length = strlen(dest), length + 10 > PATH_MAX) {
        merror("At unsign(): Too long temp file.");
        return -1;
    }

    memcpy(dest + length, TEMPLATE, sizeof(TEMPLATE));
    mode_t old_mask = umask(0022);
#ifndef WIN32
    int fd;

    if (fd = mkstemp(dest), fd >= 0) {
        close(fd);

        if (chmod(dest, 0640) < 0) {
            unlink(dest);
            merror("At unsign(): Couldn't chmod '%s'", dest);
            output = -1;
        }
    } else {
#else
    if (!_mktemp(dest)) {
#endif
        merror("At unsign(): Couldn't create temporary compressed file");
        output = -1;
    }

    if (w_wpk_unsign(source_j, dest, (const char **)wcom_ca_store) < 0) {
        unlink(dest);
        merror("At unsign: Couldn't unsign package file '%s'", source_j);
        output = -1;
    }
    umask(old_mask);
    unlink(source);
    return output;
}

int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]) {
    const char TEMPLATE[] = ".mg.XXXXXX";
    char buffer[4096];
    gzFile fsource;
    FILE *ftarget;

    if (_jailfile(dest, TMP_DIR, package) > PATH_MAX) {
        merror("At uncompress(): Invalid file name '%s'", package);
        return -1;
    }

    {
        size_t length;

        if (length = strlen(dest), length + 10 > PATH_MAX) {
            merror("At uncompress(): Too long temp file.");
            return -1;
        }

        memcpy(dest + length, TEMPLATE, sizeof(TEMPLATE));
    }

    if (fsource = gzopen(source, "rb"), !fsource) {
        merror("At uncompress(): Unable to open '%s'", source);
        return -1;
    }

    if (ftarget = fopen(dest, "wb"), !ftarget) {
        gzclose(fsource);
        merror("At uncompress(): Unable to open '%s'", dest);
        return -1;
    }

    {
        int length;

        while (length = gzread(fsource, buffer, sizeof(buffer)), length > 0) {
            if ((int)fwrite(buffer, 1, length, ftarget) != length) {
                unlink(dest);
                gzclose(fsource);
                fclose(ftarget);
                merror("At uncompress(): Unable to write '%s'", source);
                return -1;
            }
        }

        gzclose(fsource);
        fclose(ftarget);

        if (length < 0) {
            unlink(dest);
            merror("At uncompress(): Unable to read '%s'", source);
            return -1;
        }
    }

    unlink(source);
    return 0;
}

size_t lock_restart(int timeout) {
    pending_upg = time(NULL) + (time_t) timeout;
    return 0;
}
