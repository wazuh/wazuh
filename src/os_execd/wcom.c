/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
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
#include "rootcheck/rootcheck.h"

static int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);
int req_timeout;
int max_restart_lock;

size_t wcom_dispatch(char *command, char ** output) {
    char *rcv_comm = command;
    char *rcv_args = NULL;
    char * source;
    char * target;

    if ((rcv_args = strchr(rcv_comm, ' '))) {
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "unmerge") == 0) {
        if (!rcv_args) {
            mdebug1("WCOM unmerge needs arguments.");
            os_strdup("err WCOM unmerge needs arguments", *output);
            return strlen(*output);
        }
        // unmerge [file_path]
        return wcom_unmerge(rcv_args, output);

    } else if (strcmp(rcv_comm, "uncompress") == 0) {
        if (!rcv_args) {
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

    } else if (strcmp(rcv_comm, "restart") == 0 || strcmp(rcv_comm, "restart-wazuh") == 0) {
        return wcom_restart(output);

    } else if (strcmp(rcv_comm, "reload")  == 0) {
        return wcom_reload(output);

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

    } else if (strcmp(rcv_comm, "getconfig") == 0) {
        // getconfig section
        if (!rcv_args) {
            mdebug1("WCOM getconfig needs arguments.");
            os_strdup("err WCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return wcom_getconfig(rcv_args, output);

    } else if (strcmp(rcv_comm, "check-manager-configuration") == 0) {
        return wcom_check_manager_config(output);

    } else {
        mdebug1("WCOM Unrecognized command '%s'.", rcv_comm);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

size_t wcom_unmerge(const char *file_path, char ** output) {
    char final_path[PATH_MAX + 1];

    if (_jailfile(final_path, INCOMING_DIR, file_path) < 0) {
        merror("At WCOM unmerge: Invalid file name");
        os_strdup("err Invalid file name", *output);
        return strlen(*output);
    }

    if (UnmergeFiles(final_path, INCOMING_DIR, OS_BINARY, NULL) == 0) {
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

    if (ftarget = wfopen(final_target, "wb"), !ftarget) {
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

size_t wcom_restart(char ** output) {
    time_t lock = pending_upg - time(NULL);
    if (lock <= 0) {
#ifndef WIN32
        char *exec_cmd[3] = {NULL};

        if (waccess("active-response/bin/restart.sh", F_OK) == 0) {
            exec_cmd[0] = "active-response/bin/restart.sh";
#ifdef CLIENT
            exec_cmd[1] = "agent";
#else
            exec_cmd[1] = "manager";
#endif
        } else {
            exec_cmd[0] = "bin/wazuh-control";
            exec_cmd[1] = "restart";
        }

        switch (fork()) {
            case -1:
                merror("At WCOM restart: Cannot fork");
                os_strdup("err Cannot fork", *output);
            break;
            case 0:
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
        static char command[OS_FLSIZE];
        snprintf(command, sizeof(command), "%s/%s", AR_BINDIR, "restart-wazuh.exe");
        char *cmd[2] = { command, NULL };
        char *cmd_parameters = "{\"version\":1,\"origin\":{\"name\":\"\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{\"extra_args\":[],\"alert\":{},\"program\":\"restart-wazuh.exe\"}}";
        wfd_t *wfd = wpopenv(cmd[0], cmd, W_BIND_STDIN);
        if (wfd) {
            /* Send alert to AR script */
            fprintf(wfd->file_in, "%s\n", cmd_parameters);
            fflush(wfd->file_in);
            wpclose(wfd);
        } else {
            merror("At WCOM restart: Cannot execute restart process");
            os_strdup("err Cannot execute restart process", *output);
        }
#endif
    } else {
        minfo(LOCK_RES, (int)lock);
    }

    if (!*output) os_strdup("ok ", *output);
    return strlen(*output);
}

size_t wcom_reload(char ** output) {
    time_t lock = pending_upg - time(NULL);
    if (lock <= 0) {
#ifndef WIN32
        char *exec_cmd[4] = {NULL};

        if (waccess("active-response/bin/restart.sh", F_OK) == 0) {
            exec_cmd[0] = "active-response/bin/restart.sh";
#ifdef CLIENT
            exec_cmd[1] = "agent";
#else
            exec_cmd[1] = "manager";
#endif
            exec_cmd[2] = "reload";
        } else {
            exec_cmd[0] = "bin/wazuh-control";
            exec_cmd[1] = "reload";
        }

        switch (fork()) {
            case -1:
                merror("At WCOM reload: Cannot fork");
                os_strdup("err Cannot fork", *output);
            break;
            case 0:
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
        static char command[OS_FLSIZE];
        snprintf(command, sizeof(command), "%s/%s", AR_BINDIR, "restart-wazuh.exe");
        char *cmd[2] = { command, NULL };
        char *cmd_parameters = "{\"version\":1,\"origin\":{\"name\":\"\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{\"extra_args\":[],\"alert\":{},\"program\":\"restart-wazuh.exe\"}}";
        wfd_t *wfd = wpopenv(cmd[0], cmd, W_BIND_STDIN);
        if (wfd) {
            // Send alert to AR script
            fprintf(wfd->file_in, "%s\n", cmd_parameters);
            fflush(wfd->file_in);
            wpclose(wfd);
        } else {
            merror("At WCOM restart: Cannot execute restart process");
            os_strdup("err Cannot execute restart process", *output);
        }
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

    if (strcmp(section, "active-response") == 0) {
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
    } else if (strcmp(section, "logging") == 0) {
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
    } else if (strcmp(section, "internal") == 0) {
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
    } else if (strcmp(section, "cluster") == 0) {
#ifndef WIN32
        /* Check socket connection with cluster first */
        int sock = -1;
        char sockname[PATH_MAX + 1] = {0};

        strcpy(sockname, CLUSTER_SOCK);

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

size_t wcom_check_manager_config(char **output) {
    static const char *daemons[] = {"bin/wazuh-authd", "bin/wazuh-remoted",
                                    "bin/wazuh-execd", "bin/wazuh-engine", "bin/wazuh-logcollector",
                                    "bin/wazuh-integratord", "bin/wazuh-syscheckd", "bin/wazuh-maild",
                                    "bin/wazuh-modulesd", "bin/wazuh-clusterd", "bin/wazuh-agentlessd",
                                    "bin/wazuh-integratord", "bin/wazuh-dbd", "bin/wazuh-csyslogd", NULL
                                    };

    int response_retval = 0;
    int i;
    char command_in[PATH_MAX] = {0};
    char *response_string = NULL;
    char *command_out = NULL;
    cJSON *response = cJSON_CreateObject();

    OS_XML xml_check;
    const char *cfg = OSSECCONF;

    if (OS_ReadXML(cfg, &xml_check) < 0) {
        snprintf(response_string, 0, "Error reading %s file", cfg);
        response_retval = EXECVE_ERROR;
    } else {
        OS_ClearXML(&xml_check);

        for (i = 0; daemons[i]; i++) {
            response_retval = 0;
            snprintf(command_in, PATH_MAX, "%s -t", daemons[i]);
            // Exec a command with a timeout of 2000 seconds.
            if (wm_exec(command_in, &command_out, &response_retval, 2000, NULL) < 0) {
                if (response_retval == EXECVE_ERROR) {
                    mwarn("Path is invalid or file has insufficient permissions. %s", command_in);
                } else {
                    mwarn("Error executing [%s]", command_in);
                }

                os_free(response_string);
                size_t size = snprintf(NULL, 0, "Error executing %s - (%d)", command_in, response_retval);
                os_calloc(size + 1, sizeof(char), response_string);
                snprintf(response_string, size, "Error executing %s - (%d)", command_in, response_retval);
                break;
            }

            if (command_out && *command_out) {
                // Remove last newline
                size_t lastchar = strlen(command_out) - 1;
                command_out[lastchar] = command_out[lastchar] == '\n' ? '\0' : command_out[lastchar];

                wm_strcat(&response_string, command_out, ' ');
            }

            os_free(command_out);

            if(response_retval) {
                break;
            }
        }
    }

    cJSON_AddNumberToObject(response, "error", response_retval);

    if (response_retval) {
        char error_msg[OS_SIZE_4096 - 27] = {0};
        snprintf(error_msg, OS_SIZE_4096 - 27, "%s", response_string);
        cJSON_AddStringToObject(response, "message", error_msg);
    } else {
        cJSON_AddStringToObject(response, "message", "ok");
    }

    os_free(response_string);

    *output = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

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

    if (sock = OS_BindUnixDomain(COM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
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
            length = wcom_dispatch(buffer, &response);
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
    return snprintf(finalpath, PATH_MAX + 1, "%s/%s", basedir, filename) > PATH_MAX ? -1 : 0;
#else
    return snprintf(finalpath, PATH_MAX + 1, "%s\\%s", basedir, filename) > PATH_MAX ? -1 : 0;
#endif
}

size_t lock_restart(int timeout) {
    pending_upg = time(NULL) + (time_t) timeout;
    return 0;
}
