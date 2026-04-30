/*
 * Wazuh Module for custom command execution
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "time_op.h"

#ifdef WIN32
#include <windows.h>
#else
#endif

static char *wm_command_build_event_payload(const char *event_start,
                                            const char *tag,
                                            const char *command_line,
                                            const char *proc_name,
                                            const char *proc_path,
                                            char **proc_argv,
                                            const wm_command_t *command,
                                            int status,
                                            const char *payload_output);

#ifdef WIN32
static DWORD WINAPI wm_command_main(void *arg);             // Module main function. It won't return
#else
static void * wm_command_main(wm_command_t * command);    // Module main function. It won't return
#endif
static void wm_command_destroy(wm_command_t * command);   // Destroy data
cJSON *wm_command_dump(const wm_command_t * command);
int validate_command_checksums(wm_command_t * command, const char * full_path); // Validate checksums

static char *wm_command_build_event_payload(const char *event_start,
                                            const char *tag,
                                            const char *command_line,
                                            const char *proc_name,
                                            const char *proc_path,
                                            char **proc_argv,
                                            const wm_command_t *command,
                                            int status,
                                            const char *payload_output) {
    cJSON *json_event = NULL;
    char *json_payload = NULL;

    json_event = cJSON_CreateObject();
    if (!json_event) {
        return NULL;
    }

    cJSON_AddStringToObject(json_event, "event.module", "wazuh-wodle-cmd");
    cJSON_AddStringToObject(json_event, "event.start", event_start ? event_start : "");
    if (tag) {
        cJSON_AddStringToObject(json_event, "tags", tag);
    }

    cJSON *process = cJSON_AddObjectToObject(json_event, "process");
    if (process) {
        cJSON *process_args = cJSON_AddArrayToObject(process, "args");
        if (process_args && proc_argv) {
            for (size_t i = 1; proc_argv[i]; ++i) {
                cJSON_AddItemToArray(process_args, cJSON_CreateString(proc_argv[i]));
            }
        }

        cJSON_AddStringToObject(process, "name", proc_name ? proc_name : "");
        cJSON_AddStringToObject(process, "path", proc_path ? proc_path : "");
        cJSON_AddStringToObject(process, "command_line", command_line ? command_line : "");

        if (command && ((command->md5_hash && command->md5_hash[0]) || (command->sha1_hash && command->sha1_hash[0]) ||
                        (command->sha256_hash && command->sha256_hash[0]))) {
            cJSON *hash = cJSON_AddObjectToObject(process, "hash");

            if (hash) {
                if (command->md5_hash && command->md5_hash[0]) {
                    cJSON_AddStringToObject(hash, "md5", command->md5_hash);
                }
                if (command->sha1_hash && command->sha1_hash[0]) {
                    cJSON_AddStringToObject(hash, "sha1", command->sha1_hash);
                }
                if (command->sha256_hash && command->sha256_hash[0]) {
                    cJSON_AddStringToObject(hash, "sha256", command->sha256_hash);
                }
            }
        }

        cJSON_AddNumberToObject(process, "exit_code", status);

        cJSON *process_io = cJSON_AddObjectToObject(process, "io");
        if (process_io) {
            cJSON_AddStringToObject(process_io, "text", payload_output ? payload_output : "");
        }
    }

    json_payload = cJSON_PrintUnformatted(json_event);
    cJSON_Delete(json_event);

    return json_payload;
}

// Command module context definition

const wm_context WM_COMMAND_CONTEXT = {
    .name = "command",
    .start = (wm_routine)wm_command_main,
    .destroy = (void(*)(void *))wm_command_destroy,
    .dump = (cJSON * (*)(const void *))wm_command_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

// Module module main function. It won't return.

#ifdef WIN32
DWORD WINAPI wm_command_main(void *arg) {
    wm_command_t * command = (wm_command_t *)arg;
#else
void * wm_command_main(wm_command_t * command) {
#endif
    size_t extag_len;
    char * extag;
    int usec = 1000000 / wm_max_eps;
    char *command_cpy;
    char *binary;
    char *full_path = NULL;
    char **argv;
    char * timestamp = NULL;
    bool verify_command = command->md5_hash || command->sha1_hash || command->sha256_hash;

    if (!command->enabled) {
        mtinfo(WM_COMMAND_LOGTAG, "Module command:%s is disabled. Exiting.", command->tag);
        pthread_exit(0);
    }

    if (command->agent_cfg && !getDefine_Int_default("wazuh_command", "remote_commands", 0, 1, 0)) {
        mtwarn(WM_COMMAND_LOGTAG, "Remote commands are disabled. Ignoring '%s'.", command->tag);
        pthread_exit(0);
    }

    if (verify_command) {
        command_cpy = strdup(command->command);

        argv = w_strtok(command_cpy);
    #ifndef __clang_analyzer__
        if (!argv) {
            merror("Could not split command: %s", command_cpy);
            pthread_exit(NULL);
        }
    #endif
        binary = argv[0];

        if (get_binary_path(binary, &full_path) == OS_INVALID) {
            mterror(WM_COMMAND_LOGTAG, "Cannot check binary: '%s'. Cannot stat binary file.", binary);
            pthread_exit(NULL);
        }

        // Modify command with full path.
        if (!command->full_command) {
            os_malloc(strlen(full_path) + strlen(command->command) - strlen(binary) + 1, command->full_command);
        }
        snprintf(command->full_command, strlen(full_path) + strlen(command->command) - strlen(binary) + 1, "%s %s", full_path, command->command + strlen(binary) + 1);
        free_strarray(argv);

        if (validate_command_checksums(command, full_path) != 0) {
            os_free(full_path);
            pthread_exit(NULL);
        }

        free(command_cpy);

    } else {
        command->full_command = strdup(command->command);
    }

    mtinfo(WM_COMMAND_LOGTAG, "Module command:%s started", command->tag);

    // Set extended tag

    // Keep a stable routing tag for all command events.
    extag_len = strlen(WM_COMMAND_CONTEXT.name) + 1;
    os_malloc(extag_len * sizeof(char), extag);
    snprintf(extag, extag_len, "%s", WM_COMMAND_CONTEXT.name);

    if (wm_state_io(extag, WM_IO_READ, &command->state, sizeof(command->state)) < 0) {
        memset(&command->state, 0, sizeof(command->state));
    }

    // Connect to socket

#ifndef WIN32
    if (!command->ignore_output) {

        command->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

        if (command->queue_fd < 0) {
            mterror(WM_COMMAND_LOGTAG, "Can't connect to queue.");
            if (verify_command) {
                os_free(full_path);
            }

            pthread_exit(NULL);
        }
    }
#endif

    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(command->scan_config), WM_COMMAND_LOGTAG, command->run_on_start);

        if(command->state.next_time == 0) {
            command->state.next_time = command->scan_config.time_start + time_sleep;
        }

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(command->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_COMMAND_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }

        if (full_path != NULL && verify_command && !command->skip_verification) {
            mtinfo(WM_COMMAND_LOGTAG, "Verifying command checksum '%s'.", command->tag);
            if (validate_command_checksums(command, full_path) != 0) {
                os_free(full_path);
                pthread_exit(NULL);
            }
        }

        mtinfo(WM_COMMAND_LOGTAG, "Starting command '%s'.", command->tag);

        int status = 0;
        char *output = NULL;
        char event_start[32] = {0};
        get_iso8601_utc_time(event_start, sizeof(event_start));
        switch (wm_exec(command->full_command, command->ignore_output ? NULL : &output, &status, command->timeout, NULL)) {
        case 0:
            if (status > 0) {
                mtwarn(WM_COMMAND_LOGTAG, "Command '%s' returned exit code %d.", command->tag, status);

                if (!command->ignore_output) {
                    mtdebug2(WM_COMMAND_LOGTAG, "OUTPUT: %s", output);
                }
            }
            break;
        case WM_ERROR_TIMEOUT:
            mterror(WM_COMMAND_LOGTAG, "%s: Timeout overtaken. You can modify your command timeout at '%s'. Exiting...", command->tag, WAZUHCONF);
            break;

        default:
            mterror(WM_COMMAND_LOGTAG, "Command '%s' failed.", command->tag);
            break;
        }

        if (!command->ignore_output) {
            char *json_payload = NULL;
            const char *raw_output = output ? output : "";
            const char *payload_output = raw_output;
            char *truncated_output = NULL;
            const size_t header_len = 3 + strlen(extag); // "1:" + extag + ":"
            const size_t max_message_len = header_len < OS_MAXSTR ? (OS_MAXSTR - header_len - 1) : 0;

            // Best-effort process details.
            const char *command_line = command->full_command ? command->full_command : "";
            char *command_line_cpy = NULL;
            char **proc_argv = NULL;
            const char *proc_argv0 = "";
            char *tmp_full_path = NULL;
            const char *proc_path = full_path ? full_path : "";
            const char *proc_name = "";
            if (command_line[0]) {
                command_line_cpy = strdup(command_line);
                if (command_line_cpy) {
                    proc_argv = w_strtok(command_line_cpy);
                    if (proc_argv && proc_argv[0]) {
                        proc_argv0 = proc_argv[0];
                    }
                }
            }

            if (!full_path && proc_argv0 && proc_argv0[0]) {
                if (get_binary_path(proc_argv0, &tmp_full_path) != OS_INVALID) {
                    proc_path = tmp_full_path;
                }
            }

            if (proc_path && proc_path[0]) {
                const char *slash = strrchr(proc_path, '/');
                const char *backslash = strrchr(proc_path, '\\');
                const char *separator = slash;

                if (backslash && (!separator || backslash > separator)) {
                    separator = backslash;
                }

                proc_name = separator ? (separator + 1) : proc_path;
            } else if (proc_argv0 && proc_argv0[0]) {
                const char *slash = strrchr(proc_argv0, '/');
                const char *backslash = strrchr(proc_argv0, '\\');
                const char *separator = slash;

                if (backslash && (!separator || backslash > separator)) {
                    separator = backslash;
                }

                proc_name = separator ? (separator + 1) : proc_argv0;
            }

            size_t base_json_len = 0;

            // Compute JSON overhead with all fields except output content.
            {
                char *base_payload = wm_command_build_event_payload(event_start,
                                                                    command->tag,
                                                                    command_line,
                                                                    proc_name,
                                                                    proc_path,
                                                                    proc_argv,
                                                                    command,
                                                                    status,
                                                                    "");
                if (base_payload) {
                    base_json_len = strlen(base_payload);
                    os_free(base_payload);
                }
            }

            // Build JSON payload (single event with full output).
            json_payload = wm_command_build_event_payload(event_start,
                                                          command->tag,
                                                          command_line,
                                                          proc_name,
                                                          proc_path,
                                                          proc_argv,
                                                          command,
                                                          status,
                                                          payload_output);

            // If the final message could be truncated at the MQ layer, truncate the output and rebuild.
            if (json_payload && max_message_len > 0 && strlen(json_payload) > max_message_len) {
                const size_t output_len = strlen(raw_output);
                size_t allowed_output_len = 0;
                int attempts = 0;

                if (base_json_len > 0 && max_message_len > base_json_len) {
                    allowed_output_len = max_message_len - base_json_len;
                }

                // Best-effort: keep JSON valid by truncating the output field before encoding.
                if (allowed_output_len > 0) {
                    if (allowed_output_len > output_len) {
                        allowed_output_len = output_len;
                    }

                    mtwarn(WM_COMMAND_LOGTAG, "Command output is too long to fit in a single message. Truncating.");

                    do {
                        os_free(truncated_output);
                        truncated_output = NULL;

                        os_malloc(allowed_output_len + 1, truncated_output);
                        memcpy(truncated_output, raw_output, allowed_output_len);
                        truncated_output[allowed_output_len] = '\0';
                        payload_output = truncated_output;

                        os_free(json_payload);
                        json_payload = NULL;

                        json_payload = wm_command_build_event_payload(event_start,
                                                                      command->tag,
                                                                      command_line,
                                                                      proc_name,
                                                                      proc_path,
                                                                      proc_argv,
                                                                      command,
                                                                      status,
                                                                      payload_output);

                        if (json_payload && strlen(json_payload) <= max_message_len) {
                            break;
                        }

                        // Reduce and try again (output escaping may enlarge JSON more than expected)
                        allowed_output_len /= 2;
                        attempts++;
                    } while (allowed_output_len > 0 && attempts < 4);

                    if (json_payload && strlen(json_payload) > max_message_len) {
                        os_free(json_payload);
                        json_payload = NULL;

                        // Last-resort: send a metadata-only event.
                        mtwarn(WM_COMMAND_LOGTAG, "Command event is too large even after truncation. Dropping output but sending metadata-only event.");
                        json_payload = wm_command_build_event_payload(event_start,
                                                                      command->tag,
                                                                      command_line,
                                                                      proc_name,
                                                                      proc_path,
                                                                      proc_argv,
                                                                      command,
                                                                      status,
                                                                      "");
                    }
                } else {
                    mtwarn(WM_COMMAND_LOGTAG, "Command output is too long to fit in a single message. Dropping output but sending metadata-only event.");
                    os_free(json_payload);
                    json_payload = wm_command_build_event_payload(event_start,
                                                                  command->tag,
                                                                  command_line,
                                                                  proc_name,
                                                                  proc_path,
                                                                  proc_argv,
                                                                  command,
                                                                  status,
                                                                  "");
                }
            }
            if (json_payload) {
            #ifdef WIN32
                if (wm_sendmsg(usec, 0, json_payload, extag, LOCALFILE_MQ) < 0) {
                    mterror(WM_COMMAND_LOGTAG, "Unable to send command event to queue.");
                }
            #else
                if (wm_sendmsg(usec, command->queue_fd, json_payload, extag, LOCALFILE_MQ) < 0) {
                    mterror(WM_COMMAND_LOGTAG, "Unable to send command event to queue.");
                }
            #endif
                os_free(json_payload);
            } else {
                mtwarn(WM_COMMAND_LOGTAG, "Could not build command event payload. Dropping event.");
            }

            os_free(truncated_output);

            os_free(tmp_full_path);
            free_strarray(proc_argv);
            free(command_line_cpy);

            if (output) {
                os_free(output);
            }
        }

        mtdebug1(WM_COMMAND_LOGTAG, "Command '%s' finished.", command->tag);
    } while (FOREVER());

    os_free(full_path);
    free(extag);
#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

int validate_command_checksums(wm_command_t * command, const char * full_path) {
    if (command->md5_hash && command->md5_hash[0]) {
        if (wm_validate_command(full_path, command->md5_hash, MD5SUM) != 1) {
            if (command->skip_verification) {
                mtwarn(WM_COMMAND_LOGTAG, "MD5 checksum verification failed for command '%s'. Skipping...", command->full_command);
                return 0;
            }
            mterror(WM_COMMAND_LOGTAG, "MD5 checksum verification failed for command '%s'.", command->full_command);
            return -1;
        }
        mtdebug1(WM_COMMAND_LOGTAG, "MD5 checksum verification was successful for command '%s'.", command->full_command);
    }

    if (command->sha1_hash && command->sha1_hash[0]) {
        if (wm_validate_command(full_path, command->sha1_hash, SHA1SUM) != 1) {
            if (command->skip_verification) {
                mtwarn(WM_COMMAND_LOGTAG, "SHA1 checksum verification failed for command '%s'. Skipping...", command->full_command);
                return 0;
            }
            mterror(WM_COMMAND_LOGTAG, "SHA1 checksum verification failed for command '%s'.", command->full_command);
            return -1;
        }
        mtdebug1(WM_COMMAND_LOGTAG, "SHA1 checksum verification was successful for command '%s'.", command->full_command);
    }

    if (command->sha256_hash && command->sha256_hash[0]) {
        if (wm_validate_command(full_path, command->sha256_hash, SHA256SUM) != 1) {
            if (command->skip_verification) {
                mtwarn(WM_COMMAND_LOGTAG, "SHA256 checksum verification failed for command '%s'. Skipping...", command->full_command);
                return 0;
            }
            mterror(WM_COMMAND_LOGTAG, "SHA256 checksum verification failed for command '%s'.", command->full_command);
            return -1;
        }
        mtdebug1(WM_COMMAND_LOGTAG, "SHA256 checksum verification was successful for command '%s'.", command->full_command);
    }

    return 0;
}


// Get read data

cJSON *wm_command_dump(const wm_command_t * command) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_comm = cJSON_CreateObject();

    sched_scan_dump(&(command->scan_config), wm_comm);

    if (command->enabled) cJSON_AddStringToObject(wm_comm,"disabled","no"); else cJSON_AddStringToObject(wm_comm,"disabled","yes");
    if (command->run_on_start) cJSON_AddStringToObject(wm_comm,"run_on_start","yes"); else cJSON_AddStringToObject(wm_comm,"run_on_start","no");
    if (command->ignore_output) cJSON_AddStringToObject(wm_comm,"ignore_output","yes"); else cJSON_AddStringToObject(wm_comm,"ignore_output","no");
    if (command->skip_verification) cJSON_AddStringToObject(wm_comm,"skip_verification","yes"); else cJSON_AddStringToObject(wm_comm,"skip_verification","no");
    if (command->tag) cJSON_AddStringToObject(wm_comm,"tag",command->tag);
    if (command->command) cJSON_AddStringToObject(wm_comm,"command",command->command);
    if (command->md5_hash) cJSON_AddStringToObject(wm_comm,"verify_md5",command->md5_hash);
    if (command->sha1_hash) cJSON_AddStringToObject(wm_comm,"verify_sha1",command->sha1_hash);
    if (command->sha256_hash) cJSON_AddStringToObject(wm_comm,"verify_sha256",command->sha256_hash);

    cJSON_AddItemToObject(root,"command",wm_comm);

    return root;
}


// Destroy data
void wm_command_destroy(wm_command_t * command) {
    free(command->tag);
    free(command->command);
    free(command->full_command);
    free(command);
}
