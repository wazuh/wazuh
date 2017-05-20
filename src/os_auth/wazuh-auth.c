/*
 * Local Authd client
 * Copyright (C) 2017 Wazuh Inc.
 * May 20, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "addagent/manage_agents.h"
#include "os_net/os_net.h"

#define ACTION_NONE 0
#define ACTION_INSERT 1
#define ACTION_REMOVE 2
#define ACTION_EXTRACT 3

static void helpmsg();
static char* _get_string_or_die(cJSON *object, const char *string);

int main(int argc, char **argv) {
    int c;
    int sock;
    int force = 0;
    int json_format = 0;
    int action = ACTION_NONE;
    char id[9];
    char *name;
    char *ip = "any";
    char *output;
    char buffer[OS_MAXSTR + 1];
    ssize_t length;
    uid_t uid;
    gid_t gid;
    cJSON *request;
    cJSON *arguments;
    cJSON *response;
    cJSON *error;
    cJSON *message;
    cJSON *data;

    // Set __local_name
    OS_SetName("wazuh-auth");

    // Read configuration

    while (c = getopt(argc, argv, "a:e:fhi:jr:V"), c != -1) {
        switch (c) {
        case 'a':
            if (optarg) {
                action = ACTION_INSERT;
                name = optarg;
            } else {
                ErrorExit("%s: ERROR: -%c needs an argument.", __local_name, c);
            }

            break;

        case 'e':
            if (optarg) {
                action = ACTION_EXTRACT;
                strncpy(id, optarg, 8);
                FormatID(id);
            } else {
                ErrorExit("%s: ERROR: -%c needs an argument.", __local_name, c);
            }

            break;

        case 'f':
            force++;
            break;

        case 'h':
            helpmsg();
            break;

        case 'i':
            if (optarg) {
                ip = optarg;
            } else {
                ErrorExit("%s: ERROR: -%c needs an argument.", __local_name, c);
            }

            break;

        case 'j':
            json_format++;
            break;

        case 'r':
            if (optarg) {
                action = ACTION_REMOVE;
                strncpy(id, optarg, 8);
                FormatID(id);
            } else {
                ErrorExit("%s: ERROR: -%c needs an argument.", __local_name, c);
            }

            break;

        case 'V':
            print_version();
            break;

        default:
            helpmsg();
        }
    }

    // Test configuration

    if (action == ACTION_NONE) {
        ErrorExit("%s: ERROR: No action specified.", __local_name);
    }

    // Change user, group and root directory

    uid = Privsep_GetUser(USER);
    gid = Privsep_GetGroup(GROUPGLOBAL);

    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, __local_name, USER, GROUPGLOBAL);
    }

    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, __local_name, GROUPGLOBAL, errno, strerror(errno));
    }

    if (Privsep_Chroot(DEFAULTDIR) < 0) {
        ErrorExit(CHROOT_ERROR, __local_name, DEFAULTDIR, errno, strerror(errno));
    }

    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, __local_name, USER, errno, strerror(errno));
    }

    // Create objects and socket

    if (sock = OS_ConnectUnixDomain(AUTH_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        ErrorExit("%s: Unable to connect to ossec-auth daemon. Is it running?", __local_name);
    }

    request = cJSON_CreateObject();
    cJSON_AddItemToObject(request, "arguments", arguments = cJSON_CreateObject());

    switch (action) {
    case ACTION_INSERT:
        cJSON_AddStringToObject(request, "function", "add");
        cJSON_AddStringToObject(arguments, "name", name);
        cJSON_AddStringToObject(arguments, "ip", ip);

        if (force) {
            cJSON_AddTrueToObject(arguments, "force");
        }

        break;

    case ACTION_REMOVE:
        cJSON_AddStringToObject(request, "function", "remove");
        cJSON_AddStringToObject(arguments, "id", id);

        break;

    case ACTION_EXTRACT:
        cJSON_AddStringToObject(request, "function", "get");
        cJSON_AddStringToObject(arguments, "id", id);
        break;

    default:
        ErrorExit("%s: CRITICAL: Undefined action (1).", __local_name);
    }

    output = cJSON_PrintUnformatted(request);
    send(sock, output, strlen(output), 0);
    cJSON_Delete(request);
    free(output);

    switch (length = recv(sock, buffer, OS_MAXSTR, 0), length) {
    case -1:
        ErrorExit("%s: ERROR: recv(): %s", __local_name, strerror(errno));
        break;

    case 0:
        ErrorExit("%s: DEBUG: empty message from local server.", __local_name);
        break;

    default:
        buffer[length] = '\0';

        // Decode response

        if (response = cJSON_Parse(buffer), !response) {
            ErrorExit("%s: ERROR: Parsing JSON response.", __local_name);
        }

        // Detect error condition

        if (error = cJSON_GetObjectItem(response, "error"), !error) {
            ErrorExit("%s: ERROR: No such status from response.", __local_name);
        } else if (error->valueint > 0) {
            if (json_format) {
                printf("%s", buffer);
            } else {
                message = cJSON_GetObjectItem(response, "message");
                ErrorExit("%s: ERROR %d: %s", __local_name, error->valueint, message ? message->valuestring : "(undefined)");
            }
        } else {

            // Output data

            switch (action) {
            case ACTION_INSERT:
                if (data = cJSON_GetObjectItem(response, "data"), !data) {
                    ErrorExit("%s: ERROR: No data received.", __local_name);
                }

                if (json_format) {
                    printf("%s", buffer);
                } else {
                    printf("Agent added with ID '%s'\n", _get_string_or_die(data, "id"));
                }

                break;

            case ACTION_REMOVE:
                if (json_format) {
                    printf("%s", buffer);
                } else {
                    printf("Agent '%s' sucessfully removed.\n", id);
                }

                break;

            case ACTION_EXTRACT:
                if (data = cJSON_GetObjectItem(response, "data"), !data) {
                    ErrorExit("%s: ERROR: No data received.", __local_name);
                }

                // Produce base64 exchange code

                snprintf(buffer, OS_MAXSTR + 1, "%s %s %s %s", id, _get_string_or_die(data, "name"), _get_string_or_die(data, "ip"), _get_string_or_die(data, "key"));
                output = encode_base64(0, buffer);

                if (json_format) {
                    cJSON_AddStringToObject(data, "exchange", output);
                    free(output);
                    output = cJSON_PrintUnformatted(response);
                    printf("%s", output);
                    free(output);
                } else {
                    printf("Agent ID:      %s\n", id);
                    printf("Agent name:    %s\n", _get_string_or_die(data, "name"));
                    printf("Authorized IP: %s\n", _get_string_or_die(data, "ip"));
                    printf("Exchange key:  %s\n", output);
                    free(output);
                }

                break;

            default:
                ErrorExit("%s: CRITICAL: Undefined action (2).", __local_name);
            }
        }

        free(response);

    }

    close(sock);
    return EXIT_SUCCESS;
}

static void helpmsg()
{
    print_header();

    print_out("  %s: -[Vhj] -a <name> [ -f ] [ -i <ip> ] | -r <id> | -e <id>", __local_name);
    print_out("    -a <name>   Add new agent.");
    print_out("    -r <id>     Remove an agent.");
    print_out("    -e <id>     Extracts key for an agent.");
    print_out("    -i <ip>     IP for new agent. Default: any.");
    print_out("    -f          Force insertion (remove agents with duplicated name or IP).");
    print_out("    -j          Use JSON output.");
    print_out("    -V          Version and license message.");
    print_out("    -h          This help message.");

    exit(EXIT_FAILURE);
}

char* _get_string_or_die(cJSON *object, const char *string) {
    cJSON *item;

    if (item = cJSON_GetObjectItem(object, string), !string) {
        ErrorExit("%s: ERROR: No such item '%s' at JSON.", __local_name, string);
    }

    return item->valuestring;
}
