/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"
#include "dll_load_notify.h"

#ifdef WIN32
#include <iphlpapi.h>

/**
 * @brief Resolve a fixed Windows system tool directly under the system directory
 * (e.g. C:\Windows\System32), instead of searching PATH. On failure, falls back to
 * the bare binary name, matching get_binary_path()'s own fallback convention.
 * @param binary Name of the binary to resolve
 * @param validated_comm Output parameter for the resolved path (caller must free)
 * @return OS_SUCCESS if resolved under the system directory, OS_INVALID otherwise
 */
static int resolve_system_tool(const char *binary, char **validated_comm) {
    char sys_dir[MAX_PATH];
    char full_path[OS_MAXSTR];

    if (GetSystemDirectoryA(sys_dir, sizeof(sys_dir)) == 0) {
        if (validated_comm) {
            *validated_comm = strdup(binary);
        }
        return OS_INVALID;
    }

    snprintf(full_path, OS_MAXSTR - 1, "%s\\%s", sys_dir, binary);

    if (IsFile(full_path) != 0) {
        if (validated_comm) {
            *validated_comm = strdup(binary);
        }
        return OS_INVALID;
    }

    if (validated_comm) {
        *validated_comm = strdup(full_path);
    }
    return OS_SUCCESS;
}

/**
 * @brief Parse a validated dotted-quad IPv4 string into a network-byte-order
 * address (as GetBestRoute expects), without pulling in a winsock link dependency.
 */
static DWORD ipv4_to_network(const char *ip) {
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
        a > 255 || b > 255 || c > 255 || d > 255) {
        return INADDR_NONE;
    }
    return (DWORD)(a | (b << 8) | (c << 16) | (d << 24));
}

/**
 * @brief Confirm the /32 blackhole for srcip is actually in the active routing table.
 * route.exe exits 0 even when it rejects the route, so the exit code alone is not proof.
 * Query the forwarding table and require a host route (/32) that resolves through the
 * loopback interface (IF 1) we asked for.
 */
static bool route_blackhole_is_active(const char *srcip) {
    DWORD dest = ipv4_to_network(srcip);
    if (dest == INADDR_NONE) {
        return false;
    }

    MIB_IPFORWARDROW row;
    memset(&row, 0, sizeof(row));
    if (GetBestRoute(dest, 0, &row) != NO_ERROR) {
        return false;
    }

    return row.dwForwardMask == 0xFFFFFFFF && row.dwForwardIfIndex == 1;
}
#endif

int main (int argc, char **argv) {
#ifdef WIN32
    // This must be always the first instruction
    enable_dll_verification();
#endif

    (void)argc;
    int action = OS_INVALID;
    cJSON *input_json = NULL;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Get srcip
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (action == ADD_COMMAND) {
        char **keys = NULL;
        int action2 = OS_INVALID;

        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);

        os_free(keys);

        // If necessary, abort execution
        if (action2 != CONTINUE_COMMAND) {
            cJSON_Delete(input_json);

            if (action2 == ABORT_COMMAND) {
                write_debug_file(argv[0], "Aborted");
                return OS_SUCCESS;
            } else {
                return OS_INVALID;
            }
        }
    }

#ifndef WIN32
    struct utsname uname_buffer;
    wfd_t *wfd = NULL;
    char *route_path = NULL;
    char log_msg[OS_MAXSTR];

    if (get_binary_path("route", &route_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", route_path);
        write_debug_file(argv[0], log_msg);
    }

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        os_free(route_path);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        if (action == ADD_COMMAND) {
            char *exec_cmd1[5] = { route_path, "add", (char *)srcip, "reject", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *exec_cmd1[5] = { route_path, "del", (char *)srcip, "reject", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        if (action == ADD_COMMAND) {
            char *exec_cmd1[7] = { route_path, "-q", "add", (char *)srcip, "127.0.0.1", "-blackhole", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        } else {
            char *exec_cmd1[7] = { route_path, "-q", "delete", (char *)srcip, "127.0.0.1", "-blackhole", NULL };

            wfd = wpopenv(route_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run route");
            } else {
                wpclose(wfd);
            }
        }
    } else {
        write_debug_file(argv[0], "Invalid system");
    }
    os_free(route_path);
#else
    char log_msg[OS_MAXSTR];
    char *route_path = NULL;

    // Fail closed: falling back to the bare name would let CreateProcess resolve the
    // tool via %PATH% again, which this change avoids.
    if (resolve_system_tool("route.exe", &route_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Could not resolve 'route.exe' under the system directory, aborting to avoid PATH-based execution.");
        write_debug_file(argv[0], log_msg);
        os_free(route_path);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (strchr(srcip, ':') != NULL) {
        // The route fallback is IPv4-only (MASK 255.255.255.255); skip IPv6 like 5.0 does.
        if (action == ADD_COMMAND) {
            write_debug_file(argv[0], "route fallback supports IPv4 only - skipping IPv6 target");
        } else {
            write_debug_file(argv[0], "route fallback is IPv4-only - no route to remove for IPv6 target");
        }
    } else if (action == ADD_COMMAND) {
        // Blackhole the source IP through the loopback interface (gateway 0.0.0.0, IF 1):
        // this stays in the active routing table. A 127.0.0.1 gateway is only saved to the
        // persistent store and never becomes active, so it would not block anything.
        char *exec_args_add[10] = { route_path, "-p", "ADD", (char *)srcip, "MASK", "255.255.255.255", "0.0.0.0", "IF", "1", NULL };

        wfd_t *wfd = wpopenv(route_path, exec_args_add, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to run %s, action: 'ADD'", route_path);
            write_debug_file(argv[0], log_msg);
        }
        else {
            int rc = wpclose(wfd);
            if (rc != 0) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "%s returned %d, action: 'ADD'", route_path, rc);
                write_debug_file(argv[0], log_msg);
            }
            else if (!route_blackhole_is_active(srcip)) {
                // route.exe exits 0 even when it silently rejects the route, so confirm it took.
                write_debug_file(argv[0], "route add reported success but the blackhole route is not in the active table");
            }
        }
    } else {
        char *exec_args_delete[4] = { route_path, "DELETE", (char *)srcip, NULL };

        wfd_t *wfd = wpopenv(route_path, exec_args_delete, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to run %s, action: 'DELETE'", route_path);
            write_debug_file(argv[0], log_msg);
        }
        else {
            int rc = wpclose(wfd);
            if (rc != 0) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "%s returned %d, action: 'DELETE'", route_path, rc);
                write_debug_file(argv[0], log_msg);
            }
        }
    }
    os_free(route_path);
#endif

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}
