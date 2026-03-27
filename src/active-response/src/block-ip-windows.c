/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"
#include "helpers/firewall_helpers.h"

#ifdef WIN32

#include "dll_load_notify.h"

/**
 * Windows-specific block-ip implementation
 * Fallback chain: netsh → route
 */

firewall_result_t try_netsh(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route_windows(const char *srcip, int action, int ip_version, const char *argv0);

int main(int argc, char **argv) {
    // This must always be the first instruction on Windows
    enable_dll_verification();

    (void)argc;
    int action = OS_INVALID;
    int action2 = OS_INVALID;
    cJSON *input_json = NULL;

    // Setup and parse JSON input
    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Extract source IP from WCS-compliant JSON
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'source.ip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Send keys and check for abort (ADD command only)
    if (action == ADD_COMMAND) {
        char **keys = NULL;
        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);
        os_free(keys);

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

    // Define Windows method chain
    const firewall_method_t methods[] = {
        {"netsh", try_netsh, false},
        {"route", try_route_windows, false},
        {NULL, NULL, false}  // Sentinel
    };

    // Execute firewall chain with fallback
    int result = execute_firewall_chain(methods, srcip, action, 0, argv[0]);

    cJSON_Delete(input_json);
    return result;
}

// ============================================================================
// WINDOWS: netsh (Windows Firewall) implementation
// ============================================================================

firewall_result_t try_netsh(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // netsh handles both IPv4 and IPv6
    static const char rule_name[] = "name=\"WAZUH ACTIVE RESPONSE BLOCKED IP\"";
    char log_msg[OS_MAXSTR];
    char *netsh_path = NULL;
    char *reg_path = NULL;

    // Check if netsh.exe is available
    if (check_binary_available("netsh.exe", &netsh_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if reg.exe is available (for profile checking)
    if (get_binary_path("reg.exe", &reg_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Binary 'reg.exe' not found - skipping firewall profile check");
        write_debug_file(argv0, log_msg);
        // Continue without profile check
    }

    // Check Windows Firewall profiles if reg.exe is available
    if (reg_path) {
        const char *profiles[] = {
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
        };
        const char *profile_names[] = {"Domain", "Private", "Public"};
        bool any_enabled = false;

        for (int i = 0; i < 3; i++) {
            char *exec_cmd[] = {reg_path, "query", (char *)profiles[i], "/v", "EnableFirewall", NULL};
            wfd_t *wfd = wpopenv(reg_path, exec_cmd, W_BIND_STDOUT);

            if (wfd) {
                char output_buf[OS_MAXSTR];
                while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
                    if (strstr(output_buf, "0x1") != NULL) {
                        any_enabled = true;
                        memset(log_msg, '\0', OS_MAXSTR);
                        snprintf(log_msg, OS_MAXSTR - 1, "Windows Firewall %s profile: Enabled", profile_names[i]);
                        write_debug_file(argv0, log_msg);
                        break;
                    }
                }
                wpclose(wfd);
            }
        }

        os_free(reg_path);

        if (!any_enabled) {
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "netsh", "check",
                              "No Windows Firewall profiles are enabled");
            os_free(netsh_path);
            return FIREWALL_INVALID_STATE;
        }
    }

    // Build netsh command
    wfd_t *wfd = NULL;

    if (action == ADD_COMMAND) {
        // netsh advfirewall firewall add rule name="..." interface=any dir=in action=block remoteip=<IP>/32
        char remote_ip_arg[OS_MAXSTR];
        memset(remote_ip_arg, '\0', OS_MAXSTR);
        snprintf(remote_ip_arg, OS_MAXSTR - 1, "remoteip=%s/32", srcip);

        char *exec_cmd_in[] = {
            netsh_path,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            (char *)rule_name,
            "interface=any",
            "dir=in",
            "action=block",
            remote_ip_arg,
            NULL
        };

        // Add inbound rule
        wfd = wpopenv(netsh_path, exec_cmd_in, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to execute netsh add rule (inbound)");
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        int result_in = wpclose(wfd);
        if (result_in != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "netsh inbound rule failed with exit code %d", result_in);
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        // Add outbound rule (from PR #34675 fix for bidirectional blocking)
        char remote_ip_arg_out[OS_MAXSTR];
        memset(remote_ip_arg_out, '\0', OS_MAXSTR);
        snprintf(remote_ip_arg_out, OS_MAXSTR - 1, "remoteip=%s/32", srcip);

        char *exec_cmd_out[] = {
            netsh_path,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            (char *)rule_name,
            "interface=any",
            "dir=out",
            "action=block",
            remote_ip_arg_out,
            NULL
        };

        wfd = wpopenv(netsh_path, exec_cmd_out, W_BIND_STDERR);
        if (wfd) {
            int result_out = wpclose(wfd);
            if (result_out != 0) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "netsh outbound rule failed with exit code %d", result_out);
                write_debug_file(argv0, log_msg);
                // Don't fail - outbound rule is optional
            }
        }

    } else {
        // DELETE: netsh advfirewall firewall delete rule name="..." remoteip=<IP>/32
        char remote_ip_arg_del[OS_MAXSTR];
        memset(remote_ip_arg_del, '\0', OS_MAXSTR);
        snprintf(remote_ip_arg_del, OS_MAXSTR - 1, "remoteip=%s/32", srcip);

        char *exec_cmd[] = {
            netsh_path,
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            (char *)rule_name,
            remote_ip_arg_del,
            NULL
        };

        wfd = wpopenv(netsh_path, exec_cmd, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to execute netsh delete rule");
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        int result_del = wpclose(wfd);
        if (result_del != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "netsh delete rule failed with exit code %d", result_del);
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }
    }

    os_free(netsh_path);
    return FIREWALL_SUCCESS;
}

// ============================================================================
// WINDOWS: route implementation (fallback)
// ============================================================================

firewall_result_t try_route_windows(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // route works for both IPv4 and IPv6
    char log_msg[OS_MAXSTR];
    char *route_path = NULL;
    char *ipconfig_path = NULL;
    char gateway[OS_MAXSTR] = {0};

    // Check if route.exe is available
    if (check_binary_available("route.exe", &route_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    if (action == ADD_COMMAND) {
        // Need to find default gateway using ipconfig
        if (check_binary_available("ipconfig.exe", &ipconfig_path, argv0) != FIREWALL_SUCCESS) {
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "route", "check",
                              "ipconfig.exe not found - cannot determine gateway");
            os_free(route_path);
            return FIREWALL_NOT_AVAILABLE;
        }

        // Query default gateway
        char *ipconfig_cmd[] = {ipconfig_path, NULL};
        wfd_t *wfd = wpopenv(ipconfig_path, ipconfig_cmd, W_BIND_STDOUT);

        if (!wfd) {
            os_free(ipconfig_path);
            os_free(route_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        // Parse ipconfig output to find default gateway
        char output_buf[OS_MAXSTR];
        bool found_gateway = false;

        while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
            if (strstr(output_buf, "Default Gateway") != NULL ||
                strstr(output_buf, "Puerta de enlace predeterminada") != NULL) {
                // Extract IP address from line
                char *ip_start = strchr(output_buf, ':');
                if (ip_start) {
                    ip_start++;
                    // Skip whitespace
                    while (*ip_start == ' ' || *ip_start == '\t') ip_start++;

                    // Copy IP address
                    int i = 0;
                    while (ip_start[i] != '\0' && ip_start[i] != '\n' && ip_start[i] != '\r' && i < OS_MAXSTR - 1) {
                        gateway[i] = ip_start[i];
                        i++;
                    }
                    gateway[i] = '\0';

                    if (strlen(gateway) > 0) {
                        found_gateway = true;
                        break;
                    }
                }
            }
        }
        wpclose(wfd);
        os_free(ipconfig_path);

        if (!found_gateway) {
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "route", "gateway",
                              "Unable to determine default gateway");
            os_free(route_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Using gateway: %s", gateway);
        write_debug_file(argv0, log_msg);

        // Add persistent route: route -p ADD <IP> MASK 255.255.255.255 <gateway>
        char *exec_cmd[] = {
            route_path,
            "-p",
            "ADD",
            (char *)srcip,
            "MASK",
            "255.255.255.255",
            gateway,
            NULL
        };

        wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
        if (!wfd) {
            os_free(route_path);
            return FIREWALL_EXECUTION_FAILED;
        }
        wpclose(wfd);

    } else {
        // DELETE: route DELETE <IP>
        char *exec_cmd[] = {route_path, "DELETE", (char *)srcip, NULL};

        wfd_t *wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
        if (!wfd) {
            os_free(route_path);
            return FIREWALL_EXECUTION_FAILED;
        }
        wpclose(wfd);
    }

    os_free(route_path);
    return FIREWALL_SUCCESS;
}

#endif // WIN32
