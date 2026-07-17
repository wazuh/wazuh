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
 *
 * ENABLE: method chain (first success wins) netsh (Windows Firewall) -> route (null-route).
 * netsh provides true bidirectional (inbound + outbound) blocking, but its rules are only
 * enforced while a firewall profile is enabled. try_netsh checks the EFFECTIVE firewall
 * state; when the firewall is off it defers to the route fallback, which null-routes the
 * target to loopback (dropping the attacker's reverse path). netsh.exe being unavailable
 * also falls through to route.
 *
 * DISABLE: not a fallback chain - the netsh rule AND any null-route are removed
 * unconditionally (best-effort), since either may exist depending on how the block was
 * applied.
 */

firewall_result_t try_netsh(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route_windows(const char *srcip, int action, int ip_version, const char *argv0);
static bool firewall_is_effectively_on(const char *argv0);

int main(int argc, char **argv) {
    // This must always be the first instruction on Windows
    enable_dll_verification();

    (void)argc;
    int action = OS_INVALID;
    int action2 = OS_INVALID;
    cJSON *input_json = NULL;

    // Setup and parse JSON input
    action = setup_and_check_message(argv, &input_json);
    if ((action != ENABLE_COMMAND) && (action != DISABLE_COMMAND)) {
        return OS_INVALID;
    }

    // Extract source IP from WCS-compliant JSON
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'source.ip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Send keys and check for abort (ENABLE command only)
    if (action == ENABLE_COMMAND) {
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

    // Validate IP and get version (mirrors block-ip-unix.c / block-ip-macos.c)
    int ip_version = validate_srcip(srcip);
    if (ip_version == OS_INVALID) {
        char log_msg[OS_MAXSTR];
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Invalid IP address: '%s'", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    int result;
    if (action == DISABLE_COMMAND) {
        // Removal is NOT a fallback chain: the block may have been applied by netsh
        // (firewall enabled) OR by the null-route (firewall off) - or, across re-blocks with
        // a firewall state change, BOTH - so we unconditionally attempt to remove BOTH.
        // Each is best-effort: a missing rule/route is the expected case (not a failure), so
        // cleanup never depends on netsh's (undocumented) exit code for "no rule matched".
        // The unblock counts as successful if EITHER removal actually took effect.
        firewall_result_t netsh_res = try_netsh(srcip, DISABLE_COMMAND, ip_version, argv[0]);
        firewall_result_t route_res = try_route_windows(srcip, DISABLE_COMMAND, ip_version, argv[0]);
        if (netsh_res == FIREWALL_SUCCESS || route_res == FIREWALL_SUCCESS) {
            char unblock_msg[OS_MAXSTR];
            memset(unblock_msg, '\0', OS_MAXSTR);
            snprintf(unblock_msg, OS_MAXSTR - 1, "IP %s successfully unblocked", srcip);
            log_firewall_action(argv[0], LOG_LEVEL_INFO, "block-ip", "unblock", unblock_msg);
        } else {
            // Neither a rule nor a route was actually removed. Usually benign (the IP was
            // not blocked, or was blocked by the artifact that is now gone), but surface it
            // so a genuine removal failure is not silent.
            log_firewall_action(argv[0], LOG_LEVEL_WARNING, "block-ip", "unblock",
                              "Nothing was removed (no matching firewall rule or null-route) - "
                              "the IP may already be unblocked, or removal failed");
        }
        write_debug_file(argv[0], "Ended");
        result = OS_SUCCESS;
    } else {
        // ENABLE: netsh -> route fallback (first success wins).
        const firewall_method_t methods[] = {
            {"netsh", try_netsh, false},
            {"route", try_route_windows, false},
            {NULL, NULL, false}  // Sentinel
        };
        result = execute_firewall_chain(methods, srcip, action, ip_version, argv[0]);
    }

    cJSON_Delete(input_json);
    return result;
}

// ============================================================================
// WINDOWS: effective firewall-state detection
// ============================================================================

// Reads the EnableFirewall DWORD under HKLM\<subkey>. Returns 1 (enabled), 0 (disabled),
// or -1 (key/value absent). Forces the 64-bit view (KEY_WOW64_64KEY) because block-ip may
// run as a 32-bit process and these keys live in the native hive.
static int read_enable_firewall(const char *subkey) {
    HKEY hkey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS) {
        return -1;
    }

    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    LONG rc = RegQueryValueEx(hkey, "EnableFirewall", NULL, &type, (LPBYTE)&value, &size);
    RegCloseKey(hkey);

    if (rc != ERROR_SUCCESS || type != REG_DWORD) {
        return -1;
    }
    return value != 0 ? 1 : 0;
}

// Returns true if ANY firewall profile is effectively enabled (enforcing). Reads the
// EnableFirewall DWORD directly from the registry.
// Per profile: the GPO policy value wins if present, else the local SharedAccess value,
// else it defaults to ENABLED (the Windows default). Defaulting an ABSENT value to enabled
// is the fix for the #37388 misfire (the old check treated absent as "disabled").
static bool firewall_is_effectively_on(const char *argv0) {
    static const char *profiles[] = {"DomainProfile", "StandardProfile", "PublicProfile"};
    char gpo_key[OS_MAXSTR];
    char local_key[OS_MAXSTR];
    bool any_on = false;

    for (int i = 0; i < 3; i++) {
        snprintf(gpo_key, OS_MAXSTR - 1,
                 "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\%s", profiles[i]);
        snprintf(local_key, OS_MAXSTR - 1,
                 "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\%s",
                 profiles[i]);

        int gpo = read_enable_firewall(gpo_key);
        int state = (gpo != -1) ? gpo : read_enable_firewall(local_key);
        bool enabled = (state == -1) ? true : (state == 1);  // both absent -> Windows default ON
        if (enabled) {
            any_on = true;
            break;
        }
    }

    if (!any_on) {
        write_debug_file(argv0, "No firewall profile is effectively enabled (registry check)");
    }
    return any_on;
}

// ============================================================================
// WINDOWS: netsh (Windows Firewall) implementation
// ============================================================================

firewall_result_t try_netsh(const char *srcip, int action, int ip_version, const char *argv0) {
    static const char rule_name[] = "name=\"WAZUH ACTIVE RESPONSE BLOCKED IP\"";
    char log_msg[OS_MAXSTR];
    char *netsh_path = NULL;

    // Check if netsh.exe is available
    if (check_binary_available("netsh.exe", &netsh_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // A netsh block rule is only enforced while a firewall profile is enabled. On ENABLE,
    // if the firewall is effectively OFF, defer to the route fallback instead of adding a
    // dormant rule. The effective state is read from the registry (see
    // firewall_is_effectively_on), which is locale-independent. This is ENABLE-only: on
    // DISABLE we must always try to remove the rule, which may have been added while the
    // firewall was enabled.
    if (action == ENABLE_COMMAND && !firewall_is_effectively_on(argv0)) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "netsh", "check",
                          "Windows Firewall is effectively disabled - deferring to route fallback");
        os_free(netsh_path);
        return FIREWALL_INVALID_STATE;
    }

    // Single-host prefix for netsh remoteip: /32 for IPv4, /128 for IPv6.
    const char *host_prefix = (ip_version == 6) ? "128" : "32";

    // Build netsh command
    wfd_t *wfd = NULL;

    if (action == ENABLE_COMMAND) {
        // netsh advfirewall firewall add rule name="..." interface=any dir=in action=block remoteip=<IP>/<prefix>
        char remote_ip_arg[OS_MAXSTR];
        memset(remote_ip_arg, '\0', OS_MAXSTR);
        snprintf(remote_ip_arg, OS_MAXSTR - 1, "remoteip=%s/%s", srcip, host_prefix);

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
        snprintf(remote_ip_arg_out, OS_MAXSTR - 1, "remoteip=%s/%s", srcip, host_prefix);

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
        // DELETE (best-effort): the rule may not exist - e.g. the block was applied via the
        // route fallback while the firewall was off - so a non-zero "no rule matched" exit
        // is expected and is NOT treated as a failure. The caller removes the null-route
        // unconditionally, independently of this result.
        //
        // netsh matches the rule by its exact remoteip prefix. For IPv6 we also try the
        // legacy "/32" prefix: an agent upgraded from a version that wrote every rule as
        // remoteip=<ip>/32 may still carry such a rule, which a "/128" delete would not match.
        const char *del_prefixes[2];
        int del_prefix_count = 0;
        del_prefixes[del_prefix_count++] = host_prefix;
        if (ip_version == 6) {
            del_prefixes[del_prefix_count++] = "32";  // pre-upgrade IPv6 rules used /32
        }

        firewall_result_t del_res = FIREWALL_EXECUTION_FAILED;
        for (int p = 0; p < del_prefix_count; p++) {
            char remote_ip_arg_del[OS_MAXSTR];
            memset(remote_ip_arg_del, '\0', OS_MAXSTR);
            snprintf(remote_ip_arg_del, OS_MAXSTR - 1, "remoteip=%s/%s", srcip, del_prefixes[p]);

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
            if (wfd) {
                int result_del = wpclose(wfd);
                if (result_del == 0) {
                    del_res = FIREWALL_SUCCESS;  // a matching rule was actually removed
                } else {
                    memset(log_msg, '\0', OS_MAXSTR);
                    snprintf(log_msg, OS_MAXSTR - 1,
                             "netsh delete rule (remoteip=%s/%s) returned %d (no matching rule is expected if the block used the route fallback)",
                             srcip, del_prefixes[p], result_del);
                    write_debug_file(argv0, log_msg);
                }
            } else {
                write_debug_file(argv0, "Unable to execute netsh delete rule");
            }
        }
        os_free(netsh_path);
        return del_res;
    }

    os_free(netsh_path);
    return FIREWALL_SUCCESS;
}

// ============================================================================
// WINDOWS: route implementation (fallback)
// ============================================================================

firewall_result_t try_route_windows(const char *srcip, int action, int ip_version, const char *argv0) {
    char log_msg[OS_MAXSTR];
    char *route_path = NULL;

    // Reached when netsh is unavailable, or (via try_netsh) when the firewall is
    // effectively OFF. BEST-EFFORT: null-routes the target to loopback so the host drops
    // packets destined to it, which in principle also breaks the reverse path of inbound
    // TCP sessions to a routed/remote attacker.
    // LIMITATION: this does NOT block a target on a directly-connected
    // subnet - on-link hosts are reached via ARP and the /32-via-loopback route does not
    // redirect that egress. Effectiveness against routed/remote attackers was not verified.
    // netsh (Windows Firewall) remains the only comprehensive blocking mechanism.

    // The IPv4 mask below only applies to IPv4 targets; netsh already covers IPv6.
    if (ip_version == 6) {
        // On ENABLE this is a genuine limitation worth flagging. On DISABLE, skipping IPv6
        // here is the expected path (the route fallback never creates an IPv6 null-route, so
        // there is nothing to remove), so keep it at debug to avoid a warning on every
        // routine IPv6 unblock.
        if (action == ENABLE_COMMAND) {
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "route", "check",
                              "route fallback supports IPv4 only - skipping IPv6 target");
        } else {
            write_debug_file(argv0, "route fallback is IPv4-only - no null-route to remove for IPv6 target");
        }
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if route.exe is available
    if (check_binary_available("route.exe", &route_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    if (action == ENABLE_COMMAND) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "route", "best_effort",
                          "Applying best-effort null-route (firewall off or netsh unavailable): "
                          "blocks routed/remote attackers but NOT same-subnet hosts - enable "
                          "Windows Firewall for comprehensive blocking");

        // Null-route to the loopback so packets to the target are discarded.
        char *add_cmd[] = {route_path, "-p", "ADD", (char *)srcip,
                           "MASK", "255.255.255.255", "127.0.0.1", NULL};
        wfd_t *wfd = wpopenv(route_path, add_cmd, W_BIND_STDERR);
        if (!wfd) {
            os_free(route_path);
            return FIREWALL_EXECUTION_FAILED;
        }
        int rc = wpclose(wfd);
        if (rc != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "route add failed with exit code %d", rc);
            write_debug_file(argv0, log_msg);
            os_free(route_path);
            return FIREWALL_EXECUTION_FAILED;
        }
    } else {
        // DELETE (best-effort): a null-route may not exist - e.g. the block was applied via
        // netsh while the firewall was on - so a non-zero "element not found" is expected
        // and is NOT treated as a failure.
        char *del_cmd[] = {route_path, "DELETE", (char *)srcip, NULL};
        wfd_t *wfd = wpopenv(route_path, del_cmd, W_BIND_STDERR);
        firewall_result_t del_res = FIREWALL_EXECUTION_FAILED;
        if (wfd) {
            int rc = wpclose(wfd);
            if (rc == 0) {
                del_res = FIREWALL_SUCCESS;  // a route was actually removed
            } else {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1,
                         "route delete returned %d (no route is expected if the block used netsh)", rc);
                write_debug_file(argv0, log_msg);
            }
        }
        os_free(route_path);
        return del_res;
    }

    os_free(route_path);
    return FIREWALL_SUCCESS;
}

#endif // WIN32
