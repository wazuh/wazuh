/* Copyright (C) Wazuh Inc.
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
#include <iphlpapi.h>
#define COBJMACROS
#include <netfw.h>

/**
 * Windows-specific block-ip implementation
 *
 * ENABLE: netsh (Windows Firewall) adds an inbound and an outbound block rule. A rule is only
 * enforced on networks whose firewall profile is on and where Group Policy applies local rules,
 * so after adding it the profiles of the networks in use are checked: the block is reported as
 * done only when that holds for every one of them. Otherwise the rules stay in place (they take
 * effect if that changes before the unblock) and the block is reported as not done.
 *
 * There is no fallback: a route can't filter inbound connections, so it can't block an
 * address either.
 *
 * DISABLE: the netsh rules are removed whether or not the firewall is on, since they may have
 * been added while it was on. A loopback route added by an earlier version's route fallback
 * is removed too (see remove_legacy_route).
 */

firewall_result_t try_netsh(const char *srcip, int action, int ip_version, const char *argv0);
static bool remove_legacy_route(const char *srcip, int ip_version, const char *argv0);

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
        // Removal is best-effort: a missing rule is not a failure, so cleanup never depends on
        // netsh's (undocumented) exit code for "no rule matched".
        firewall_result_t netsh_res = try_netsh(srcip, DISABLE_COMMAND, ip_version, argv[0]);
        bool route_removed = remove_legacy_route(srcip, ip_version, argv[0]);
        if (netsh_res == FIREWALL_SUCCESS || route_removed) {
            char unblock_msg[OS_MAXSTR];
            memset(unblock_msg, '\0', OS_MAXSTR);
            snprintf(unblock_msg, OS_MAXSTR - 1, "IP %s successfully unblocked", srcip);
            log_firewall_action(argv[0], LOG_LEVEL_INFO, "block-ip", "unblock", unblock_msg);
        } else {
            // Usually benign (the IP was not blocked), but surface it so a genuine removal
            // failure is not silent.
            log_firewall_action(argv[0], LOG_LEVEL_WARNING, "block-ip", "unblock",
                              "Nothing was removed (no matching firewall rule) - "
                              "the IP may already be unblocked, or removal failed");
        }
        write_debug_file(argv[0], "Ended");
        result = OS_SUCCESS;
    } else {
        const firewall_method_t methods[] = {
            {"netsh", try_netsh, false},
            {NULL, NULL, false}  // Sentinel
        };
        result = execute_firewall_chain(methods, srcip, action, ip_version, argv[0]);
    }

    cJSON_Delete(input_json);
    return result;
}

// ============================================================================
// WINDOWS: firewall state of the networks in use
// ============================================================================

typedef enum {
    FW_IN_USE_ALL_ON,   // the firewall is on for every profile in use
    FW_IN_USE_SOME_OFF, // on for some profiles in use, off for others
    FW_IN_USE_ALL_OFF,  // off for every profile in use
    FW_IN_USE_GP_OVERRIDE, // Group Policy doesn't apply local rules to the profiles in use
    FW_IN_USE_GP_OVERRIDE_SOME, // ...to some of the profiles in use
    FW_IN_USE_UNKNOWN   // the state could not be read
} fw_in_use_state_t;

// Defined here because the import library doesn't export them.
static const CLSID wazuh_CLSID_NetFwPolicy2 =
    {0xe2b3c97f, 0x6ae1, 0x41ac, {0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd}};
static const IID wazuh_IID_INetFwPolicy2 =
    {0x98325047, 0xc671, 0x4174, {0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86}};

// Opens HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<subkey>, where Group Policy writes the
// firewall settings. Forces the 64-bit view because block-ip may run as a 32-bit process.
static LONG open_policy_key(const char *subkey, HKEY *hkey) {
    char key[OS_MAXSTR];
    snprintf(key, sizeof(key), "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\%s", subkey);
    return RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ | KEY_WOW64_64KEY, hkey);
}

// Only a key that is known to be missing counts as absent: a key that can't be opened for another
// reason is taken as present.
static bool policy_key_exists(const char *subkey) {
    HKEY hkey;
    LONG rc = open_policy_key(subkey, &hkey);
    if (rc == ERROR_SUCCESS) {
        RegCloseKey(hkey);
    }
    return rc != ERROR_FILE_NOT_FOUND;
}

// Reads a DWORD set by Group Policy under the policy key <subkey>. Returns 1 (non-zero), 0 or
// -1 (not set by policy).
static int read_policy_dword(const char *subkey, const char *value_name) {
    HKEY hkey;
    if (open_policy_key(subkey, &hkey) != ERROR_SUCCESS) {
        return -1;
    }

    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    LONG rc = RegQueryValueEx(hkey, value_name, NULL, &type, (LPBYTE)&value, &size);
    RegCloseKey(hkey);

    if (rc != ERROR_SUCCESS || type != REG_DWORD) {
        return -1;
    }
    return value != 0 ? 1 : 0;
}

static void append_profile_name(char *buf, size_t size, const char *name) {
    size_t len = strlen(buf);
    snprintf(buf + len, size - len, "%s%s", len ? ", " : "", name);
}

// Reads which firewall profiles the active networks use (INetFwPolicy2::CurrentProfileTypes),
// whether the firewall is on for each one, and whether Group Policy lets local rules (the ones
// netsh adds) take effect on them (LocalPolicyModifyState). INetFwPolicy2::FirewallEnabled is
// the local setting, so a value set by Group Policy takes precedence over it. The names of the
// profiles in use with the firewall off are written to off_profiles, and the ones where Group
// Policy doesn't apply local rules (AllowLocalPolicyMerge = 0) to merge_off_profiles.
static fw_in_use_state_t firewall_state_for_networks_in_use(char *off_profiles,
                                                            size_t off_size,
                                                            char *merge_off_profiles,
                                                            size_t merge_off_size,
                                                            const char *argv0) {
    // policy_key: Windows Firewall with Advanced Security policy. legacy_key: the older
    // "Windows Firewall" policy, whose Standard profile covers Private and Public. Windows applies
    // StandardProfile only when neither the PrivateProfile nor the PublicProfile key exists, and
    // ignores it otherwise, whatever values those keys hold ([MS-GPFAS] Per-Profile Policy
    // Configuration Options).
    static const struct {
        NET_FW_PROFILE_TYPE2 type;
        const char *name;
        const char *policy_key;
        const char *legacy_key;
    } profiles[] = {
        {NET_FW_PROFILE2_DOMAIN, "Domain", "DomainProfile", NULL},
        {NET_FW_PROFILE2_PRIVATE, "Private", "PrivateProfile", "StandardProfile"},
        {NET_FW_PROFILE2_PUBLIC, "Public", "PublicProfile", "StandardProfile"},
    };
    char log_msg[OS_MAXSTR];
    fw_in_use_state_t state = FW_IN_USE_UNKNOWN;
    INetFwPolicy2 *policy = NULL;
    long current = 0;
    NET_FW_MODIFY_STATE modify_state = NET_FW_MODIFY_STATE_OK;
    int in_use = 0;
    int off = 0;

    off_profiles[0] = '\0';
    merge_off_profiles[0] = '\0';

    const bool use_legacy = !policy_key_exists("PrivateProfile") && !policy_key_exists("PublicProfile");

    HRESULT hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    HRESULT hr = hr_init;
    if (FAILED(hr_init) && hr_init != RPC_E_CHANGED_MODE) {
        goto end;
    }

    hr = CoCreateInstance(&wazuh_CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &wazuh_IID_INetFwPolicy2, (void **)&policy);
    if (FAILED(hr)) {
        goto end;
    }

    hr = INetFwPolicy2_get_CurrentProfileTypes(policy, &current);
    if (FAILED(hr)) {
        goto end;
    }

    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
        if (!(current & profiles[i].type)) {
            continue;
        }

        const char *gpo_key = (use_legacy && profiles[i].legacy_key) ? profiles[i].legacy_key
                                                                     : profiles[i].policy_key;
        VARIANT_BOOL enabled = VARIANT_FALSE;
        int gpo_state = read_policy_dword(gpo_key, "EnableFirewall");
        if (gpo_state != -1) {
            enabled = gpo_state ? VARIANT_TRUE : VARIANT_FALSE;
        } else {
            hr = INetFwPolicy2_get_FirewallEnabled(policy, profiles[i].type, &enabled);
            if (FAILED(hr)) {
                goto end;
            }
        }

        in_use++;
        if (enabled == VARIANT_FALSE) {
            off++;
            append_profile_name(off_profiles, off_size, profiles[i].name);
        } else if (read_policy_dword(gpo_key, "AllowLocalPolicyMerge") == 0) {
            append_profile_name(merge_off_profiles, merge_off_size, profiles[i].name);
        }
    }

    if (in_use == 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1,
                 "No known firewall profile is in use (CurrentProfileTypes 0x%lx)", (unsigned long)current);
        write_debug_file(argv0, log_msg);
        goto end;
    }

    // S_FALSE means the returned state holds for only some of the profiles in use: local rules
    // may not take effect on all of them.
    hr = INetFwPolicy2_get_LocalPolicyModifyState(policy, &modify_state);
    if (FAILED(hr)) {
        goto end;
    }

    if (off == in_use) {
        state = FW_IN_USE_ALL_OFF;
    } else if (hr == S_OK && modify_state == NET_FW_MODIFY_STATE_GP_OVERRIDE) {
        state = FW_IN_USE_GP_OVERRIDE;
    } else if (off > 0) {
        state = FW_IN_USE_SOME_OFF;
    } else if (hr == S_FALSE || merge_off_profiles[0] != '\0') {
        state = FW_IN_USE_GP_OVERRIDE_SOME;
    } else {
        state = FW_IN_USE_ALL_ON;
    }

end:
    if (FAILED(hr)) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1,
                 "Cannot read the firewall state of the networks in use (HRESULT 0x%08lx)",
                 (unsigned long)hr);
        write_debug_file(argv0, log_msg);
    }
    if (policy) {
        INetFwPolicy2_Release(policy);
    }
    if (SUCCEEDED(hr_init)) {
        CoUninitialize();
    }
    return state;
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
        // DELETE (best-effort): the rule may not exist, so a non-zero "no rule matched" exit
        // is expected and is NOT treated as a failure.
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
                             "netsh delete rule (remoteip=%s/%s) returned %d (no matching rule)",
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

    // The rules are only enforced on networks whose firewall profile is on and where Group Policy
    // applies local rules. Report the block as done only when that holds for every network in
    // use; otherwise the rules are kept, so they take effect if that changes before the unblock.
    char off_profiles[64];
    char merge_off_profiles[64];
    const char *reason = NULL;
    switch (firewall_state_for_networks_in_use(off_profiles, sizeof(off_profiles), merge_off_profiles,
                                               sizeof(merge_off_profiles), argv0)) {
        case FW_IN_USE_ALL_ON:
            return FIREWALL_SUCCESS;

        case FW_IN_USE_ALL_OFF:
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1,
                     "IP %s is not blocked: Windows Firewall is off for the networks in use "
                     "(profiles: %s). Turn it on for those profiles to block the IP",
                     srcip, off_profiles);
            reason = log_msg;
            break;

        case FW_IN_USE_SOME_OFF:
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1,
                     "IP %s is not blocked on every network in use: Windows Firewall is off for "
                     "some of them (profiles: %s), so the rules don't apply there. Turn it on for "
                     "those profiles to block the IP",
                     srcip, off_profiles);
            reason = log_msg;
            break;

        case FW_IN_USE_GP_OVERRIDE:
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1,
                     "IP %s is not blocked: Group Policy doesn't apply local firewall rules to the "
                     "networks in use, so the rules added by block-ip are ignored",
                     srcip);
            reason = log_msg;
            break;

        case FW_IN_USE_GP_OVERRIDE_SOME:
            memset(log_msg, '\0', OS_MAXSTR);
            if (merge_off_profiles[0] != '\0') {
                snprintf(log_msg, OS_MAXSTR - 1,
                         "IP %s is not blocked on every network in use: Group Policy doesn't apply "
                         "local firewall rules to some of them (profiles: %s), so the rules added "
                         "by block-ip only apply to the others",
                         srcip, merge_off_profiles);
            } else {
                snprintf(log_msg, OS_MAXSTR - 1,
                         "IP %s may not be blocked on every network in use: the firewall policy "
                         "differs between them, so it can't be confirmed that the rules added by "
                         "block-ip apply to all of them",
                         srcip);
            }
            reason = log_msg;
            break;

        case FW_IN_USE_UNKNOWN:
        default:
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1,
                     "IP %s may not be blocked: the firewall rules were added, but the firewall "
                     "state of the networks in use can't be read to confirm they apply",
                     srcip);
            reason = log_msg;
            break;
    }

    log_firewall_action(argv0, LOG_LEVEL_ERROR, "netsh", "not_enforced", reason);
    return FIREWALL_INVALID_STATE;
}

// ============================================================================
// WINDOWS: cleanup of the route fallback of earlier versions
// ============================================================================

// Parse a validated dotted-quad IPv4 string into a network-byte-order address
// (as GetBestRoute expects), without pulling in a winsock link dependency.
static DWORD ipv4_to_network(const char *ip) {
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
        a > 255 || b > 255 || c > 255 || d > 255) {
        return INADDR_NONE;
    }
    return (DWORD)(a | (b << 8) | (c << 16) | (d << 24));
}

// Earlier 5.0.0 pre-releases fell back to a persistent route
// (route -p ADD <ip> MASK 255.255.255.255 0.0.0.0 IF 1) when the firewall was off. If the agent
// restarted before the unblock, that route stayed. It is removed here, only when the best
// route to the IP is exactly that /32 host route through the loopback interface (IF 1), and only
// that route is deleted, so a route to the IP through another gateway or interface is never
// touched. Returns true if a route was removed.
static bool remove_legacy_route(const char *srcip, int ip_version, const char *argv0) {
    if (ip_version != 4) {
        return false;  // the route fallback was IPv4-only
    }

    DWORD dest = ipv4_to_network(srcip);
    MIB_IPFORWARDROW row;
    memset(&row, 0, sizeof(row));
    if (dest == INADDR_NONE || GetBestRoute(dest, 0, &row) != NO_ERROR ||
        row.dwForwardDest != dest || row.dwForwardMask != 0xFFFFFFFF || row.dwForwardIfIndex != 1) {
        return false;
    }

    char *route_path = NULL;
    if (check_binary_available("route.exe", &route_path, argv0) != FIREWALL_SUCCESS) {
        return false;
    }

    bool removed = false;
    char *del_cmd[] = {route_path, "DELETE", (char *)srcip, "MASK", "255.255.255.255", "0.0.0.0",
                       "IF", "1", NULL};
    wfd_t *wfd = wpopenv(route_path, del_cmd, W_BIND_STDERR);
    if (wfd) {
        int rc = wpclose(wfd);
        removed = (rc == 0);
        if (!removed) {
            char log_msg[OS_MAXSTR];
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "route delete of the legacy loopback route returned %d", rc);
            write_debug_file(argv0, log_msg);
        }
    }
    os_free(route_path);

    if (removed) {
        log_firewall_action(argv0, LOG_LEVEL_INFO, "route", "unblock",
                          "Removed the loopback route added by an earlier version's route fallback");
    }
    return removed;
}

#endif // WIN32
