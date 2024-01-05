/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "active_responses.h"
#include "dll_load_notify.h"

#define RULE_NAME "WAZUH ACTIVE RESPONSE BLOCKED IP"

#define PATH_FIREWALL_PROFILES_REG_DEFAULT "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\"
#define FIREWALL_DATA_INITIALIZE { false, false, FIREWALL_DOMAIN }
#define FIREWALL_PROFILES_MAX (3)   /*!< Maximum number of profiles*/

/**
 * @brief enumeration of the available profiles
 */
typedef enum {
    FIREWALL_DOMAIN = 0,
    FIREWALL_PRIVATE,
    FIREWALL_PUBLIC,
    FIREWALL_DEFAULT
} firewallProfile_t;

/**
 * @brief firewall data struct
 */
typedef struct {
    bool isThereProfile;
    bool isEnabled;
    firewallProfile_t profile;
} firewallData_t;

/**
 * @brief Get all firewall profiles status
 * @param argv Name of logging file
 * @return int
 */
static int getAllProfilesStatus(const char *argv);

/**
 * @brief Get name of the profile if it exists
 * @param output_buf buffer output
 * @param firewallData pointer to firewall data
*/
static void getFirewallProfile(const char * output_buf, firewallData_t *firewallData);

/**
 * @brief Get status of the profile
 * @param output_buf buffer output
 * @param firewallData pointer to firewall data
*/
static void getStatusFirewallProfile(const char * output_buf, firewallData_t *firewallData);

int main (int argc, char **argv) {
    // This must be always the first instruction
    enable_dll_verification();

    (void)argc;
    char log_msg[OS_MAXSTR];
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

    char name[OS_MAXSTR -1];
    char description[OS_MAXSTR -1];
    char remoteip[OS_MAXSTR -1];
    wfd_t *wfd = NULL;
    char *netsh_path = NULL;

    snprintf(name, OS_MAXSTR -1, "name=\"%s\"", RULE_NAME);
    snprintf(remoteip, OS_MAXSTR -1, "remoteip=%s/32", srcip);

    // Checking if netsh.exe is present
    if (get_binary_path("netsh.exe", &netsh_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", netsh_path);
        write_debug_file(argv[0], log_msg);
    }

    char *exec_args_add[11] = { netsh_path, "advfirewall", "firewall", "add", "rule", name, "interface=any", "dir=in", "action=block", remoteip, NULL };
    char *exec_args_delete[8] = { netsh_path, "advfirewall", "firewall", "delete", "rule", name, remoteip, NULL };

    if ((action == ADD_COMMAND)) {
        if (getAllProfilesStatus(argv[0]) == OS_INVALID) {
            cJSON_Delete(input_json);
            os_free(netsh_path);
            return OS_INVALID;
        }
    }

    if (1 == checkVista()) {
        wfd = wpopenv(netsh_path, (action == ADD_COMMAND) ? exec_args_add : exec_args_delete, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: '%s', rule: '%s'", (action == ADD_COMMAND) ? "ADD" : "DELETE", RULE_NAME);
            write_debug_file(argv[0], log_msg);
        } else {
            wpclose(wfd);
        }
    } else {
        snprintf(description, OS_MAXSTR -1, "description=\"%s\"", RULE_NAME);
        snprintf(remoteip, OS_MAXSTR -1, "srcaddr=\"%s\"", srcip);

        char *exec_args_delete[12] = { netsh_path, "ipsec", "static", "delete", "filter", "filterlist=\"wazuh_filter\"", "srcmask=\"255.255.255.255\"", remoteip, "dstaddr=Me", "protocol=\"any\"", "mirrored=yes", NULL };
        char *exec_args_filter[12] = { netsh_path, "ipsec", "static", "add", "filter", "filterlist=\"wazuh_filter\"", "srcmask=\"255.255.255.255\"", remoteip, "dstaddr=Me", "protocol=\"any\"", "mirrored=yes", NULL };
        char *exec_args_faction[8] = { netsh_path, "ipsec", "static", "add", "filteraction", "name=\"wazuh_action\"", "action=block", NULL };
        char *exec_args_policy[9]  = { netsh_path, "ipsec", "static", "add", "policy", "name=\"wazuh_policy\"", "assign=yes", description, NULL };
        char *exec_args_rule[10]   = { netsh_path, "ipsec", "static", "add", "rule", "name=wazuh_rule", "policy=wazuh_policy", "filterlist=wazuh_filter", "filteraction=wazuh_action", NULL };

        if (action == ADD_COMMAND) {
            wfd = wpopenv(netsh_path, exec_args_filter, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_filter'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }

            wfd = wpopenv(netsh_path, exec_args_faction, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_action'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }

            wfd = wpopenv(netsh_path, exec_args_policy, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_policy'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }

            wfd = wpopenv(netsh_path, exec_args_rule, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_rule'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }
        } else {
            wfd = wpopenv(netsh_path, exec_args_delete, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'DELETE', rule: 'wazuh_rule'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }
        }
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);
    os_free(netsh_path);

    return OS_SUCCESS;
}

static int getAllProfilesStatus(const char *argv) {
    char pathFirewallProfilesReg[256] = {0};
    char *firewallProfilesReg[FIREWALL_PROFILES_MAX] = { "DomainProfile", "StandardProfile", "PublicProfile" };
    bool globalfirewallStatus = true;
    char aux_buf[OS_MAXSTR] = {0}, aux_buf2[OS_MAXSTR] = {0}, msgLengths[FIREWALL_PROFILES_MAX] = {0,0,0};
    int countActiveProfile = 0, nextPositionComma = 0, numCommas = 0;
    char output_buf[OS_MAXSTR];
    char log_msg[OS_MAXSTR];
    const char *firewallProfileStr[FIREWALL_PROFILES_MAX + 1] = { "FIREWALL_DOMAIN", "FIREWALL_PRIVATE", "FIREWALL_PUBLIC", "FIREWALL_DEFAULT" };
    firewallData_t firewallData = FIREWALL_DATA_INITIALIZE;
    wfd_t *wfd = NULL;
    char *reg_path = NULL;


    // Checking if reg.exe is present
    if (get_binary_path("reg.exe", &reg_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", reg_path);
        write_debug_file(argv, log_msg);
    }

    char *exec_args_show_profile[6] = { reg_path, "query", pathFirewallProfilesReg, "/v", "EnableFirewall", NULL };
    memset(aux_buf2, '\0', OS_MAXSTR);
    memset(log_msg, '\0', OS_MAXSTR);
    strcpy(log_msg, "{\"message\":\"Active response may not have an effect\",\"firewall\":{");

    for (int i = 0; i < FIREWALL_PROFILES_MAX; i++) {
        memset(pathFirewallProfilesReg, 0, sizeof(pathFirewallProfilesReg));
        strcpy(pathFirewallProfilesReg, PATH_FIREWALL_PROFILES_REG_DEFAULT);
        strcat(pathFirewallProfilesReg, firewallProfilesReg[i]);

        wfd = wpopenv(reg_path, exec_args_show_profile, W_BIND_STDOUT);

        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s' : %s", reg_path, strerror(errno));
            write_debug_file(argv, log_msg);
            os_free(reg_path);
            return OS_INVALID;
        } else {
            while (fgets(output_buf, OS_MAXSTR -1, wfd->file_out)) {
                if (firewallData.isThereProfile == false) {
                    getFirewallProfile(output_buf, &firewallData);
                } else {
                    countActiveProfile++;
                    getStatusFirewallProfile(output_buf, &firewallData);
                    char msg_buf[OS_MAXSTR] = {0};
                    strncpy(msg_buf, "\"profile%d\":\"%s\",\"status%d\":\"%s\" ", OS_MAXSTR -1);
                    globalfirewallStatus &= firewallData.isEnabled;
                    memset(aux_buf, '\0', OS_MAXSTR);
                    snprintf(aux_buf, OS_MAXSTR -1, msg_buf, i + 1,
                        firewallProfileStr[firewallData.profile], i + 1,
                        firewallData.isEnabled == true ? "active" : "inactive"
                    );
                    msgLengths[i] = strlen(aux_buf);
                    strcat(aux_buf2, aux_buf);
                    firewallData.isThereProfile = false;
                }
            }
            wpclose(wfd);
        }
    }

    for (int i = 0; i < FIREWALL_PROFILES_MAX - 1; i++) {
        nextPositionComma += msgLengths[i];
        if(nextPositionComma > 0 && (numCommas < countActiveProfile - 1)){
            aux_buf2[nextPositionComma -1] = ',';
            numCommas++;
        }
    }

    if (false == globalfirewallStatus) {
        strcat(log_msg, aux_buf2);
        memset(aux_buf, '\0', OS_MAXSTR);
        snprintf(aux_buf, OS_MAXSTR -1, "},\"status\":\"inactive\",\"script\":\"netsh\"}");
        strcat(log_msg, aux_buf);
        write_debug_file(argv, log_msg);
    }
    os_free(reg_path);
    return OS_SUCCESS;
}

static void getFirewallProfile(const char * output_buf, firewallData_t *firewallData) {
    if (output_buf != NULL) {
        const char* ptr = NULL;

        if ((ptr = strstr(output_buf, "FirewallPolicy")) != NULL) {
           char after[OS_MAXSTR];
           splitStrFromCharDelimiter(ptr, '\\', NULL, after);

            if (after != NULL) {
                if (strstr(after, "DomainProfile") != NULL) {
                    firewallData->profile = FIREWALL_DOMAIN;
                    firewallData->isThereProfile = true;
                } else if (strstr(after, "PublicProfile") != NULL) {
                    firewallData->profile = FIREWALL_PUBLIC;
                    firewallData->isThereProfile = true;
                } else if (strstr(after, "StandardProfile") != NULL) {
                    firewallData->profile = FIREWALL_PRIVATE;
                    firewallData->isThereProfile = true;
                } else {
                    firewallData->isThereProfile = false;
                }
            }
        }
    }
}

static void getStatusFirewallProfile(const char * output_buf, firewallData_t *firewallData) {
    if (firewallData->isThereProfile == true && isEnabledFromPattern(output_buf, "REG_DWORD", "0x1")) {
        firewallData->isEnabled = true;
    } else {
        firewallData->isEnabled = false;
    }
}

#endif
