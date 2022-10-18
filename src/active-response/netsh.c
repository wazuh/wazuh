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
#include "utilities.h"

#define RULE_NAME "WAZUH ACTIVE RESPONSE BLOCKED IP"
#define NETSH     "C:\\Windows\\System32\\netsh.exe"
#define REG       "C:\\Windows\\System32\\reg.exe"

#define PATH_FIREWALL_PROFILES_REG_DEFAULT "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\"

typedef struct {
    char *log_msg;
    cJSON *input_json;
    char **argv;
} data_common_t;

static int getAllProfilesStatus(data_common_t *data_common);

int main (int argc, char **argv) {
    (void)argc;
    char log_msg[OS_MAXSTR];
    int action = OS_INVALID;
    cJSON *input_json = NULL;
    data_common_t data_common = { log_msg, input_json, argv };
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

    snprintf(name, OS_MAXSTR -1, "name=\"%s\"", RULE_NAME);
    snprintf(remoteip, OS_MAXSTR -1, "remoteip=%s/32", srcip);

    char *exec_args_add[11] = { NETSH, "advfirewall", "firewall", "add", "rule", name, "interface=any", "dir=in", "action=block", remoteip, NULL };
    char *exec_args_delete[8] = { NETSH, "advfirewall", "firewall", "delete", "rule", name, remoteip, NULL };
    
    wfd_t *wfd = NULL;
    if ((action == ADD_COMMAND)) {
        if(getAllProfilesStatus(&data_common) == OS_INVALID) {
            return OS_INVALID;
        }
    }

    if (1 == checkVista()) {
        wfd = wpopenv(NETSH, (action == ADD_COMMAND) ? exec_args_add : exec_args_delete, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: '%s', rule: '%s'", (action == ADD_COMMAND) ? "ADD" : "DELETE", RULE_NAME);
            write_debug_file(argv[0], log_msg);
        }
        else {
            wpclose(wfd);
        }
    } else {
        snprintf(description, OS_MAXSTR -1, "description=\"%s\"", RULE_NAME);
        snprintf(remoteip, OS_MAXSTR -1, "srcaddr=\"%s\"", srcip);

        char *exec_args_delete[12] = { NETSH, "ipsec", "static", "delete", "filter", "filterlist=\"wazuh_filter\"", "srcmask=\"255.255.255.255\"", remoteip, "dstaddr=Me", "protocol=\"any\"", "mirrored=yes", NULL };
        char *exec_args_filter[13] = { NETSH, "ipsec", "static", "add", "filter", "filterlist=\"wazuh_filter\"", "srcmask=\"255.255.255.255\"", remoteip, "dstaddr=Me", "protocol=\"any\"", "srcport=\"0\"", "dstport=\"0\"", NULL };
        char *exec_args_faction[8] = { NETSH, "ipsec", "static", "add", "filteraction", "name=\"wazuh_action\"", "action=block", NULL };
        char *exec_args_policy[9]  = { NETSH, "ipsec", "static", "add", "policy", "name=\"wazuh_policy\"", "assign=yes", description, NULL };
        char *exec_args_rule[10]   = { NETSH, "ipsec", "static", "add", "rule", "name=wazuh_rule", "policy=wazuh_policy", "filterlist=wazuh_filter", "filteraction=wazuh_action", NULL };

        if (action == ADD_COMMAND){
            wfd = wpopenv(NETSH, exec_args_filter , W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_filter'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }

            wfd = wpopenv(NETSH, exec_args_faction, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_action'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }

            wfd = wpopenv(NETSH, exec_args_policy, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_policy'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }

            wfd = wpopenv(NETSH, exec_args_rule, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: 'ADD', 'wazuh_rule'");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }
        } else {
            wfd = wpopenv(NETSH, exec_args_delete, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: '%s', rule: 'wazuh_rule'", (action == ADD_COMMAND) ? "ADD" : "DELETE");
                write_debug_file(argv[0], log_msg);
            } else {
                wpclose(wfd);
            }
        }
    }

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}


/**
 * @brief Get the all firewall profiles status
 * 
 * @param data_common 
 * @return int 
 */
static int getAllProfilesStatus(data_common_t *data_common){
    
    if (data_common == NULL)
        return OS_INVALID;
    
    char pathFirewallProfilesReg[256] = {0};
    char *exec_args_show_profile[6] = { REG, "query", pathFirewallProfilesReg, "/v", "EnableFirewall", NULL};
    char *firewallProfilesReg[FIREWALL_PROFILES_MAX] = {"DomainProfile", "StandardProfile", "PublicProfile"};
    bool globalfirewallStatus = true;
    char aux_buf[OS_MAXSTR] = {0};
    char output_buf[OS_MAXSTR];
    const char *firewallProfileStr[FIREWALL_PROFILES_MAX + 1] = {"FIREWALL_DOMAIN", "FIREWALL_PRIVATE", "FIREWALL_PUBLIC", "FIREWALL_DEFAULT" };
    firewallData_t firewallData = FIREWALL_DATA_INITIALIZE;
    wfd_t *wfd = NULL;

    memset(data_common->log_msg, '\0', OS_MAXSTR);
    strcpy(data_common->log_msg, "{\"message\":\"Active response may not have an effect\",\"firewall\":{");
    int retVal = OS_SUCCESS;
        
    for ( int i = 0; i < FIREWALL_PROFILES_MAX; i++) {
        memset(pathFirewallProfilesReg, 0, sizeof(pathFirewallProfilesReg));
        strcpy(pathFirewallProfilesReg, PATH_FIREWALL_PROFILES_REG_DEFAULT);
        strcat(pathFirewallProfilesReg, firewallProfilesReg[i]);
        if (exec_args_show_profile[2] != NULL) {
            wfd = wpopenv(REG, exec_args_show_profile, W_BIND_STDOUT);
        }
        if (!wfd) {
            memset(data_common->log_msg, '\0', OS_MAXSTR);
            snprintf(data_common->log_msg, OS_MAXSTR -1, "Error executing '%s' : %s", NETSH, strerror(errno));
            write_debug_file(data_common->argv[0], data_common->log_msg);
            cJSON_Delete(data_common->input_json);
            return OS_INVALID;
        }
        else {
            while (fgets(output_buf, OS_MAXSTR -1, wfd->file_out)) {
                memset(aux_buf, '\0', OS_MAXSTR);
                if (firewallData.isThereProfile == false){
                    getFirewallProfile(output_buf, &firewallData); 
                }else {
                    getStatusFirewallProfile(output_buf, &firewallData);
                    char msg_buf[OS_MAXSTR] = {0};
                    if (i == FIREWALL_PROFILES_MAX - 1){
                        strncpy(msg_buf, "\"profile%d\":\"%s\",\"status%d\":\"%s\"", OS_MAXSTR -1);
                    }
                    else {
                        strncpy(msg_buf, "\"profile%d\":\"%s\",\"status%d\":\"%s\",", OS_MAXSTR -1);
                    }
                    globalfirewallStatus &= firewallData.isEnabled;
                    snprintf(aux_buf, OS_MAXSTR -1, msg_buf, i + 1,
                        firewallProfileStr[firewallData.profile], i + 1,
                        firewallData.isEnabled == true ? "active" : "inactive"
                    );
                    strcat(data_common->log_msg, aux_buf);
                    firewallData.isThereProfile = false;
                }
            }
            wpclose(wfd);
        }
    }
    if (false == globalfirewallStatus){
        memset(aux_buf, '\0', OS_MAXSTR);
        snprintf(aux_buf, OS_MAXSTR -1, "},\"status\":\"%s\",\"script\":\"%s\"}", globalfirewallStatus == true ? "active":"inactive", "netsh");
        strcat(data_common->log_msg, aux_buf);
        write_debug_file(data_common->argv[0], data_common->log_msg);
    }
    return retVal;
}
#endif
