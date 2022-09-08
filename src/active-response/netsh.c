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

#define RULE_NAME "WAZUH ACTIVE RESPONSE BLOCKED IP"
#define NETSH "C:\\Windows\\System32\\netsh.exe"
#define FIREWALL_DATA_INITIALIZE {{false, FIREWALL_DOMAIN}, {false, FIREWALL_PRIVATE}, {false, FIREWALL_PUBLIC}};

typedef enum {
    FIREWALL_DOMAIN = 0,
    FIREWALL_PRIVATE,
    FIREWALL_PUBLIC
} firewallProfile_t;

typedef struct{
    bool isEnabled;
    firewallProfile_t profile;
} firewallData_t;

const char *firewallProfileStr[3] = {"FIREWALL_DOMAIN", "FIREWALL_PRIVATE", "FIREWALL_PUBLIC"};

int getFirewallStateAllProfiles(const char * output_buf, firewallData_t *firewallData);

int main (int argc, char **argv) {
    (void)argc;
    char log_msg[OS_MAXSTR];
    char output_buf[OS_MAXSTR];
    const char *firewallProfileStr[3] = {"FIREWALL_DOMAIN", "FIREWALL_PRIVATE", "FIREWALL_PUBLIC"};
    firewallData_t firewallData[3] = FIREWALL_DATA_INITIALIZE;
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
    char remoteip[OS_MAXSTR -1];

    snprintf(name, OS_MAXSTR -1, "name=\"%s\"", RULE_NAME);
    snprintf(remoteip, OS_MAXSTR -1, "remoteip=%s/32", srcip);

    char *exec_args_add[11] = { NETSH, "advfirewall", "firewall", "add", "rule", name, "interface=any", "dir=in", "action=block", remoteip, NULL };
    char *exec_args_delete[8] = { NETSH, "advfirewall", "firewall", "delete", "rule", name, remoteip, NULL };
    char *exec_args_show[6] = { NETSH, "advfirewall", "show", "allprofiles", NULL };

    wfd_t *wfd = NULL;
    if ((action == ADD_COMMAND)) {
        wfd = wpopenv(NETSH, exec_args_show, W_BIND_STDOUT);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s' : %s", NETSH, strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }
        else {
            int index = 0;
            while (fgets(output_buf, OS_MAXSTR -1, wfd->file_out)) {   
                if ((index = getFirewallStateAllProfiles(output_buf, firewallData)) != -1) {
                    if (false == firewallData[index].isEnabled) {
                        memset(log_msg, '\0', OS_MAXSTR);
                        snprintf(
                            log_msg, OS_MAXSTR -1, "{\"message\":\"Firewall is disabled\",\"profile\":\"%s\",\"status\":\"%s\"}",
                            firewallProfileStr[firewallData[index].profile],
                            firewallData[index].isEnabled == true ? "active" : "inactive"
                        );
                        write_debug_file(argv[0], log_msg);
                    }
                }
            }
            wpclose(wfd);
        }
    }

    wfd = wpopenv(NETSH, (action == ADD_COMMAND) ? exec_args_add : exec_args_delete, W_BIND_STDERR);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to run netsh, action: '%s', rule: '%s'", (action == ADD_COMMAND) ? "ADD" : "DELETE", RULE_NAME);
        write_debug_file(argv[0], log_msg);
    }
    else {
        wpclose(wfd);
    }

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}


/** 
 * @brief get firewall state of all profiles
 * @param output_buf: buffer output
 * @param firewallData: pointer to firewall data
 * @return index firewall profile firewallProfile_t
*/
int getFirewallStateAllProfiles(const char * output_buf, firewallData_t *firewallData) {
    const char *pos = strstr(output_buf, "State");
    static int countNumProf = 0;
    int retVal = -1;
    if (pos != NULL) {
        char state[15];
        if (pos && sscanf(pos, "%*s %2s", state) == 1) {
            if (strcmp(state, "ON") == 0) {
                firewallData[countNumProf].isEnabled = true;             
            } else {
                firewallData[countNumProf].isEnabled = false;
            }
            switch (countNumProf) {
                case 0:
                    firewallData[countNumProf].profile = FIREWALL_DOMAIN;
                    break;
                case 1:
                    firewallData[countNumProf].profile = FIREWALL_PRIVATE;
                    break;
                case 2:
                    firewallData[countNumProf].profile = FIREWALL_PUBLIC;
                    break;
                default:
                    break;
            }
            retVal = countNumProf;
            if (countNumProf++ > 2) {
                countNumProf = 0;
            }
        }
    }
    return retVal;
}

#endif
