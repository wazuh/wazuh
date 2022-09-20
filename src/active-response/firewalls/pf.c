/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../active_responses.h"

#define GREP        ("/usr/bin/grep")
#define PFCTL       ("/sbin/pfctl")
#define PFCTL_RULES ("/etc/pf.conf")
#define PFCTL_TABLE ("wazuh_fwtable")
#define RCCONF      ("/etc/rc.conf")
#define LAUNCHCTL   ("/bin/launchctl")

static int checking_if_its_configured(const char *path, const char *table);
static int isEnabledFromPattern(const char * output_buf, const char * str_pattern_1, const char * str_pattern_2);
static int write_cmd_to_file(const char *path, const char *cmd);

int main (int argc, char **argv) {
    (void)argc;
    char log_msg[OS_MAXSTR];
    char output_buf[OS_MAXSTR];
    int isEnabledFirewall = 0;
    int action = OS_INVALID;
    cJSON *input_json = NULL;
    struct utsname uname_buffer;

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

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("OpenBSD", uname_buffer.sysname) || !strcmp("FreeBSD", uname_buffer.sysname) || !strcmp("Darwin", uname_buffer.sysname)) {
        wfd_t *wfd = NULL;

        // Checking if pfctl is present
        if (access(PFCTL, F_OK) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The pfctl file '%s' is not accessible", PFCTL);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        char *exec_cmd1[7] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
        char *exec_cmd2[4] = { NULL, NULL, NULL, NULL };
        char *exec_cmd3[4] = { PFCTL, "-s", "info", NULL };
        char *exec_cmd4[4] = { LAUNCHCTL, "start", "/Library/LaunchDaemons/pf.plist", NULL };
        char *exec_cmd5[4] = { PFCTL, "-f", PFCTL_RULES, NULL };

        // Checking if we have pf config file
        if (access(PFCTL_RULES, F_OK) == 0) {
            // Checking if wazuh table is configured in pf.conf
            if (checking_if_its_configured(PFCTL_RULES, PFCTL_TABLE) == 0) {
                if (action == ADD_COMMAND) {
                    const char *arg1[7] = { PFCTL, "-t", PFCTL_TABLE, "-T", "add", srcip, NULL };
                    memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

                    const char *arg2[4] = { PFCTL, "-k", srcip, NULL };
                    memcpy(exec_cmd2, arg2, sizeof(exec_cmd2));
                } else {
                    const char *arg1[7] = { PFCTL, "-t", PFCTL_TABLE, "-T", "delete", srcip, NULL };
                    memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));
                }
            } else {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Table '%s' does not exist", PFCTL_TABLE);
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);

                (void)write_cmd_to_file(RCCONF, "pf_enable=\"YES\"" "\n" "pf_rules=\"/etc/pf.conf\"" "\n" "pflog_enable=\"YES\"" "\n" "pflog_logfile=\"/var/log/pflog\"");
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "table <%s> persist #%s\nblock in quick from <%s> to any\nblock out quick from any to <%s>", PFCTL_TABLE, PFCTL_TABLE, PFCTL_TABLE, PFCTL_TABLE);
                (void)write_cmd_to_file(PFCTL_RULES, log_msg);

                if (exec_cmd4[0] != NULL ) {
                    wfd = wpopenv(PFCTL, exec_cmd4, W_BIND_STDOUT);
                    if (!wfd) {
                        memset(log_msg, '\0', OS_MAXSTR);
                        snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", PFCTL, strerror(errno));
                        write_debug_file(argv[0], log_msg);
                        cJSON_Delete(input_json);
                        return OS_INVALID;
                    }
                    wpclose(wfd);
                }

                if (exec_cmd5[0] != NULL) {
                    wfd = wpopenv(PFCTL, exec_cmd5, W_BIND_STDOUT);
                    if (!wfd) {
                        memset(log_msg, '\0', OS_MAXSTR);
                        snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", PFCTL, strerror(errno));
                        write_debug_file(argv[0], log_msg);
                        cJSON_Delete(input_json);
                        return OS_INVALID;
                    }
                    wpclose(wfd);
                }
                return OS_SUCCESS;
            }
        } else {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The pf rules file '%s' does not exist", PFCTL_RULES);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        // Executing it

        if (exec_cmd3[0] != NULL) {
            wfd = wpopenv(PFCTL, exec_cmd3, W_BIND_STDOUT);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", PFCTL, strerror(errno));
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                return OS_INVALID;
            }
            else {
                while (fgets(output_buf, OS_MAXSTR -1, wfd->file_out) && 0  == isEnabledFirewall) {
                    isEnabledFirewall = isEnabledFromPattern(output_buf, "Status: ", "Enabled");
                }

                if (( 0 == isEnabledFirewall )) {
                    memset(log_msg, '\0', OS_MAXSTR);
                    snprintf(log_msg, OS_MAXSTR -1, "{\"message\":\"Firewall is disabled\",\"profile\":\"%s\",\"status\":\"%s\"}",
                            "undefined", 1 == isEnabledFirewall ? "active" : "inactive"
                    );
                    write_debug_file(argv[0], log_msg);
                }
            }
            wpclose(wfd);
        }

        if (exec_cmd1[0] != NULL) {
            wfd = wpopenv(PFCTL, exec_cmd1, W_BIND_STDOUT);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", PFCTL, strerror(errno));
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                return OS_INVALID;
            }
            wpclose(wfd);
        }

        if (exec_cmd2[0] != NULL) {
            wfd = wpopenv(PFCTL, exec_cmd2, W_BIND_STDOUT);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", PFCTL, strerror(errno));
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                return OS_INVALID;
            }
            wpclose(wfd);
        }

    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}

static int checking_if_its_configured(const char *path, const char *table) {
    char command[COMMANDSIZE_4096];
    char output_buf[OS_MAXSTR];

    snprintf(command, COMMANDSIZE_4096 -1, "cat %s | %s %s", path, GREP, table);
    FILE *fp = popen(command, "r");

    if (fp) {
        while (fgets(output_buf, OS_MAXSTR, fp) != NULL) {
            pclose(fp);
            return OS_SUCCESS;
        }
        pclose(fp);
        return OS_INVALID;
    }
    return OS_INVALID;
}

/**
 * @brief search a pair pattern1 and after pattern2
 * @param output_buf buffer where search
 * @param str_pattern_1 pattern search to match
 * @param str_pattern_2 pattern search to match
 * @return 1 or 0 
 * @example retVal = isEnabledFromPattern(output_buf, "Status: ", "Enabled");
 * @example if for example with patter1:"Status :" find "Enabled", its return 1
*/
static int isEnabledFromPattern(const char * output_buf, const char * str_pattern_1, const char * str_pattern_2){
    int retVal = 0;
    const char *pos = NULL;
    if (str_pattern_1 != NULL) {
        pos = strstr(output_buf, str_pattern_1);
    }

    if (pos != NULL) {
        char state[OS_MAXSTR];
        char buffer[OS_MAXSTR];
        if (str_pattern_2 != NULL) {
            snprintf(buffer, OS_MAXSTR -1 , "%%*s %%%lds",strlen(str_pattern_2));
            if (pos && sscanf(pos, buffer /*"%*s %7s"*/, state) == 1) {
                if (strcmp(state, str_pattern_2) == 0) {
                    retVal = 1;
                } else {
                    retVal = 0;
                }
            }
        }
    }
    return  retVal;
}

/**
 * @brief write to file path
 * @param path path to file
 * @param cmd command or text to write inside file
 * @return 1 or 0 
*/
static int write_cmd_to_file(const char *path, const char *cmd) {
    int retVal = 0;
    if (path != NULL && cmd != NULL) {
        FILE *fp = fopen(path, "a+");
        if (fp != NULL) {
            fprintf(fp, "%s\n", cmd);
            retVal = 1;
        }
        fclose(fp);
    }
    return retVal;
 }
