/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remoted_op.h"


/**
 * @brief Looks for the OS architecture in a string. Possibles architectures
 *        are x86_64, i386, i686, sparc, amd64, ia64, AIX, armv6, armv7.
 *        The function will return a pointer to allocated memory that must
 *        be de-allocated by the caller.
 *
 * @param[in] os_header String that contains the architecture. Usually uname.
 * @retval A string pointer to the architecture.
 */
char * get_os_arch(char * os_header) {
    const char * ARCHS[] = { "x86_64", "i386", "i686", "sparc", "amd64", "ia64", "AIX", "armv6", "armv7", NULL };
    char * os_arch = NULL;
    int i;

    for (i = 0; ARCHS[i]; i++) {
        if (strstr(os_header, ARCHS[i])) {
            os_strdup(ARCHS[i], os_arch);
            break;
        }
    }

    if (!ARCHS[i]) {
        os_strdup("", os_arch);
    }

    mdebug2("Detected architecture from %s: %s", os_header, os_arch);
    return os_arch;
}

/**
 * @brief Parses an agent update message to get the information by fields. All
 *        the OUT parameters are pointers to allocated memory that must be
 *        de-allocated by the caller.
 *
 * @param[in] msg The agent update message string to be parsed.
 * @param[Out] version The Wazuh version.
 * @param[Out] os_name The OS name.
 * @param[Out] os_major The OS major version.
 * @param[Out] os_minor The OS minor version.
 * @param[Out] os_build The OS build number.
 * @param[Out] os_version The OS full version.
 * @param[Out] os_codename The OS codename.
 * @param[Out] os_platform The OS platform.
 * @param[Out] os_arch The OS architecture.
 * @param[Out] uname The OS uname string.
 * @param[Out] config_sum The hash of the config file.
 * @param[Out] merged_sum The hash of the merged.mg file.
 * @param[Out] agent_ip The agent IP address.
 * @retval -1 Error parsing the message.
 * @retval 0 Success.
 */
int parse_agent_update_msg (char *msg,
                            char **version,
                            char **os_name,
                            char **os_major,
                            char **os_minor,
                            char **os_build,
                            char **os_version,
                            char **os_codename,
                            char **os_platform,
                            char **os_arch,
                            char **uname,
                            char **config_sum,
                            char **merged_sum,
                            char **agent_ip)
{
    char *msg_tmp = NULL;
    char *str_tmp = NULL;
    char *end_line = NULL;
    regmatch_t match[2] = { 0 };
    int match_size = 0;

    // Temporary coping the msg string
    os_strdup(msg, msg_tmp);

    if (!msg_tmp)
        return OS_INVALID; 

    if (end_line = strstr(msg_tmp, "\n"), end_line){
        *end_line = '\0';
    } else {
        mwarn("Corrupt data parsing agent update msg. Returning.");
        os_free(msg_tmp);
        return OS_INVALID;
    }

    if (str_tmp = strstr(msg_tmp, " / "), str_tmp){
        *str_tmp = '\0';
        str_tmp += 3;
        os_strdup(str_tmp, *config_sum);
    }

    if (str_tmp = strstr(msg_tmp, " - "), str_tmp){
        *str_tmp = '\0';
        str_tmp += 3;
        os_strdup(str_tmp, *version);
    } else {
        merror("Corrupt data parsing agent update msg. Returning.");
        os_free(msg_tmp);
        return OS_INVALID;
    }

    // [Ver: os_major.os_minor.os_build]
    if (str_tmp = strstr(msg_tmp, " [Ver: "), str_tmp){
        *str_tmp = '\0';
        str_tmp += 7;
        os_strdup(msg_tmp, *os_name);
        *(str_tmp + strlen(str_tmp) - 1) = '\0';

        // Get os_major
        if (w_regexec("^([0-9]+)\\.*", str_tmp, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            *os_major = malloc(match_size +1 );
            snprintf (*os_major, match_size + 1, "%.*s", match_size, str_tmp + match[1].rm_so);
        }

        // Get os_minor
        if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", str_tmp, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            *os_minor = malloc(match_size +1);
            snprintf(*os_minor, match_size + 1, "%.*s", match_size, str_tmp + match[1].rm_so);
        }

        // Get os_build
        if (w_regexec("^[0-9]+\\.[0-9]+\\.([0-9]+)\\.*", str_tmp, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            *os_build = malloc(match_size +1);
            snprintf(*os_build, match_size + 1, "%.*s", match_size, str_tmp + match[1].rm_so);
        }

        os_strdup(str_tmp, *os_version);
        os_strdup("windows", *os_platform);
    }
    else {
        if (str_tmp = strstr(msg_tmp, " ["), str_tmp){
            *str_tmp = '\0';
            str_tmp += 2;
            os_strdup(str_tmp, *os_name);
            if (str_tmp = strstr(*os_name, ": "), str_tmp){
                *str_tmp = '\0';
                str_tmp += 2;
                os_strdup(str_tmp, *os_version);
                *(*os_version + strlen(*os_version) - 1) = '\0';

                // os_major.os_minor (os_codename)
                if (str_tmp = strstr(*os_version, " ("), str_tmp){
                    *str_tmp = '\0';
                    str_tmp += 2;
                    os_strdup(str_tmp, *os_codename);
                    *(*os_codename + strlen(*os_codename) - 1) = '\0';
                }

                // Get os_major
                if (w_regexec("^([0-9]+)\\.*", *os_version, 2, match)) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    *os_major = malloc(match_size +1);
                    snprintf(*os_major, match_size + 1, "%.*s", match_size, *os_version + match[1].rm_so);
                }

                // Get os_minor
                if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", *os_version, 2, match)) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    *os_minor = malloc(match_size +1);
                    snprintf(*os_minor, match_size + 1, "%.*s", match_size, *os_version + match[1].rm_so);
                }

            } else
                *(*os_name + strlen(*os_name) - 1) = '\0';

            // os_name|os_platform
            if (str_tmp = strstr(*os_name, "|"), str_tmp){
                *str_tmp = '\0';
                str_tmp++;
                os_strdup(str_tmp, *os_platform);
            }
        }
        str_tmp = get_os_arch(msg_tmp);
        os_strdup(str_tmp, *os_arch);
        os_free(str_tmp);
    }

    os_strdup(msg_tmp, *uname);

    // Get merged.mg sum
    str_tmp = end_line + 1;
    if (*str_tmp != '\"' && *str_tmp != '!' && (end_line = strchr(str_tmp, ' '), end_line)) {
        *end_line = '\0';
        end_line++;

        if (strncmp(end_line, SHAREDCFG_FILENAME "\n", sizeof(SHAREDCFG_FILENAME "\n")-1) != 0) {
            *merged_sum = NULL;
        }
        else {
            os_strdup(str_tmp, *merged_sum);
        }
    }
    else { // If we didn't find merged.mg we should keep the end line
        end_line = str_tmp;
    }

    // Get the agent ip
    const char * AGENT_IP_TAG = "#\"_agent_ip\":";
    str_tmp = end_line;

    end_line = strchr(str_tmp, '\n') + 1;
    if (end_line && !strncmp(end_line, AGENT_IP_TAG, strlen(AGENT_IP_TAG))) {
        os_strdup(end_line + strlen(AGENT_IP_TAG), *agent_ip);

        if (end_line = strchr(*agent_ip, '\n'), end_line){
            *end_line = '\0';
        }
    }
    else {
        agent_ip = NULL;
    }

    os_free(msg_tmp);

    return OS_SUCCESS;
}