/*
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remoted_op.h"

#ifndef WIN32

/**
 * @brief Looks for the OS architecture in a string. Possibles architectures
 *        are x86_64, i386, i686, sparc, amd64, ia64, AIX, armv6, armv7.
 *        The function will return a pointer to allocated memory that must
 *        be de-allocated by the caller.
 *
 * @param[in] os_header String that contains the architecture. Usually uname.
 * @retval A string pointer to the architecture. NULL if not found.
 */
char * get_os_arch(char * os_header) {
    const char * ARCHS[] = { "x86_64", "i386", "i686", "sparc", "amd64", "i86pc", "ia64", "AIX", "armv6", "armv7", "aarch64", "arm64", NULL };
    char * os_arch = NULL;
    int i;

    for (i = 0; ARCHS[i]; i++) {
        if (strstr(os_header, ARCHS[i])) {
            os_strdup(ARCHS[i], os_arch);
            break;
        }
    }

    return os_arch;
}

/**
 * @brief Extracts os_major and os_minor from a version string.
 *        Handles formats like "10.0", "22.04", and SUSE "15-SP7".
 *        Output parameters are set to allocated strings or left unchanged.
 *
 * @param[in] version The version string to parse.
 * @param[out] os_major Pointer to receive the major version string.
 * @param[out] os_minor Pointer to receive the minor version string.
 */
static void extract_os_version_parts(const char *version, char **os_major, char **os_minor) {
    regmatch_t match[2] = {{.rm_so = 0}};
    int match_size = 0;

    // Get os_major
    if (w_regexec("^([0-9]+)\\.*", version, 2, match)) {
        match_size = match[1].rm_eo - match[1].rm_so;
        os_malloc(match_size + 1, *os_major);
        snprintf(*os_major, match_size + 1, "%.*s", match_size, version + match[1].rm_so);
    }

    // Get os_minor
    if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", version, 2, match)) {
        match_size = match[1].rm_eo - match[1].rm_so;
        os_malloc(match_size + 1, *os_minor);
        snprintf(*os_minor, match_size + 1, "%.*s", match_size, version + match[1].rm_so);
    } else if (w_regexec("^[0-9]+-[Ss][Pp]([0-9]+)\\.*", version, 2, match)) {
        // SUSE: 15-SP7, 15-SPxx
        match_size = match[1].rm_eo - match[1].rm_so;
        os_malloc(match_size + 1, *os_minor);
        snprintf(*os_minor, match_size + 1, "%.*s", match_size, version + match[1].rm_so);
    }
}

/**
 * @brief Parses an OS uname string. All the OUT parameters are pointers
 *        to allocated memory that must be de-allocated by the caller.
 *
 * @param[in] msg The agent update message string to be parsed.
 * @param[in] osd An os_data structure to be filled with the os's data.
 */
void parse_uname_string (char *uname,
                         os_data *osd)
{
    char *str_tmp = NULL;

    if (!osd)
        return;

    // [Ver: os_major.os_minor.os_build]
    if (str_tmp = strstr(uname, " [Ver: "), str_tmp) {
        char *bracket_end = NULL;

        *str_tmp = '\0';
        str_tmp += 7;
        os_strdup(uname, osd->os_name);

        // Find closing bracket to handle both old and new formats
        if (bracket_end = strchr(str_tmp, ']'), bracket_end) {
            *bracket_end = '\0';

            char *hostname_start = strstr(bracket_end + 1, " |");
            if (hostname_start) {
                hostname_start += 2;
                char *hostname_end = strstr(hostname_start, " |");
                if (hostname_end) {
                    // Extract hostname
                    int hostname_len = hostname_end - hostname_start;
                    os_malloc(hostname_len + 1, osd->hostname);
                    snprintf(osd->hostname, hostname_len + 1, "%.*s", hostname_len, hostname_start);

                    // Extract architecture
                    char *arch_start = hostname_end + 2;
                    while (*arch_start == ' ') arch_start++;
                    if (*arch_start) {
                        char *arch_end = arch_start;
                        while (*arch_end && *arch_end != ' ' && *arch_end != '-') arch_end++;
                        int arch_len = arch_end - arch_start;
                        if (arch_len > 0) {
                            os_malloc(arch_len + 1, osd->os_arch);
                            snprintf(osd->os_arch, arch_len + 1, "%.*s", arch_len, arch_start);
                        }
                    }
                }
            }
        } else {
            mwarn("Windows uname missing closing ']' in version field: '%s'", str_tmp);
        }

        extract_os_version_parts(str_tmp, &osd->os_major, &osd->os_minor);

        os_strdup(str_tmp, osd->os_version);
        os_strdup("windows", osd->os_platform);
    } else {
        if (str_tmp = strstr(uname, " |"), str_tmp) {
            char *hostname_start = str_tmp + 2;
            char *hostname_end = strstr(hostname_start, " |");
            if (hostname_end) {
                int hostname_len = hostname_end - hostname_start;
                os_malloc(hostname_len + 1, osd->hostname);
                snprintf(osd->hostname, hostname_len + 1, "%.*s", hostname_len, hostname_start);
            }
        }

        if (str_tmp = strstr(uname, " ["), str_tmp) {
            *str_tmp = '\0';
            str_tmp += 2;
            os_strdup(str_tmp, osd->os_name);
            if (str_tmp = strstr(osd->os_name, ": "), str_tmp) {
                *str_tmp = '\0';
                str_tmp += 2;
                os_strdup(str_tmp, osd->os_version);
                    size_t ver_len = strlen(osd->os_version);
                    if (ver_len > 0 && osd->os_version[ver_len - 1] == ']') osd->os_version[ver_len - 1] = '\0';

                // Strip codename suffix from version string e.g. "22.04 (Jammy Jellyfish)"
                if (str_tmp = strstr(osd->os_version, " ("), str_tmp) {
                    *str_tmp = '\0';
                }

                extract_os_version_parts(osd->os_version, &osd->os_major, &osd->os_minor);

            } else {
                size_t name_len = strlen(osd->os_name);
                if (name_len > 0 && osd->os_name[name_len - 1] == ']') osd->os_name[name_len - 1] = '\0';
            }

            // os_name|os_platform
            if (str_tmp = strstr(osd->os_name, "|"), str_tmp) {
                *str_tmp = '\0';
                str_tmp++;
                os_strdup(str_tmp, osd->os_platform);
            }
        }

        if (str_tmp = get_os_arch(uname), str_tmp) {
            os_strdup(str_tmp, osd->os_arch);
            os_free(str_tmp);
        }
    }
}

/**
 * @brief Parses an agent update message to get the information by fields. All
 *        the OUT parameters are pointers to allocated memory that must be
 *        de-allocated by the caller. If the information is not found for an
 *        OUT parameter, it returns pointing to NULL.
 *
 * @param[in] msg The agent update message string to be parsed.
 * @param[in] agent_data An agent_info_data structure to be filled with the agent's data.
 * @retval -1 Error parsing the message.
 * @retval 0 Success.
 */
int parse_agent_update_msg (char *msg,
                            agent_info_data *agent_data)
{
    char *msg_tmp = NULL;
    char *str_tmp = NULL;
    char *line = NULL;
    char *savedptr = NULL;
    char sdelim[] = { '\n', '\0' };
    const char * agent_ip_label = "#\"_agent_ip\":";

    if (!agent_data) {
        return OS_INVALID;
    }

    // Temporary coping the msg string
    os_strdup(msg, msg_tmp);

    for (line = strtok_r(msg_tmp, sdelim, &savedptr); line; line = strtok_r(NULL, sdelim, &savedptr)) {
        switch (*line) {
        case '#':  // Legacy format: prefixed metadata line
        case '!':
        case '\"':
            // Extract agent IP from legacy text keepalive format.
            if (!strncmp(line, agent_ip_label, strlen(agent_ip_label))) {
                os_strdup(line + strlen(agent_ip_label), agent_data->agent_ip);
            }
            break;
        default:
            // uname - wazuh version / config sum
            if (str_tmp = strstr(line, " - "), str_tmp)
            {
                *str_tmp = '\0';
                str_tmp += 3;

                os_calloc(1, sizeof(os_data), agent_data->osd);
                parse_uname_string(line, agent_data->osd);

                line = str_tmp;
                if (str_tmp = strstr(line, " / "), str_tmp) {
                    *str_tmp = '\0';
                    os_strdup(line, agent_data->version);
                }
                else if (str_tmp = strstr(line, __wazuh_name), str_tmp) {
                    // If for some reason the separator between Wazuh version and config sum is
                    // not found, we look for the Wazuh version in the second part of the line.
                    os_strdup(str_tmp, agent_data->version);
                }
            }
            // merged sum
            else if (str_tmp = strchr(line, ' '), str_tmp)
            {
                *str_tmp = '\0';
                str_tmp++;

                if (strncmp(str_tmp, SHAREDCFG_FILENAME, strlen(SHAREDCFG_FILENAME)-1) == 0) {
                    os_strdup(line, agent_data->merged_sum);
                }
            }
        }
    }

    os_free(msg_tmp);

    return OS_SUCCESS;
}

#endif
