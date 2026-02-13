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
    regmatch_t match[2] = {{.rm_so = 0}};
    int match_size = 0;

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
            *(str_tmp + strlen(str_tmp) - 1) = '\0';
        }

        // Get os_major
        if (w_regexec("^([0-9]+)\\.*", str_tmp, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            os_malloc(match_size +1, osd->os_major);
            snprintf (osd->os_major, match_size + 1, "%.*s", match_size, str_tmp + match[1].rm_so);
        }

        // Get os_minor
        if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", str_tmp, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            os_malloc(match_size +1, osd->os_minor);
            snprintf(osd->os_minor, match_size + 1, "%.*s", match_size, str_tmp + match[1].rm_so);
        }

        // Get os_build
        if (w_regexec("^[0-9]+\\.[0-9]+\\.([0-9]+(\\.[0-9]+)*)\\.*", str_tmp, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            os_malloc(match_size +1, osd->os_build);
            snprintf(osd->os_build, match_size + 1, "%.*s", match_size, str_tmp + match[1].rm_so);
        }

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
                *(osd->os_version + strlen(osd->os_version) - 1) = '\0';

                // os_major.os_minor (os_codename)
                if (str_tmp = strstr(osd->os_version, " ("), str_tmp) {
                    *str_tmp = '\0';
                    str_tmp += 2;
                    os_strdup(str_tmp, osd->os_codename);
                    *(osd->os_codename + strlen(osd->os_codename) - 1) = '\0';
                }

                // Get os_major
                if (w_regexec("^([0-9]+)\\.*", osd->os_version, 2, match)) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size +1, osd->os_major);
                    snprintf(osd->os_major, match_size + 1, "%.*s", match_size, osd->os_version + match[1].rm_so);
                }

                // Get os_minor
                if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", osd->os_version, 2, match)) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size +1, osd->os_minor);
                    snprintf(osd->os_minor, match_size + 1, "%.*s", match_size, osd->os_version + match[1].rm_so);
                } else if (w_regexec("^[0-9]+-[Ss][Pp]([0-9]+)\\.*", osd->os_version, 2, match)) {
                    // SUSE: 15-SP7, 15-SPxx
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, osd->os_minor);
                    snprintf(osd->os_minor, match_size + 1, "%.*s", match_size, osd->os_version + match[1].rm_so);
                }

            } else {
                *(osd->os_name + strlen(osd->os_name) - 1) = '\0';
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
        case '#':  // System label
        case '!':  // Hidden label
        case '\"': // Regular label
            // The _agent_ip will not be appended to the labels string.
            // Instead it will be returned in the agent_ip parameter.
            if (!strncmp(line, agent_ip_label, strlen(agent_ip_label))) {
                os_strdup(line + strlen(agent_ip_label), agent_data->agent_ip);
            }
            else {
                wm_strcat(&agent_data->labels, line, '\n');
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
                os_strdup(line, agent_data->osd->os_uname);

                line = str_tmp;
                if (str_tmp = strstr(line, " / "), str_tmp) {
                    *str_tmp = '\0';
                    str_tmp += 3;
                    os_strdup(line, agent_data->version);
                    os_strdup(str_tmp, agent_data->config_sum);
                }
                else if (str_tmp = strstr(line, __ossec_name), str_tmp) {
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

/* Parse JSON keepalive message (5.0+ agents) */
int parse_json_keepalive(const char *json_str, agent_info_data *agent_data, char ***groups_out, size_t *groups_count_out, char **cluster_name_out, char **cluster_node_out) {
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return OS_INVALID;
    }

    cJSON *agent = cJSON_GetObjectItem(root, "agent");
    if (!agent) {
        cJSON_Delete(root);
        return OS_INVALID;
    }

    // Extract agent version
    cJSON *version = cJSON_GetObjectItem(agent, "version");
    if (version && cJSON_IsString(version)) {
        os_strdup(version->valuestring, agent_data->version);
    }

    // Extract agent config_sum
    cJSON *config_sum = cJSON_GetObjectItem(agent, "config_sum");
    if (config_sum && cJSON_IsString(config_sum)) {
        os_strdup(config_sum->valuestring, agent_data->config_sum);
    }

    // Extract agent merged_sum
    cJSON *merged_sum = cJSON_GetObjectItem(agent, "merged_sum");
    if (merged_sum && cJSON_IsString(merged_sum)) {
        os_strdup(merged_sum->valuestring, agent_data->merged_sum);
    }

    // Extract agent ip
    cJSON *agent_ip = cJSON_GetObjectItem(agent, "ip");
    if (agent_ip && cJSON_IsString(agent_ip)) {
        os_strdup(agent_ip->valuestring, agent_data->agent_ip);
    }

    // Extract agent uname
    cJSON *agent_uname = cJSON_GetObjectItem(agent, "uname");

    // Extract agent labels
    cJSON *labels = cJSON_GetObjectItem(agent, "labels");
    if (labels && cJSON_IsString(labels)) {
        os_strdup(labels->valuestring, agent_data->labels);
    }

    // Allocate os_data structure
    os_calloc(1, sizeof(os_data), agent_data->osd);

    // Parse uname FIRST to get ALL fields (major, minor, codename, build)
    if (agent_uname && cJSON_IsString(agent_uname)) {
        char *uname_copy = NULL;
        os_strdup(agent_uname->valuestring, uname_copy);
        os_strdup(agent_uname->valuestring, agent_data->osd->os_uname);
        parse_uname_string(uname_copy, agent_data->osd);
        os_free(uname_copy);
    }

    // Extract host info
    cJSON *host = cJSON_GetObjectItem(root, "host");
    if (host) {
        // Extract OS info
        cJSON *os = cJSON_GetObjectItem(host, "os");
        if (os) {

            // THEN overwrite with more accurate JSON fields
            cJSON *os_name = cJSON_GetObjectItem(os, "name");
            if (os_name && cJSON_IsString(os_name)) {
                os_free(agent_data->osd->os_name);
                os_strdup(os_name->valuestring, agent_data->osd->os_name);
            }

            cJSON *os_version = cJSON_GetObjectItem(os, "version");
            if (os_version && cJSON_IsString(os_version)) {
                os_free(agent_data->osd->os_version);
                os_strdup(os_version->valuestring, agent_data->osd->os_version);
            }

            cJSON *os_platform = cJSON_GetObjectItem(os, "platform");
            if (os_platform && cJSON_IsString(os_platform)) {
                os_free(agent_data->osd->os_platform);
                os_strdup(os_platform->valuestring, agent_data->osd->os_platform);
            }

            cJSON *os_type = cJSON_GetObjectItem(os, "type");
            if (os_type && cJSON_IsString(os_type)) {
                os_free(agent_data->osd->os_type);
                os_strdup(os_type->valuestring, agent_data->osd->os_type);
            }
        }

        // Extract architecture (after uname parsing, to overwrite if present)
        cJSON *architecture = cJSON_GetObjectItem(host, "architecture");
        if (architecture && cJSON_IsString(architecture)) {
            os_free(agent_data->osd->os_arch);
            os_strdup(architecture->valuestring, agent_data->osd->os_arch);
        }

        // Extract hostname (after uname parsing, to overwrite if present)
        cJSON *hostname = cJSON_GetObjectItem(host, "hostname");
        if (hostname && cJSON_IsString(hostname)) {
            os_free(agent_data->osd->hostname);
            os_strdup(hostname->valuestring, agent_data->osd->hostname);
        }
    }

    // Extract groups if requested
    if (groups_out && groups_count_out) {
        *groups_out = NULL;
        *groups_count_out = 0;

        cJSON *groups = cJSON_GetObjectItem(agent, "groups");
        if (groups && cJSON_IsArray(groups)) {
            int group_count = cJSON_GetArraySize(groups);
            if (group_count > 0) {
                os_calloc(group_count, sizeof(char*), *groups_out);

                for (int i = 0; i < group_count; i++) {
                    cJSON *group_item = cJSON_GetArrayItem(groups, i);
                    if (group_item && cJSON_IsString(group_item) && group_item->valuestring[0]) {
                        os_strdup(group_item->valuestring, (*groups_out)[*groups_count_out]);
                        (*groups_count_out)++;
                    }
                }
            }
        }
    }

    // Extract cluster info if requested
    if (cluster_name_out || cluster_node_out) {
        cJSON *cluster = cJSON_GetObjectItem(root, "cluster");
        if (cluster) {
            if (cluster_name_out) {
                *cluster_name_out = NULL;
                cJSON *cluster_name = cJSON_GetObjectItem(cluster, "name");
                if (cluster_name && cJSON_IsString(cluster_name) && cluster_name->valuestring[0]) {
                    os_strdup(cluster_name->valuestring, *cluster_name_out);
                }
            }
            if (cluster_node_out) {
                *cluster_node_out = NULL;
                cJSON *cluster_node = cJSON_GetObjectItem(cluster, "node");
                if (cluster_node && cJSON_IsString(cluster_node) && cluster_node->valuestring[0]) {
                    os_strdup(cluster_node->valuestring, *cluster_node_out);
                }
            }
        }
    }

    cJSON_Delete(root);
    return OS_SUCCESS;
}

#endif
