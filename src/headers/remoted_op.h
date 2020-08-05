/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"


/**
 * @brief Looks for the OS architecture in a string. Possibles architectures
 *        are x86_64, i386, i686, sparc, amd64, ia64, AIX, armv6, armv7.
 *        The function will return a pointer to allocated memory that must
 *        be de-allocated by the caller.
 *
 * @param[in] os_header String that contains the architecture. Usually uname.
 * @retval A string pointer to the architecture.
 */
char * get_os_arch(char * os_header);

/**
 * @brief Parses an OS uname string. All the OUT parameters are pointers
 *        to allocated memory that must be de-allocated by the caller.
 *
 * @param[in] msg The agent update message string to be parsed.
 * @param[Out] os_name The OS name.
 * @param[Out] os_major The OS major version.
 * @param[Out] os_minor The OS minor version.
 * @param[Out] os_build The OS build number.
 * @param[Out] os_version The OS full version.
 * @param[Out] os_codename The OS codename.
 * @param[Out] os_platform The OS platform.
 * @param[Out] os_arch The OS architecture.
 */
void parse_uname_string (char *uname,
                        char **os_name,
                        char **os_major,
                        char **os_minor,
                        char **os_build,
                        char **os_version,
                        char **os_codename,
                        char **os_platform,
                        char **os_arch);

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
 * @param[Out] labels String with all the labels separated by EOL.
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
                            char **agent_ip,
                            char **labels);
