/*
 * Wazuh Container Security - syscheck section parser
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined(__linux__) && defined(CLIENT)

#include "shared.h"
#include "config.h"
#include "syscheck-config.h"

/* The syscheckd half of <container_security>:
 *
 *   <container_security>
 *     <syscheck>
 *       <enabled>yes</enabled>
 *       <directories container_name="A">/data</directories>
 *       <directories>/etc</directories>
 *     </syscheck>
 *   </container_security>
 *
 * modulesd parses the same element for <container_instances> and <syscollector>
 * (see wmodules-container-instances.c); each daemon takes its own half and steps
 * over the other's, which is why both readers carry a known-siblings list.
 *
 * Two things follow from a <directories> entry living here rather than in the
 * top-level <syscheck>:
 *
 *   - it is container-scoped by construction, so no tags="container" marker;
 *   - it is never walked on the host, which is why these entries go into their
 *     own list instead of syscheck->directories.
 */
static const char* CS_XML_CONTAINER_INSTANCES = "container_instances";
static const char* CS_XML_SYSCHECK = "syscheck";
static const char* CS_XML_SYSCOLLECTOR = "syscollector";
static const char* CS_XML_ENABLED = "enabled";
static const char* CS_XML_DIRECTORIES = "directories";

static const char* CS_ATTR_CONTAINER_NAME = "container_name";
static const char* CS_ATTR_RESTRICT = "restrict";
static const char* CS_ATTR_REPORT_CHANGES = "report_changes";
static const char* CS_ATTR_RECURSION_LEVEL = "recursion_level";
static const char* CS_ATTR_DIFF_SIZE_LIMIT = "diff_size_limit";
static const char* CS_ATTR_TAGS = "tags";
static const char* CS_ATTR_REALTIME = "realtime";
static const char* CS_ATTR_WHODATA = "whodata";
static const char* CS_ATTR_FOLLOW_SYMBOLIC_LINK = "follow_symbolic_link";

/* yes/no is the Wazuh convention; true/false is accepted for the same reason the
 * modulesd-side parser accepts it (the HLD writes <enabled>true</enabled>), so the
 * boolean spelling is uniform across <container_security> rather than depending on
 * which daemon happens to read the block. */
static int cs_parse_bool(const char* content)
{
    if (!content)
    {
        return -1;
    }

    const int value = w_parse_bool(content);

    if (value >= 0)
    {
        return value;
    }

    if (strcmp(content, "true") == 0)
    {
        return 1;
    }

    if (strcmp(content, "false") == 0)
    {
        return 0;
    }

    return -1;
}

/* A container path is addressed through /proc/<pid>/root/<path>, so it must be
 * absolute and free of traversal segments: a ".." here would escape the container
 * rootfs and read the host. The scanner enforces this again at walk time; catching
 * it in the configuration means the operator hears about it at start-up instead of
 * silently losing the entry later. */
static int cs_path_is_safe(const char* path)
{
    if (path == NULL || path[0] != '/')
    {
        return 0;
    }

    for (const char* cursor = path; *cursor != '\0';)
    {
        if (cursor[0] == '/' && cursor[1] == '.' && cursor[2] == '.' && (cursor[3] == '/' || cursor[3] == '\0'))
        {
            return 0;
        }

        ++cursor;
    }

    return 1;
}

/* A wildcard cannot be expanded here: expand_wildcards() globs the *host*
 * filesystem, and these paths live inside container images that may not even be
 * pulled yet. Rejecting is honest; silently keeping the literal would monitor a
 * path named "*". */
static int cs_path_has_wildcard(const char* path)
{
    return strchr(path, '*') != NULL || strchr(path, '?') != NULL;
}

/* Parses one <directories> entry and appends it to syscheck->container_directories. */
static void cs_read_container_attr(syscheck_config* syscheck, const char* dirs, char** g_attrs, char** g_values)
{
    char** attrs = g_attrs;
    char** values = g_values;
    char* restrictfile = NULL;
    char* tag = NULL;
    char* container_name = NULL;
    int recursion_limit = syscheck->max_depth;
    int tmp_diff_size = -1;
    int opts = 0;

    /* Same defaults as a host entry: every check_* on, scheduled mode. */
    opts |= SCHEDULED_ACTIVE;
    (void)fim_parse_check_attribute("check_all", "yes", &opts);

    while (attrs && values && *attrs && *values)
    {
        const int check_rc = fim_parse_check_attribute(*attrs, *values, &opts);

        if (check_rc != 0)
        {
            if (check_rc < 0)
            {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        else if (strcmp(*attrs, CS_ATTR_CONTAINER_NAME) == 0)
        {
            if ((*values)[0] == '\0')
            {
                mwarn("Empty '%s' in <container_security><syscheck><directories>'%s'. Entry skipped.",
                      CS_ATTR_CONTAINER_NAME,
                      dirs);
                goto out_free;
            }

            os_free(container_name);
            os_strdup(*values, container_name);
        }
        else if (strcmp(*attrs, CS_ATTR_RESTRICT) == 0)
        {
            os_free(restrictfile);
            os_strdup(*values, restrictfile);
        }
        else if (strcmp(*attrs, CS_ATTR_TAGS) == 0)
        {
            os_free(tag);
            os_strdup(*values, tag);
        }
        else if (strcmp(*attrs, CS_ATTR_REPORT_CHANGES) == 0)
        {
            const int enable = cs_parse_bool(*values);

            if (enable < 0)
            {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }

            if (enable)
            {
                opts |= CHECK_SEECHANGES;
            }
            else
            {
                opts &= ~CHECK_SEECHANGES;
            }
        }
        else if (strcmp(*attrs, CS_ATTR_RECURSION_LEVEL) == 0)
        {
            if (!OS_StrIsNum(*values))
            {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }

            recursion_limit = (int)atoi(*values);

            if (recursion_limit < 0)
            {
                mwarn("Invalid recursion level value: %d. Setting 0.", recursion_limit);
                recursion_limit = 0;
            }
            else if (recursion_limit > MAX_DEPTH_ALLOWED)
            {
                mwarn("Recursion level '%d' exceeding limit. Setting %d.", recursion_limit, MAX_DEPTH_ALLOWED);
                recursion_limit = MAX_DEPTH_ALLOWED;
            }
        }
        else if (strcmp(*attrs, CS_ATTR_DIFF_SIZE_LIMIT) == 0)
        {
            tmp_diff_size = read_data_unit(*values);

            if (tmp_diff_size == -1)
            {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }

            if (tmp_diff_size < 1)
            {
                tmp_diff_size = 1; /* 1 KB is the minimum */
            }
        }
        else if (strcmp(*attrs, CS_ATTR_REALTIME) == 0 || strcmp(*attrs, CS_ATTR_WHODATA) == 0)
        {
            /* Container FIM is driven by eBPF file events; there is no scheduled vs
             * realtime vs whodata choice to make, so accepting these would promise a
             * mode selection that does not exist. */
            mwarn("'%s' does not apply to a container-scoped <directories> entry; container file monitoring is "
                  "always event driven. Ignoring it for '%s'.",
                  *attrs,
                  dirs);
        }
        else if (strcmp(*attrs, CS_ATTR_FOLLOW_SYMBOLIC_LINK) == 0)
        {
            /* realpath() would resolve against the host filesystem, not the
             * container's mount namespace, and would silently point elsewhere. */
            mwarn("'%s' does not apply to a container-scoped <directories> entry; symbolic links are resolved "
                  "inside the container. Ignoring it for '%s'.",
                  *attrs,
                  dirs);
        }
        else
        {
            mwarn(FIM_UNKNOWN_ATTRIBUTE, *attrs);
        }

        attrs++;
        values++;
    }

    if (opts == 0)
    {
        mwarn(FIM_NO_OPTIONS, dirs);
        goto out_free;
    }

    char** dir_org = OS_StrBreak(',', dirs, MAX_DIR_SIZE + 1);

    if (dir_org == NULL)
    {
        goto out_free;
    }

    int count = 0;

    for (char** dir = dir_org; *dir; dir++)
    {
        char* clean_path = w_strtrim(*dir);

        if (clean_path == NULL || *clean_path == '\0')
        {
            continue;
        }

        if (count++ >= MAX_DIR_SIZE)
        {
            mwarn(FIM_WARN_MAX_DIR_REACH, MAX_DIR_SIZE, clean_path);
            break;
        }

        if (cs_path_has_wildcard(clean_path))
        {
            mwarn("Wildcards are not supported in a container-scoped <directories> entry: '%s'. Entry skipped.",
                  clean_path);
            continue;
        }

        if (!cs_path_is_safe(clean_path))
        {
            mwarn("A container-scoped <directories> entry must be an absolute path without '..': '%s'. Entry "
                  "skipped.",
                  clean_path);
            continue;
        }

        /* Trailing separators would make the same path compare unequal in the merge
         * key, so "/data" and "/data/" are not two entries. */
        size_t len = strlen(clean_path);

        while (len > 1 && clean_path[len - 1] == PATH_SEP)
        {
            clean_path[--len] = '\0';
        }

        directory_t* new_entry =
            fim_create_directory(clean_path, opts, restrictfile, recursion_limit, tag, tmp_diff_size, 0);

        if (container_name != NULL)
        {
            os_strdup(container_name, new_entry->container.name);
        }

        fim_insert_container_directory(syscheck->container_directories, new_entry);
    }

    free_strarray(dir_org);

out_free:
    os_free(restrictfile);
    os_free(tag);
    os_free(container_name);
}

/* Parses the <syscheck> child of <container_security>. */
static int cs_read_syscheck_block(const OS_XML* xml, xml_node* node, syscheck_config* syscheck)
{
    xml_node** children = OS_GetElementsbyNode(xml, node);

    /* Writing the block is the opt-in, matching <container_instances>: present
     * without <enabled> means enabled. */
    syscheck->container_enabled = 1;

    if (children == NULL)
    {
        return 0;
    }

    for (int i = 0; children[i]; i++)
    {
        if (!children[i]->element)
        {
            continue;
        }

        if (strcmp(children[i]->element, CS_XML_ENABLED) == 0)
        {
            const int enabled = cs_parse_bool(children[i]->content);

            if (enabled < 0)
            {
                /* Fail closed, like the rest of <container_security>: a typo in a
                 * boolean disables container file monitoring, it does not stop the
                 * agent from starting. */
                merror("Invalid <%s> value '%s' in <container_security><syscheck>. Container file monitoring "
                       "disabled.",
                       CS_XML_ENABLED,
                       children[i]->content ? children[i]->content : "");
                syscheck->container_enabled = 0;
                OS_ClearNode(children);
                return 0;
            }

            syscheck->container_enabled = (unsigned int)enabled;
        }
        else if (strcmp(children[i]->element, CS_XML_DIRECTORIES) == 0)
        {
            if (children[i]->content == NULL)
            {
                mwarn("Empty <%s> in <container_security><syscheck>.", CS_XML_DIRECTORIES);
                continue;
            }

            cs_read_container_attr(syscheck, children[i]->content, children[i]->attributes, children[i]->values);
        }
        else
        {
            mwarn("Unknown option '%s' in <container_security><syscheck>.", children[i]->element);
        }
    }

    OS_ClearNode(children);
    return 0;
}

int Read_ContainerSecuritySyscheck(const OS_XML* xml, xml_node* node, void* d1)
{
    syscheck_config* syscheck = (syscheck_config*)d1;

    if (syscheck == NULL)
    {
        return OS_INVALID;
    }

    xml_node** children = OS_GetElementsbyNode(xml, node);

    if (children == NULL)
    {
        return 0;
    }

    int result = 0;

    for (int i = 0; children[i]; i++)
    {
        if (!children[i]->element)
        {
            continue;
        }

        if (strcmp(children[i]->element, CS_XML_SYSCHECK) == 0)
        {
            if (cs_read_syscheck_block(xml, children[i], syscheck) < 0)
            {
                result = OS_INVALID;
                break;
            }
        }
        else if (strcmp(children[i]->element, CS_XML_CONTAINER_INSTANCES) == 0 ||
                 strcmp(children[i]->element, CS_XML_SYSCOLLECTOR) == 0)
        {
            /* modulesd's half of the block. Step over it silently: warning here would
             * fire on every correct configuration. */
            continue;
        }
        else
        {
            mwarn("Unknown option '%s' in <container_security>.", children[i]->element);
        }
    }

    OS_ClearNode(children);

    if (syscheck->container_enabled && OSList_GetFirstNode(syscheck->container_directories) == NULL)
    {
        mwarn("<container_security><syscheck> is enabled but no <directories> entry was configured; container file "
              "monitoring has nothing to watch.");
    }

    return result;
}

#endif /* __linux__ && CLIENT */
