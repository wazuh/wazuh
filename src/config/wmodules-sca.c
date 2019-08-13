/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_sca.h"

#include <stdio.h>

static const char *XML_ENABLED = "enabled";
static const char *XML_SCAN_DAY = "day";
static const char *XML_WEEK_DAY = "wday";
static const char *XML_TIME = "time";
static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_ON_START= "scan_on_start";
static const char *XML_POLICIES = "policies";
static const char *XML_POLICY = "policy";
static const char *XML_SKIP_NFS = "skip_nfs";
static unsigned int profiles = 0;


#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)


static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// Reading function
int wm_sca_read(const OS_XML *xml,xml_node **nodes, wmodule *module)
{
    unsigned int i;
    int month_interval = 0;
    wm_sca_t *sca;

    if(!module->data) {
        os_calloc(1, sizeof(wm_sca_t), sca);
        sca->enabled = 1;
        sca->scan_on_start = 1;
        sca->scan_wday = -1;
        sca->scan_day = 0;
        sca->scan_time = NULL;
        sca->skip_nfs = 1;
        sca->alert_msg = NULL;
        sca->queue = -1;
        sca->interval = WM_DEF_INTERVAL / 2;
        sca->profile = NULL;
        module->context = &WM_SCA_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = sca;
        profiles = 0;
    }

    sca = module->data;

    /* By default, load all every ruleset present */

    char ruleset_path[PATH_MAX] = {0};
    #ifdef WIN32
    sprintf(ruleset_path, "%s\\", SECURITY_CONFIGURATION_ASSESSMENT_DIR_WIN);
    #else
    sprintf(ruleset_path, "%s/", DEFAULTDIR SECURITY_CONFIGURATION_ASSESSMENT_DIR);
    #endif

    DIR *ruleset_dir = opendir(ruleset_path);
    const int open_dir_errno = errno;
    if (ruleset_dir) {
        struct dirent *dir_entry;
        while ((dir_entry = readdir(ruleset_dir)) != NULL) {
            if (strcmp(dir_entry->d_name, ".") == 0 || strcmp(dir_entry->d_name, "..") == 0) {
                continue;
            }

            const char * const file_extension = strrchr(dir_entry->d_name, '.');
            if (!file_extension || (strcmp(file_extension, ".yml") != 0 && strcmp(file_extension, ".yaml") != 0)) {
                continue;
            }

            /* get the full path of the policy file */
            char relative_path[PATH_MAX] = {0};
            const int ruleset_path_len = sprintf(relative_path, "%s", ruleset_path);
            strncat(relative_path, dir_entry->d_name, PATH_MAX - ruleset_path_len);

            char realpath_buffer[PATH_MAX] = {0};
            #ifdef WIN32
            const int path_length = GetFullPathName(relative_path, PATH_MAX, realpath_buffer, NULL);
            if (!path_length) {
                mwarn("File '%s' not found.", dir_entry->d_name);
                continue;
            }
            #else
            const char * const realpath_buffer_ref = realpath(relative_path, realpath_buffer);
            if (!realpath_buffer_ref) {
                mwarn("File '%s' not found.", dir_entry->d_name);
                continue;
            }
            #endif

            int policy_found = 0;

            if (sca->profile) {
                int i;
                for(i = 0; sca->profile[i]; i++) {
                    if(sca->profile[i]->profile && !strcmp(sca->profile[i]->profile, realpath_buffer)) {
                        /* Avoid adding policies by default for each xml configuration block.
                        This happens because wm_sca_read function is called once for each xml
                        configuration block */
                        policy_found = 1;
                        break;
                    }
                }
            }

            if (policy_found) {
                continue;
            }

            minfo("Adding policy file '%s' by default.", realpath_buffer);

            os_realloc(sca->profile, (profiles + 2) * sizeof(wm_sca_profile_t *), sca->profile);
            wm_sca_profile_t *policy;
            os_calloc(1,sizeof(wm_sca_profile_t),policy);

            policy->enabled = 1;
            policy->policy_id = NULL;
            policy->remote = 0;
            os_strdup(realpath_buffer, policy->profile);
            sca->profile[profiles] = policy;
            sca->profile[profiles + 1] = NULL;
            profiles++;
        }

        closedir(ruleset_dir);
    } else {
        minfo("Could not open the default SCA ruleset folder '%s': %s", ruleset_path, strerror(open_dir_errno));
    }

    if(!sca->alert_msg) {
        /* We store up to 255 alerts */
        os_calloc(256, sizeof(char *), sca->alert_msg);
    }

    if (!nodes) {
        return 0;
    }

    for(i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_ENABLED))
        {
            int enabled = eval_bool(nodes[i]->content);

            if(enabled == OS_INVALID){
                merror("Invalid content for tag '%s'", XML_ENABLED);
                return OS_INVALID;
            }

            sca->enabled = enabled;
        }
        else if (!strcmp(nodes[i]->element, XML_WEEK_DAY))
        {
            sca->scan_wday = w_validate_wday(nodes[i]->content);
            if (sca->scan_wday < 0 || sca->scan_wday > 6) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SCAN_DAY)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            } else {
                sca->scan_day = atoi(nodes[i]->content);
                if (sca->scan_day < 1 || sca->scan_day > 31) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                    return (OS_INVALID);
                }
            }
        }
        else if (!strcmp(nodes[i]->element, XML_TIME))
        {
            sca->scan_time = w_validate_time(nodes[i]->content);
            if (!sca->scan_time) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            sca->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (sca->interval == 0 || sca->interval == UINT_MAX) {
                merror("Invalid interval value.");
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'M':
                month_interval = 1;
                sca->interval *= 60; // We can`t calculate seconds of a month
                break;
            case 'w':
                sca->interval *= 604800;
                break;
            case 'd':
                sca->interval *= 86400;
                break;
            case 'h':
                sca->interval *= 3600;
                break;
            case 'm':
                sca->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval value.");
                return OS_INVALID;
            }

            if (sca->interval < 60) {
                mwarn("Interval must be greater than 60 seconds. New interval value: 60s");
                sca->interval = 60;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START))
        {
            int scan_on_start = eval_bool(nodes[i]->content);

            if(scan_on_start == OS_INVALID)
            {
                merror("Invalid content for tag '%s'", XML_ENABLED);
                return OS_INVALID;
            }

            sca->scan_on_start = scan_on_start;
        }
        else if (!strcmp(nodes[i]->element, XML_POLICIES))
        {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, nodes[i]), !children) {
                return OS_INVALID;
            }

            int  j;
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, XML_POLICY) == 0) {
                    int enabled = 1;
                    int policy_found = 0;

                    if(children[j]->attributes && children[j]->values) {

                        if(strcmp(*children[j]->attributes,XML_ENABLED) == 0){
                            if(strcmp(*children[j]->values,"no") == 0){
                                enabled = 0;
                            }
                        }
                    }

                    if(strlen(children[j]->content) >= PATH_MAX) {
                        merror("Policy path is too long. Max path length is %d.", PATH_MAX);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    } else if (strlen(children[j]->content) == 0) {
                        merror("Empty policy value.");
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    /* full path resolution */
                    char relative_path[PATH_MAX] = {0};
                    const int ruleset_path_len = sprintf(relative_path, "%s", ruleset_path);
                    strncat(relative_path, children[j]->content, PATH_MAX - ruleset_path_len);

                    char realpath_buffer[PATH_MAX] = {0};
                    #ifdef WIN32
                    if (children[j]->content[1] && children[j]->content[2]) {
                        if ((children[j]->content[1] == ':') || (children[j]->content[0] == '\\' && children[j]->content[1] == '\\')) {
                            sprintf(realpath_buffer,"%s", children[j]->content);
                        } else {
                            const int path_length = GetFullPathName(relative_path, PATH_MAX, realpath_buffer, NULL);
                            if (!path_length) {
                                mwarn("File '%s' not found.", children[j]->content);
                                continue;
                            }
                        }
                    }
                    #else
                    if(children[j]->content[0] == '/') {
                        sprintf(realpath_buffer,"%s", children[j]->content);
                    } else {
                        const char * const realpath_buffer_ref = realpath(relative_path, realpath_buffer);
                        if (!realpath_buffer_ref) {
                            mwarn("File '%s' not found.", children[j]->content);
                            continue;
                        }
                    }
                    #endif

                    if(sca->profile) {
                        int i;
                        for(i = 0; sca->profile[i]; i++) {
                            if(!strcmp(sca->profile[i]->profile, realpath_buffer)) {
                                sca->profile[i]->enabled = enabled;
                                if(!enabled) {
                                    minfo("Disabling policy '%s' by configuration.", realpath_buffer);
                                }
                                policy_found = 1;
                                break;
                            }
                        }
                    }

                    //beware of IsFile inverted, twisted logic.
                    if (IsFile(realpath_buffer)) {
                        mwarn("Policy file '%s' not found. Check your configuration.", realpath_buffer);
                        continue;
                    }

                    if(!policy_found) {
                        os_realloc(sca->profile, (profiles + 2) * sizeof(wm_sca_profile_t *), sca->profile);
                        wm_sca_profile_t *policy;
                        os_calloc(1,sizeof(wm_sca_profile_t),policy);
                        minfo("Adding policy file '%s'", realpath_buffer);
                        policy->enabled = enabled;
                        policy->policy_id = NULL;
                        policy->remote = strstr(realpath_buffer, "etc/shared/") != NULL;
                        os_strdup(realpath_buffer, policy->profile);
                        sca->profile[profiles] = policy;
                        sca->profile[profiles + 1] = NULL;
                        profiles++;
                    }
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        }
        else if (!strcmp(nodes[i]->element, XML_SKIP_NFS))
        {
            int skip_nfs = eval_bool(nodes[i]->content);

            if(skip_nfs == OS_INVALID){
                merror("Invalid content for tag '%s'", XML_SKIP_NFS);
                return OS_INVALID;
            }

            sca->skip_nfs = skip_nfs;
        }
        else
        {
            mwarn("No such tag <%s>", nodes[i]->element);
        }
    }

    // Validate scheduled scan parameters and interval value

    if (sca->scan_day && (sca->scan_wday >= 0)) {
        merror("Options 'day' and 'wday' are not compatible.");
        return OS_INVALID;
    } else if (sca->scan_day) {
        if (!month_interval) {
            mwarn("Interval must be a multiple of one month. New interval value: 1M");
            sca->interval = 60; // 1 month
        }
        if (!sca->scan_time)
            sca->scan_time = strdup("00:00");
    } else if (sca->scan_wday >= 0) {
        if (w_validate_interval(sca->interval, 1) != 0) {
            sca->interval = 604800;  // 1 week
            mwarn("Interval must be a multiple of one week. New interval value: 1w");
        }
        if (sca->interval == 0)
            sca->interval = 604800;
        if (!sca->scan_time)
            sca->scan_time = strdup("00:00");
    } else if (sca->scan_time) {
        if (w_validate_interval(sca->interval, 0) != 0) {
            sca->interval = WM_DEF_INTERVAL;  // 1 day
            mwarn("Interval must be a multiple of one day. New interval value: 1d");
        }
    }

    return 0;
}
