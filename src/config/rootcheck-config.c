/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck-config.h"
#include "config.h"



static short eval_bool(const char *str)
{
    if (str == NULL) {
        return (OS_INVALID);
    } else if (strcmp(str, "yes") == 0) {
        return (1);
    } else if (strcmp(str, "no") == 0) {
        return (0);
    } else {
        return (OS_INVALID);
    }
}

/* Read the rootcheck config */
int Read_Rootcheck(XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;
    rkconfig *rootcheck;

    /* XML Definitions */
    const char *xml_scanall = "scanall";
    const char *xml_readall = "readall";
    const char *xml_time = "frequency";
    const char *xml_disabled = "disabled";
    const char *xml_skip_nfs = "skip_nfs";
    const char *xml_base_dir = "base_directory";
    const char *xml_ignore = "ignore";

    const char *xml_check_dev = "check_dev";
    const char *xml_check_if = "check_if";
    const char *xml_check_pids = "check_pids";
    const char *xml_check_ports = "check_ports";
    const char *xml_check_sys = "check_sys";

    rootcheck = (rkconfig *)configp;

    /* If rootcheck is defined, enable it by default */
    if (rootcheck->disabled == RK_CONF_UNPARSED) {
        rootcheck->disabled = RK_CONF_UNDEFINED;
    }

    if (!node)
        return 0;

    while (node[i]) {
        if (!node[i]->element) {
            mwarn(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            mwarn(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }

        /* Get frequency */
        else if (strcmp(node[i]->element, xml_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            rootcheck->time = atoi(node[i]->content);
        }
        /* Get scan all */
        else if (strcmp(node[i]->element, xml_scanall) == 0) {
            rootcheck->scanall = eval_bool(node[i]->content);
            if (rootcheck->scanall == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_disabled) == 0) {
            rootcheck->disabled = eval_bool(node[i]->content);
            if (rootcheck->disabled == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_skip_nfs) == 0)
        {
            rootcheck->skip_nfs = eval_bool(node[i]->content);
            if (rootcheck->skip_nfs == OS_INVALID)
            {
                mwarn(XML_VALUEERR, node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_readall) == 0)
        {
            rootcheck->readall = eval_bool(node[i]->content);
            if (rootcheck->readall == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, "rootkit_files") == 0) {
            mwarn("Rootcheck option 'rootkit_files' is no longer supported. Use the FIM module instead.");
        } else if (strcmp(node[i]->element, "rootkit_trojans") == 0) {
            mwarn("Rootcheck option 'rootkit_trojans' is no longer supported. Use the FIM module instead.");
        } else if (strcmp(node[i]->element, "windows_audit") == 0) {
            mwarn("Rootcheck option 'windows_audit' is no longer supported. Use the SCA module instead.");
        } else if (strcmp(node[i]->element, "system_audit") == 0) {
            mwarn("Rootcheck option 'system_audit' is no longer supported. Use the SCA module instead.");
        } else if (strcmp(node[i]->element, xml_ignore) == 0) {
            unsigned int j = 0;
            while (rootcheck->ignore && rootcheck->ignore[j]) {
                j++;
            }

            os_realloc(rootcheck->ignore, sizeof(char *) * (j + 2), rootcheck->ignore);
            os_strdup(node[i]->content, rootcheck->ignore[j]);
            rootcheck->ignore[j + 1] = NULL;

            os_realloc(rootcheck->ignore_sregex, sizeof(OSMatch *) * (j + 2), rootcheck->ignore_sregex);
            rootcheck->ignore_sregex[j] = NULL;
            rootcheck->ignore_sregex[j + 1] = NULL;

            if (node[i]->attributes && node[i]->values && *node[i]->attributes && *node[i]->values) {
                if (strcmp(*node[i]->attributes, "type")) {
                    mwarn("Invalid attribute for '%s': '%s'.", node[i]->element, *node[i]->attributes);
                    return OS_INVALID;
                } else if (strcmp(*node[i]->values, "sregex")) {
                    mwarn("Invalid value for '%s': '%s'.", *node[i]->attributes, *node[i]->values);
                    return OS_INVALID;
                }
                os_calloc(1, sizeof(OSMatch), rootcheck->ignore_sregex[j]);
#ifndef WIN32
                if (!OSMatch_Compile(rootcheck->ignore[j], rootcheck->ignore_sregex[j], 0)) {
#else
                if (!OSMatch_Compile(rootcheck->ignore[j], rootcheck->ignore_sregex[j], OS_CASE_SENSITIVE)) {
#endif
                    merror(REGEX_COMPILE, rootcheck->ignore[j], rootcheck->ignore_sregex[j]->error);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, "windows_malware") == 0) {
            mwarn("Rootcheck option 'windows_malware' is no longer supported. Use the SCA module instead.");
        } else if (strcmp(node[i]->element, "windows_apps") == 0) {
            mwarn("Rootcheck option 'windows_apps' is no longer supported. Use the SCA module instead.");
        } else if (strcmp(node[i]->element, xml_base_dir) == 0) {
            os_strdup(node[i]->content, rootcheck->basedir);
        } else if (strcmp(node[i]->element, xml_check_dev) == 0) {
            rootcheck->checks.rc_dev = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_dev == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, "check_files") == 0) {
            mwarn("Rootcheck option 'check_files' is no longer supported. Use the FIM module instead.");

        } else if (strcmp(node[i]->element, xml_check_if) == 0) {
            rootcheck->checks.rc_if = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_if == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_pids) == 0) {
            rootcheck->checks.rc_pids = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_pids == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_ports) == 0) {
            rootcheck->checks.rc_ports = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_ports == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_sys) == 0) {
            rootcheck->checks.rc_sys = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_sys == OS_INVALID) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, "check_trojans") == 0) {
            mwarn("Rootcheck option 'check_trojans' is no longer supported. Use the FIM module instead.");
        } else if (strcmp(node[i]->element, "check_unixaudit") == 0) {
            mwarn("Rootcheck option 'check_unixaudit' is no longer supported. Use the SCA module instead.");
        } else if (strcmp(node[i]->element, "check_winapps") == 0) {
            mwarn("Rootcheck option 'check_winapps' is no longer supported. Use the SCA module instead.");
        } else if (strcmp(node[i]->element, "check_winaudit") == 0) {
            mwarn("Rootcheck option 'check_winaudit' is no longer supported. Use the SCA module instead.");
        } else if (strcmp(node[i]->element, "check_winmalware") == 0) {
            mwarn("Rootcheck option 'check_winmalware' is no longer supported. Use the SCA module instead.");
        } else {
            mwarn(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }
    return (0);
}

int Test_Rootcheck(const char * path){
    int fail = 0;
    rkconfig test_rootcheck = { .workdir = 0 };

    if (ReadConfig(CAGENT_CONFIG | CROOTCHECK, path, &test_rootcheck, NULL) < 0) {
        merror(RCONFIG_ERROR,"Rootcheck", path);
		fail = 1;
	}

    Free_Rootcheck(&test_rootcheck);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void Free_Rootcheck(rkconfig * config){
    if (config) {
        int i;
        free((char*) config->workdir);
        free(config->basedir);
        if (config->ignore) {
            for (i=0; config->ignore[i] != NULL; i++) {
                free(config->ignore[i]);
            }
            free(config->ignore);
        }
        if (config->alert_msg) {
            for (i=0; config->alert_msg[i] != NULL; i++) {
                free(config->alert_msg[i]);
            }
            free(config->alert_msg);
        }
        if (config->fp) {
            fclose(config->fp);
        }
    }
}
