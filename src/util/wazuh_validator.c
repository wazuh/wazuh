/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CLIENT

#include "shared.h"
#include "config/config.h"
#include "config/localfile-config.h"
#include "logcollector/logcollector.h"
#include "getopt.h"

#undef ARGV0
#define ARGV0 "wazuh-validator"
#define MANDATORY_OPTION "-t is a mandatory option.\n"

#define MANAGER_CFG          1
// #define AGENT_CFG           2
// #define REMOTE_CFG          3

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\nUsage:  %s -t <manager/agent/remote> [-f <.conf file>]\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n\n");
    printf("\t-t          Mandatory option. Type of configuration file to be tested:\n");
    printf("\t            <manager>, <agent> or <remote>\n");
    printf("\t-f          Absolute path to config file to be tested.\n");
    printf("\t            If this option is not specified. Defaults to\n");
    printf("\t            \"%s%s\", or\n", DEFAULTDIR, OSSECCONF);
    printf("\t            \"%s\", if \"-t remote\" is provided.\n\n", AGENTCONFIG);
    exit(1);
}

int main(int argc, char **argv)
{
    /* Set the name */
    OS_SetName(ARGV0);

    printf("\n");
    /* User arguments */
    if (argc > 1) {
        char path_f[PATH_MAX + 1] = {0,};
        int c = 0, type_flag = 0;   // file_type = CLOCAL_CONFIG;

        while ((c = getopt(argc, argv, "Vdhf:t:")) != -1) {
            switch (c) {
                case 'V':
                    print_version();
                    break;
                case 'h':
                    helpmsg();
                    break;
                case 'd':
                    nowDebug();
                    break;
                case 'f':
                    if (IsFile(optarg) < 0){
                        fprintf(stderr, "%s: [%s] is not a valid file. Exiting...\n\n", ARGV0, optarg);
                        return -1;
                    }
                    memset(path_f, '\0', sizeof(path_f));
                    strncpy(path_f, optarg, PATH_MAX);
                    break;
                case 't':
                    if(strcmp("agent", optarg) == 0) {
                        type_flag = CAGENT_CGFILE;
                    }
                    else if(strcmp("manager", optarg) == 0) {
                        type_flag = MANAGER_CFG;
                    }
                    else if(strcmp("remote", optarg) == 0) {
                        type_flag = CRMOTE_CONFIG;
                    }
                    else {
                        fprintf(stderr, "%s: Unknown value for -t option\n\n", ARGV0);
                        helpmsg();
                    }
                    break;
                default:
                    helpmsg();
                    break;
            }
        }

        char *filepath = NULL;
        if(strcmp(path_f, "") != 0) {
            filepath = strdup(path_f);
        }

        if(type_flag == MANAGER_CFG) {
            if(!filepath) {
                filepath = strdup(DEFAULTDIR OSSECCONF);
            }
            test_manager_conf(filepath);
            os_free(filepath);
        }
        else if(type_flag == CAGENT_CGFILE) {
            if(!filepath) {
                filepath = strdup(DEFAULTDIR OSSECCONF);
            }
            test_agent_conf(filepath, type_flag);
        }
        else if(type_flag == CRMOTE_CONFIG) {
            if(!filepath) {
                filepath = strdup(AGENTCONFIG);
            }
            test_remote_conf(filepath, type_flag);
            os_free(filepath);
        }
    }
    else{
        fprintf(stderr, "%s: %s", ARGV0, MANDATORY_OPTION);
        helpmsg();
    }

    return 0;
}


#endif