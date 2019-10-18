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

#include "config/config.h"
#include "config/localfile-config.h"
#include "logcollector/logcollector.h"
#include "getopt.h"
#include "headers/check_config.h"
#include "../os_net/os_net.h"
#include <ifaddrs.h>

#undef ARGV0
#define ARGV0                   "./check_configuration"
#define MANDATORY_OPTION        "-t is a mandatory option."
#define ARGS_EXCEEDED           "number of arguments exceeded."

#define MANAGER_CFG          1


/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\nUsage:  %s -t TYPE [OPTIONS]\n\n", ARGV0);
    printf("TYPE:\n");
    printf("\tmanager     Wazuh manager configuration (ossec.conf).\n");
    printf("\tagent       Wazuh agent configuration (ossec.conf).\n");
    printf("\tremote      Wazuh centralized agent configuration (agent.conf).\n\n");
    printf("OPTIONS:\n");
    printf("\t-h          This help message.\n\n");
    printf("\t-f          Absolute path to config file to be tested.\n");
    printf("\t            If this option is not specified. Defaults to\n");
    printf("\t            \"install/path/to/ossec.conf\", or\n");
    printf("\t            \"/path/to/shared/agent.conf\", if \"-t remote\" is provided.\n\n");
    exit(1);
}

int main(int argc, char **argv)
{
    /* Set the name */
    OS_SetName(ARGV0);

    printf("\n");
    /* User arguments */
    if (argc > 1 && argc < 6) {
        char path_f[PATH_MAX + 1] = {0,};
        int c = 0, type_flag = 0;

        while ((c = getopt(argc, argv, "hf:t:")) != -1) {
            switch (c) {
                case 'h':
                    helpmsg();
                    break;
                case 'f':
                    if (IsFile(optarg) < 0) {
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
                        fprintf(stderr, "%s: Unknown value for -t option\n", ARGV0);
                        helpmsg();
                    }
                    break;
                default:
                    helpmsg();
                    break;
            }
        }

        if(!type_flag) {
            fprintf(stderr, "%s: %s\n", ARGV0, MANDATORY_OPTION);
            helpmsg();
        }

        if(type_flag && !(strcmp(path_f, "")) && (argc > 3)) {
            fprintf(stderr, "%s WARNING: -f option was not found. If you want to check a specific file this option must be provided.\n\n", ARGV0);
            return 0;
        }

        char *filepath = NULL;
        if(strcmp(path_f, "") != 0) {
            filepath = strdup(path_f);
        }

        if(!filepath) {
            filepath = type_flag == CRMOTE_CONFIG ? strdup(DEFAULTDIR SHAREDCFG_DIR "/default/agent.conf") : strdup(DEFAULTCPATH);
        }

        char *output = NULL;
        int result;
        if(type_flag == MANAGER_CFG) {
            result = test_manager_conf(filepath, &output);
        }
        else if(type_flag == CAGENT_CGFILE) {
            result = test_agent_conf(filepath, type_flag, &output);
        }
        else if(type_flag == CRMOTE_CONFIG) {
            result = test_remote_conf(filepath, type_flag, &output);
        }
        if (result == 0) {
            printf("Configuration validated successfully\n");
        } else {
            printf("%s\n", output);
        }

        os_free(output);
        os_free(filepath);
    }
    else if (argc > 5) {
        fprintf(stderr, "%s: %s\n", ARGV0, ARGS_EXCEEDED);
        helpmsg();
    }
    else {
        fprintf(stderr, "%s: %s\n", ARGV0, MANDATORY_OPTION);
        helpmsg();
    }

    printf("\n");
    return 0;
}


#endif