/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "config/localfile-config.h"
#include "config/config.h"
#include "logcollector/logcollector.h"

#undef ARGV0
#define ARGV0 "verify-agent-conf"

#define AGENT_CONF_FILE "agent.conf"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));
static int verify_agent_conf(const char * path);


static void helpmsg()
{
    printf("\n%s %s: Verify agent.conf syntax for errors.\n", __ossec_name, ARGV0);
    printf("Usage:  %s [-f <agent.conf file>]\n\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n");
    printf("\t-f          Full file name and path to config file to be tested.\n");
    printf("\t            If this option is not specified, this program will scan \n");
    printf("\t            all folders inside the 'shared' folder.\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *ar = DEFAULTDIR SHAREDCFG_DIR;
    char path[PATH_MAX + 1];
    char path_f[PATH_MAX + 1];
    DIR *gdir, *subdir;
    struct dirent *entry;
    int c = 0;
    int error = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    /* User arguments */
    if (argc > 1) {
        while ((c = getopt(argc, argv, "Vdhf:")) != -1) {
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
                    if (!optarg) {
                        merror("-f needs an argument");
                        helpmsg();
                    }
                    else{
                        if (IsFile(optarg) < 0){
                            merror("[%s] is not a valid file.\n", optarg);
                            error = 1;
                            break;
                        }

                        if (verify_agent_conf(optarg) < 0)
                            error = 1;
                        else
                            printf("%s: OK\n", ARGV0);
                    }
                    break;
                default:
                    helpmsg();
                    break;
            } // switch
        } // while
    }//if
    else{
        gdir = opendir(ar);
        if (!gdir) {
            merror("Opening directory: '%s'", ar);
            return 1;
        }

        while (entry = readdir(gdir), entry) {
            // Skip "." and ".."
            if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
                continue;
            }

            if (snprintf(path, PATH_MAX + 1, "%s/%s", ar, entry->d_name) > PATH_MAX) {
                merror("Path too long.");
                error = 1;
                break;
            }

            subdir = opendir(path);

            if (!subdir) {
                if (errno != ENOTDIR) {
                    merror("Could not open directory '%s'", path);
                    error = 1;
                }
                continue;
            }

            if (snprintf(path_f, PATH_MAX + 1, "%s/%s", path, AGENT_CONF_FILE) > PATH_MAX) {
                merror("Path too long.");
                error = 1;
                break;
            }

            printf("\n%s: Verifying [%s]\n", ARGV0, path_f);

            if (IsFile(path_f) < 0){
                printf("%s: File not found\n", ARGV0);
                error = 1;
                continue;
            }

            if (verify_agent_conf(path_f) < 0)
                error = 1;
            else
                printf("%s: OK\n", ARGV0);

            closedir(subdir);
        }
        closedir(gdir);
    }
    printf("\n");
    return (error);
}

int verify_agent_conf(const char * path) {

    if (Test_Syscheck(path) < 0) {
        return -1;
    } else if (Test_Rootcheck(path) < 0) {
        return -1;
    } else if (Test_Localfile(path) < 0) {
        return -1;
    } else if (Test_Client(path) < 0) {
        return -1;
    } else if (Test_ClientBuffer(path) < 0) {
        return -1;
    } else if (Test_WModule(path) < 0) {
        return -1;
    } else if (Test_Labels(path) < 0) {
        return -1;
    }

    return 0;
}
