/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "setup-shared.h"
#include "os_xml.h"
#include "error_messages.h"
#include <errno.h>
#define OSSEC_CONFIG_TMP  ".tmp.ossec.conf"


/* Enable Syscheck */
int main(int argc, char **argv)
{
    char *status;
    const char *(xml_syscheck_status[]) = {"ossec_config", "syscheck", "disabled", NULL};

    if (argc < 3) {
        printf("%s: Invalid syntax.\n", argv[0]);
        printf("Try: '%s <dir> [enable|disable]'\n\n", argv[0]);
        return (0);
    }

    /* Check for directory */
    if (chdir(argv[1]) != 0) {
        printf("%s: Invalid directory: '%s'.\n", argv[0], argv[1]);
        return (0);
    }

    /* Check if WAZUH-HIDS was installed already */
    if (!fileexist(WAZUHCONF)) {
        printf("%s: WAZUH not installed yet. Exiting.\n", argv[0]);
        return (0);
    }

    /* Check status */
    if (strcmp(argv[2], "enable") == 0) {
        status = "no";
    } else {
        status = "yes";
    }

    /* Write to the config file */
    if (OS_WriteXML(WAZUHCONF, OSSEC_CONFIG_TMP, xml_syscheck_status,
                    "no", status) != 0) {
        printf("%s: Error writing to the Config file. Exiting.\n", argv[0]);
        return (0);
    }

    /* Rename config files */
    unlink(OSSECLAST);
    if (rename(WAZUHCONF, OSSECLAST)) {
        printf(RENAME_ERROR, WAZUHCONF, OSSECLAST, errno, strerror(errno));
    }
    if (rename(OSSEC_CONFIG_TMP, WAZUHCONF)) {
        printf(RENAME_ERROR, OSSEC_CONFIG_TMP, WAZUHCONF, errno, strerror(errno));
    }

    return (0);
}
