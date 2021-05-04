/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "setup-shared.h"
#include "os_xml/os_xml.h"
#include "../error_messages/error_messages.h"
#include <errno.h>
#define AGENT_CONFIG_TMP  ".tmp.agent.conf"


/* Enable Syscheck */
int main(int argc, char **argv)
{
    char *status;
    const char *(xml_syscheck_status[]) = {"wazuh_config", "syscheck", "disabled", NULL};

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

    /* Check if WAZUH was installed already */
    if (!fileexist(AGENTCONF)) {
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
    if (OS_WriteXML(AGENTCONF, AGENT_CONFIG_TMP, xml_syscheck_status,
                    "no", status) != 0) {
        printf("%s: Error writing to the Config file. Exiting.\n", argv[0]);
        return (0);
    }

    /* Rename config files */
    unlink(AGENT_CONF_LAST);
    if (rename(AGENTCONF, AGENT_CONF_LAST)) {
        printf(RENAME_ERROR, AGENTCONF, AGENT_CONF_LAST, errno, strerror(errno));
    }
    if (rename(AGENT_CONFIG_TMP, AGENTCONF)) {
        printf(RENAME_ERROR, AGENT_CONFIG_TMP, AGENTCONF, errno, strerror(errno));
    }

    return (0);
}
