/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32
#include <sys/types.h>
#include <grp.h>
#endif

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "active-response.h"
#include "config.h"

/* Global variables */
int ar_flag = 0;


/* Generate a list with all active responses */
int ReadActiveResponses(XML_NODE node, void *d1, void *d2)
{
    OSList *l1 = (OSList *) d1;
    OSList *l2 = (OSList *) d2;
    active_response *tmp_ar = NULL;
    FILE *fp;
    int i = 0;
    int r_ar = 0;
    int l_ar = 0;
    int rpt = 0;
    int ret_value = OS_INVALID;

    /* Xml options */
    const char *xml_ar_command = "command";
    const char *xml_ar_location = "location";
    const char *xml_ar_agent_id = "agent_id";
    const char *xml_ar_rules_id = "rules_id";
    const char *xml_ar_rules_group = "rules_group";
    const char *xml_ar_level = "level";
    const char *xml_ar_timeout = "timeout";
    const char *xml_ar_disabled = "disabled";
    const char *xml_ar_repeated = "repeated_offenders";
    const char *xml_ca_store = "ca_store";
    char *tmp_location = NULL;

    /* Open shared ar file */
    fp = wfopen(DEFAULTAR, "a");
    if (!fp) {
        merror(FOPEN_ERROR, DEFAULTAR, errno, strerror(errno));
        return (-1);
    }

#ifndef WIN32
    gid_t gid = Privsep_GetGroup(USER);

    if (gid == (gid_t)-1) {
        merror("Could not get group name.");
        fclose(fp);
        return OS_INVALID;
    }

    if ((chown(DEFAULTAR, (uid_t) - 1, gid)) == -1) {
        merror("Could not change the group to '%s': %d.", GROUPGLOBAL, errno);
        fclose(fp);
        return OS_INVALID;
    }

#endif

    if ((chmod(DEFAULTAR, 0640)) == -1) {
        merror("Could not chmod to 0640: '%d'", errno);
        fclose(fp);
        return (-1);
    }

    /* Allocate for the active-response */
    os_calloc(1, sizeof(active_response), tmp_ar);

    /* Search for the commands */
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            goto end;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            goto end;
        }

        /* Command */
        if (strcmp(node[i]->element, xml_ar_command) == 0) {
            tmp_ar->command = strdup(node[i]->content);
        }
        /* Target */
        else if (strcmp(node[i]->element, xml_ar_location) == 0) {
            os_free(tmp_location);
            os_strdup(node[i]->content, tmp_location);
        } else if (strcmp(node[i]->element, xml_ar_agent_id) == 0) {
            os_strdup(node[i]->content, tmp_ar->agent_id);
        } else if (strcmp(node[i]->element, xml_ar_rules_id) == 0) {
            os_strdup(node[i]->content, tmp_ar->rules_id);
        } else if (strcmp(node[i]->element, xml_ar_rules_group) == 0) {
            os_strdup(node[i]->content, tmp_ar->rules_group);
        } else if (strcmp(node[i]->element, xml_ar_level) == 0) {
            /* Level must be numeric */
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                goto end;
            }

            tmp_ar->level = atoi(node[i]->content);

            /* Make sure the level is valid */
            if ((tmp_ar->level < 0) || (tmp_ar->level > 20)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                goto end;
            }
        } else if (strcmp(node[i]->element, xml_ar_timeout) == 0) {
            tmp_ar->timeout = atoi(node[i]->content);
        } else if (strcmp(node[i]->element, xml_ar_disabled) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                ar_flag = -1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                /* Don't do anything if disabled is set to "no" */
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                goto end;
            }
        } else if (strcmp(node[i]->element, xml_ar_repeated) == 0) {
            /* Nothing - we deal with it on execd */
            rpt = 1;
        } else if (strcmp(node[i]->element, xml_ca_store) == 0) {
            // Nothing to do
        } else {
            merror(XML_INVELEM, node[i]->element);
            goto end;
        }
        i++;
    }

    /* Check if ar is disabled */
    if (ar_flag == -1) {
        /* reset ar_flag, the next ar command may not be disabled */
        ar_flag = 0;
        if (tmp_ar->command) {
            mdebug1("active response command '%s' is disabled", tmp_ar->command);
        }
        ret_value = 0;
        goto end;
    }

    /* Command and location must be there */
    if (!tmp_ar->command || !tmp_location || *(tmp_ar->command) == '\0' || *(tmp_location) == '\0') {
        mdebug1("Command or location missing");

        if (rpt == 1) {
            ret_value = 0;
            goto end;
        }
        merror(AR_MISS);
        goto end;
    }

    /* analysisd */
    if (OS_Regex("AS|analysisd|analysis-server|server", tmp_location)) {
        tmp_ar->location |= AS_ONLY;
    }

    if (OS_Regex("local", tmp_location)) {
        tmp_ar->location |= REMOTE_AGENT;
    }

    if (OS_Regex("defined-agent", tmp_location)) {
        if (!tmp_ar->agent_id) {
            mdebug1("'defined-agent' agent_id not defined");
            merror(AR_DEF_AGENT);
            goto end;
        }

        if (atoi(tmp_ar->agent_id) == 0) {
            mdebug1("'defined-agent' is 0");
            mwarn(AR_SERVER_AGENT);
            ret_value = 0;
            goto end;
        }

        tmp_ar->location |= SPECIFIC_AGENT;

    }
    if (OS_Regex("all|any", tmp_location)) {
        tmp_ar->location |= ALL_AGENTS;
    }

    /* If we didn't set any value for the location */
    if (tmp_ar->location == 0) {
        mdebug1("No location defined");
        merror(AR_INV_LOC, tmp_location);
        goto end;
    }


    /* Check if command name is valid */
    {
        OSListNode *my_commands_node;

        my_commands_node = OSList_GetFirstNode(l1);
        while (my_commands_node) {
            ar_command *my_command;
            my_command = (ar_command *)my_commands_node->data;

            if (strcmp(my_command->name, tmp_ar->command) == 0) {
                tmp_ar->ar_cmd = my_command;
                break;
            }

            my_commands_node = OSList_GetNextNode(l1);
        }

        /* Didn't find a valid command */
        if (tmp_ar->ar_cmd == NULL) {
            mdebug1("Invalid command");
            merror(AR_INV_CMD, tmp_ar->command);
            goto end;
        }
    }

    /* Check if timeout is allowed */
    if (tmp_ar->timeout && !tmp_ar->ar_cmd->timeout_allowed) {
        mdebug1("Timeout is not allowed");
        minfo(AR_NO_TIMEOUT, tmp_ar->ar_cmd->name);
        tmp_ar->timeout = 0;
    }

    /* d1 is the active response list */
    if (!OSList_AddData(l2, (void *)tmp_ar)) {
        merror(LIST_ADD_ERROR);
        goto end;
    }

    /* Set a unique active response name */
    tmp_ar->name = (char *) calloc(OS_FLSIZE + 1, sizeof(char));
    if (!tmp_ar->name) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
    snprintf(tmp_ar->name, OS_FLSIZE, "%s%d",
             tmp_ar->ar_cmd->name,
             tmp_ar->timeout);

    /* Add to shared file */
    mdebug1("Writing command '%s' to '%s'", tmp_ar->command, DEFAULTAR);
    fprintf(fp, "%s - %s - %d\n",
            tmp_ar->name,
            tmp_ar->ar_cmd->executable,
            tmp_ar->timeout);

    /* Set the configs to start the right queues */
    if (tmp_ar->location & AS_ONLY) {
        l_ar = 1;
    }
    if (tmp_ar->location & ALL_AGENTS) {
        r_ar = 1;
    }
    if (tmp_ar->location & REMOTE_AGENT) {
        r_ar = 1;
        l_ar = 1;
    }
    if (tmp_ar->location & SPECIFIC_AGENT) {
        r_ar = 1;
    }

    /* Set the configuration for the active response */
    if (r_ar && (!(ar_flag & REMOTE_AR))) {
        ar_flag |= REMOTE_AR;
    }
    if (l_ar && (!(ar_flag & LOCAL_AR))) {
        ar_flag |= LOCAL_AR;
    }

    /* Done over here */
    fclose(fp);
    os_free(tmp_location);

    return (0);

end:
    fclose(fp);
    os_free(tmp_ar->agent_id);
    os_free(tmp_ar->rules_id);
    os_free(tmp_ar->rules_group);
    os_free(tmp_ar->command);

    os_free(tmp_ar);
    os_free(tmp_location);

    return ret_value;
}

int ReadActiveCommands(XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    OSList *l1 = (OSList *) d1;
    int i = 0;

    /* Xml values */
    const char *command_name = "name";
    const char *command_expect = "expect";
    const char *command_executable = "executable";
    const char *timeout_allowed = "timeout_allowed";
    const char *extra_args = "extra_args";

    ar_command *tmp_command;

    /* Allocate the active-response command */
    os_calloc(1, sizeof(ar_command), tmp_command);

    /* Search for the commands */
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            goto end;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            goto end;
        }
        if (strcmp(node[i]->element, command_name) == 0) {
            // The command name must not start with '!'

            if (node[i]->content[0] == '!') {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                goto end;
            }

            tmp_command->name = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, command_expect) == 0) {
            mdebug1("The <%s> tag is deprecated since version 4.2.0.", command_expect);
        } else if (strcmp(node[i]->element, command_executable) == 0) {
            tmp_command->executable = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, timeout_allowed) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                tmp_command->timeout_allowed = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                tmp_command->timeout_allowed = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                goto end;
            }
        } else if (strcmp(node[i]->element, extra_args) == 0) {
            tmp_command->extra_args = strdup(node[i]->content);
        } else {
            merror(XML_INVELEM, node[i]->element);
            goto end;
        }
        i++;
    }

    if (!tmp_command->name || !tmp_command->executable) {
        merror(AR_CMD_MISS);
        goto end;
    }

    /* Add command to the list */
    if (!OSList_AddData(l1, (void *)tmp_command)) {
        merror(LIST_ADD_ERROR);
        goto end;
    }

    return (0);

end:
    os_free(tmp_command->name);
    os_free(tmp_command->executable);
    os_free(tmp_command->extra_args);
    os_free(tmp_command);

    return (OS_INVALID);
}
