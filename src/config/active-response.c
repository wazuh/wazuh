/* Copyright (C) 2015-2019, Wazuh Inc.
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
int ReadActiveResponses(XML_NODE node, void *d1, void *d2, char **output)
{
    OSList *l1 = (OSList *) d1;
    OSList *l2 = (OSList *) d2;
    FILE *fp;
    int i = 0;
    int r_ar = 0;
    int l_ar = 0;
    int rpt = 0;
    char message[OS_FLSIZE];

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
    const char *xml_ca_verification = "ca_verification";

    char *tmp_location;

    /* Currently active response */
    active_response *tmp_ar;

    /* Open shared ar file */
    fp = fopen(DEFAULTARPATH, "a");
    if (!fp) {
        if (output == NULL) {
            merror(FOPEN_ERROR, DEFAULTARPATH, errno, strerror(errno));
        } else {
            snprintf(message, OS_FLSIZE,
                "Could not open file '%s' due to [(%d)-(%s)].",
                DEFAULTARPATH, errno, strerror(errno));
            wm_strcat(output, message, '\n');
        }
        return (-1);
    }

#ifndef WIN32
    struct group *os_group;
    if ((os_group = getgrnam(USER)) == NULL) {
        if (output == NULL) {
            merror("Could not get ossec gid.");
        } else {
            wm_strcat(output, "Could not get ossec gid.", '\n');
        }
        fclose(fp);
        return (-1);
    }

    if ((chown(DEFAULTARPATH, (uid_t) - 1, os_group->gr_gid)) == -1) {
        if (output == NULL) {
            merror("Could not change the group to ossec: %d", errno);
        } else {
            snprintf(message, OS_FLSIZE,
                "Could not change the group to ossec: %d",
                errno);
            wm_strcat(output, message, '\n');
        }
        fclose(fp);
        return (-1);
    }
#endif

    if ((chmod(DEFAULTARPATH, 0640)) == -1) {
        if (output == NULL) {
            merror("Could not chmod to 0640: %d", errno);
        } else {
            snprintf(message, OS_FLSIZE,
                "Could not chmod to 0640: %d",
                errno);
            wm_strcat(output, message, '\n');
        }
        fclose(fp);
        return (-1);
    }

    /* Allocate for the active-response */
    tmp_ar = (active_response *) calloc(1, sizeof(active_response));
    if (!tmp_ar) {
        if (output == NULL) {
            merror(MEM_ERROR, errno, strerror(errno));
        } else {
            snprintf(message, OS_FLSIZE,
                "Could not acquire memory due to [(%d)-(%s)].",
                errno, strerror(errno));
            wm_strcat(output, message, '\n');
        }
        fclose(fp);
        return (-1);
    }

    /* Initialize variables */
    tmp_ar->name = NULL;
    tmp_ar->command = NULL;
    tmp_ar->location = 0;
    tmp_ar->timeout = 0;
    tmp_ar->level = 0;
    tmp_ar->agent_id = NULL;
    tmp_ar->rules_id = NULL;
    tmp_ar->rules_group = NULL;
    tmp_ar->ar_cmd = NULL;
    tmp_location = NULL;

    /* Search for the commands */
    while (node[i]) {
        if (!node[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            goto error_invalid;
        } else if (!node[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            goto error_invalid;
        }

        /* Command */
        if (strcmp(node[i]->element, xml_ar_command) == 0) {
            tmp_ar->command = strdup(node[i]->content);
        }
        /* Target */
        else if (strcmp(node[i]->element, xml_ar_location) == 0) {
            free(tmp_location);
            tmp_location = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, xml_ar_agent_id) == 0) {
            tmp_ar->agent_id = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, xml_ar_rules_id) == 0) {
            tmp_ar->rules_id = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, xml_ar_rules_group) == 0) {
            tmp_ar->rules_group = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, xml_ar_level) == 0) {
            /* Level must be numeric */
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                goto error_invalid;
            }

            tmp_ar->level = atoi(node[i]->content);

            /* Make sure the level is valid */
            if ((tmp_ar->level < 0) || (tmp_ar->level > 20)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                goto error_invalid;
            }
        } else if (strcmp(node[i]->element, xml_ar_timeout) == 0) {
            tmp_ar->timeout = atoi(node[i]->content);
        } else if (strcmp(node[i]->element, xml_ar_disabled) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                ar_flag = -1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                /* Don't do anything if disabled is set to "no" */
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                goto error_invalid;
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                goto error_invalid;
            }
        } else if (strcmp(node[i]->element, xml_ar_repeated) == 0) {
            /* Nothing - we deal with it on execd and test in Test_Agent_Active_Response */
            rpt = 1;
        } else if (strcmp(node[i]->element, xml_ca_store) == 0) {
            // Nothing to do
        } else if (strcmp(node[i]->element, xml_ca_verification) == 0) {
            // Nothing to do
        } else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            goto error_invalid;
        } else {
            snprintf(message, OS_FLSIZE,
                "Invalid element in the configuration: '%s'.",
                node[i]->element);
            wm_strcat(output, message, '\n');
            goto error_invalid;
        }
        i++;
    }

    /* Check if ar is disabled */
    if (ar_flag == -1) {
        /* reset ar_flag, the next ar command may not be disabled */
        ar_flag = 0;
        if (tmp_ar->command) {
            if (output == NULL){
                mdebug1("active response command '%s' is disabled", tmp_ar->command);
            }
            free(tmp_ar->command);
        }
        fclose(fp);
        free(tmp_ar);
        free(tmp_location);
        return (0);
    }

    /* Command and location must be there */
    if (!tmp_ar->command || !tmp_location) {
        if (output == NULL){
            mdebug1("Command or location missing");
        }
        fclose(fp);
        free(tmp_ar);
        free(tmp_location);

        if (rpt == 1) {
            return (0);
        }
        if (output == NULL) {
            merror(AR_MISS);
        } else {
            wm_strcat(output, "Missing options in the active response " "configuration.", '\n');
        }
        return (-1);
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
            if (output == NULL) {
                mdebug1("'defined-agent' agent_id not defined");
                merror(AR_DEF_AGENT);
            } else {
                wm_strcat(output, "No agent defined for response.", '\n');
            }
            fclose(fp);
            free(tmp_ar);
            free(tmp_location);
            return (-1);
        }

        tmp_ar->location |= SPECIFIC_AGENT;

    }
    if (OS_Regex("all|any", tmp_location)) {
        tmp_ar->location |= ALL_AGENTS;
    }

    /* If we didn't set any value for the location */
    if (tmp_ar->location == 0) {
        if (output == NULL) {
            mdebug1("No location defined");
            merror(AR_INV_LOC, tmp_location);
        } else {
            snprintf(message, OS_FLSIZE,
                "Invalid active response location: '%s'.",
                tmp_location);
            wm_strcat(output, message, '\n');
        }
        fclose(fp);
        free(tmp_ar);
        free(tmp_location);
        return (-1);
    }

    /* Clean tmp_location */
    free(tmp_location);
    tmp_location = NULL;

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
            if (output == NULL) {
                mdebug1("Invalid command");
                merror(AR_INV_CMD, tmp_ar->command);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid command '%s' in the active response.",
                    tmp_ar->command);
                wm_strcat(output, message, '\n');
            }
            fclose(fp);
            free(tmp_ar);
            return (-1);
        }
    }

    /* Check if timeout is allowed */
    if (tmp_ar->timeout && !tmp_ar->ar_cmd->timeout_allowed) {
        if (output == NULL) {
            mdebug1("Timeout is not allowed");
            minfo(AR_NO_TIMEOUT, tmp_ar->ar_cmd->name);
        } else {
            snprintf(message, OS_FLSIZE,
                "INFO: Timeout not allowed for command: '%s'.",
                tmp_ar->ar_cmd->name);
            wm_strcat(output, message, '\n');
        }
        tmp_ar->timeout = 0;
    }

    /* d1 is the active response list */
    if (!OSList_AddData(l2, (void *)tmp_ar)) {
        if (output == NULL){
            merror(LIST_ADD_ERROR);
        } else {
            wm_strcat(output, "Error adding nodes to list.", '\n');
        }
        fclose(fp);
        free(tmp_ar);
        return (-1);
    }

    /* Set a unique active response name */
    tmp_ar->name = (char *) calloc(OS_FLSIZE + 1, sizeof(char));
    if (!tmp_ar->name) {
        if (output == NULL) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        } else {
            snprintf(message, OS_FLSIZE,
                "Could not acquire memory due to [(%d)-(%s)].",
                errno, strerror(errno));
            wm_strcat(output, message, '\n');
            return OS_INVALID;
        }
    }
    snprintf(tmp_ar->name, OS_FLSIZE, "%s%d",
             tmp_ar->ar_cmd->name,
             tmp_ar->timeout);

    /* Add to shared file */
    if (output == NULL){
        mdebug1("Writing command '%s' to '%s'", tmp_ar->command, DEFAULTARPATH);
    }
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

    /* Close shared file for active response */
    fclose(fp);

    /* Done over here */
    return (0);

error_invalid:
    /* In case of an error clean up first*/
    fclose(fp);
    free(tmp_ar);
    free(tmp_location);

    return (OS_INVALID);
}

int ReadActiveCommands(XML_NODE node, void *d1, __attribute__((unused)) void *d2, char **output)
{
    OSList *l1 = (OSList *) d1;
    int i = 0;
    char *tmp_str = NULL;
    char message[OS_FLSIZE];

    /* Xml values */
    const char *command_name = "name";
    const char *command_expect = "expect";
    const char *command_executable = "executable";
    const char *timeout_allowed = "timeout_allowed";
    const char *extra_args = "extra_args";

    ar_command *tmp_command;

    /* Allocate the active-response command */
    tmp_command = (ar_command *) calloc(1, sizeof(ar_command));
    if (!tmp_command) {
        if (output == NULL) {
            merror(MEM_ERROR, errno, strerror(errno));
        } else {
            snprintf(message, OS_FLSIZE,
                "Could not acquire memory due to [(%d)-(%s)].",
                errno, strerror(errno));
            wm_strcat(output, message, '\n');
        }
        return (-1);
    }

    tmp_command->name = NULL;
    tmp_command->expect = 0;
    tmp_command->executable = NULL;
    tmp_command->timeout_allowed = 0;
    tmp_command->extra_args = NULL;

    /* Search for the commands */
    while (node[i]) {
        if (!node[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            free(tmp_str);
            free(tmp_command);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            free(tmp_str);
            free(tmp_command);
            return (OS_INVALID);
        }
        if (strcmp(node[i]->element, command_name) == 0) {
            // The command name must not start with '!'

            if (node[i]->content[0] == '!') {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                free(tmp_str);
                free(tmp_command);
                return (OS_INVALID);
            }
            tmp_command->name = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, command_expect) == 0) {
            free(tmp_str);
            tmp_str = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, command_executable) == 0) {
            tmp_command->executable = strdup(node[i]->content);
        } else if (strcmp(node[i]->element, timeout_allowed) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                tmp_command->timeout_allowed = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                tmp_command->timeout_allowed = 0;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                free(tmp_str);
                free(tmp_command);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                free(tmp_str);
                free(tmp_command);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, extra_args) == 0) {
            tmp_command->extra_args = strdup(node[i]->content);
        } else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            free(tmp_str);
            free(tmp_command);
            return (OS_INVALID);
        } else {
            snprintf(message, OS_FLSIZE,
                "Invalid element in the configuration: '%s'.",
                node[i]->element);
            wm_strcat(output, message, '\n');
            free(tmp_str);
            free(tmp_command);
            return (OS_INVALID);
        }
        i++;
    }

    if (!tmp_command->name || !tmp_command->executable) {
        if (output == NULL) {
            merror(AR_CMD_MISS);
        } else {
            wm_strcat(output, "Missing command options. " "You must specify a 'name' and 'executable'.", '\n');
        }
        free(tmp_str);
        free(tmp_command);
        return (-1);
    }

    /* Get the expect */
    if (tmp_str && strlen(tmp_str) >= 4) {
        if (OS_Regex("user", tmp_str)) {
            tmp_command->expect |= USERNAME;
        }
        if (OS_Regex("srcip", tmp_str)) {
            tmp_command->expect |= SRCIP;
        }
        if (OS_Regex("filename", tmp_str)) {
            tmp_command->expect |= FILENAME;
        }
    }

    free(tmp_str);
    tmp_str = NULL;

    /* Add command to the list */
    if (!OSList_AddData(l1, (void *)tmp_command)) {
        if (output == NULL) {
            merror(LIST_ADD_ERROR);
        } else {
            wm_strcat(output, "Error adding nodes to list.", '\n');
        }
        free(tmp_command);
        return (-1);
    }

    return (0);
}

int Test_ActiveResponse(const char *path, int type, char **output) {
    int fail = 0;
    OSList *test_activecmd;
    OSList *test_activeresp;

    test_activecmd = OSList_Create();
    test_activeresp = OSList_Create();

    if (!test_activecmd || !test_activeresp) {
        if (output == NULL) {
            merror(LIST_ERROR);
        } else {
            wm_strcat(output, "Active-Response: Unable to create a new list", '\n');
        }      
        return OS_INVALID;
    }

    /* type indicates local or remote config */
    if (ReadConfig(CAR | type, path, test_activecmd, test_activeresp, output) < 0) {
        if (output == NULL) {
            merror(CONF_READ_ERROR, "Active-Response");
        } else {
            wm_strcat(output, "Invalid configuration in Active-Response", '\n');
        }
        fail = 1;
    }

    /* Frees the LogReader config struct */
    Free_OSList(test_activecmd);
    Free_OSList(test_activeresp);

    os_free (test_activecmd);
    os_free (test_activeresp);

    if (fail) {
        return OS_INVALID;
    }

    return 0;
}

int Test_Agent_Active_Response(const char *path, char **output) {
    const char *(xmlf[]) = {"ossec_config", "active-response", "disabled", NULL};
    const char *(castore[]) = {"ossec_config", "active-response", "ca_store", NULL};
    const char *(caverify[]) = {"ossec_config", "active-response", "ca_verification", NULL};

    /* Read XML file */

    OS_XML xml;
    if (OS_ReadXML(path, &xml) < 0) {
        if (output == NULL) {
            merror(XML_ERROR, path, xml.err, xml.err_line);
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Active-Response", '\n');
        }
        return OS_INVALID;
    }

    char *disable_entry = OS_GetOneContentforElement(&xml, xmlf);
    if (disable_entry) {
        if ( strcmp(disable_entry, "yes") && strcmp(disable_entry, "no") ) {
            if (output == NULL){
                merror(XML_VALUEERR, "disabled", disable_entry);
            } else {
                wm_strcat(output, "ERROR: Invalid configuration in Active-Response", '\n');
            }
            os_free(disable_entry);
            OS_ClearXML(&xml);
            return OS_INVALID;
        }

        os_free(disable_entry);
    }

    XML_NODE node = OS_GetElementsbyNode(&xml, NULL);
    XML_NODE child = NULL;
    char *repeated = NULL;
    int i;

    for (i = 0; node && node[i]; i++) {

        child = OS_GetElementsbyNode(&xml, node[i]);
        int j;

        for (j = 0; child && child[j]; j++) {

            if (strcmp(child[j]->element, "active-response") == 0) {
                XML_NODE child_attr = NULL;
                child_attr = OS_GetElementsbyNode(&xml, child[j]);
                int p;

                for (p = 0; child_attr && child_attr[p]; p++) {
                    if (!strcmp(child_attr[p]->element, "repeated_offenders")) {
                        os_strdup(child_attr[p]->content, repeated);
                        OS_ClearNode(child_attr);
                        goto next;
                    }
                }
                OS_ClearNode(child_attr);
            }
        }
        OS_ClearNode(child);
        child = NULL;
    }

next:
    OS_ClearNode(child);
    OS_ClearNode(node);

    if (repeated) {
        char **repeated_comp = OS_StrBreak(',', repeated, 5);

        if (!repeated_comp) {
            if (output == NULL) {
                merror(XML_VALUEERR, "repeated_offenders", repeated);
            } else {
                wm_strcat(output, "ERROR: Invalid configuration in Active-Response", '\n');
            }
            os_free(repeated);
            OS_ClearXML(&xml);
            return OS_INVALID;
        }
    }
    os_free(repeated);

    int enable_ca_verification = 0;
    char **ca_verification = OS_GetContents(&xml, caverify);
    if (ca_verification) {
        for (i = 0; ca_verification[i]; ++i) {
            if (strcasecmp(ca_verification[i], "yes") == 0) {
                enable_ca_verification = 1;
            } else if (strcasecmp(ca_verification[i], "no") == 0) {
                enable_ca_verification = 0;
            } else {
                if (output == NULL){
                    mwarn("Invalid content for tag <%s>: '%s'", caverify[2], ca_verification[i]);
                } else {
                    wm_strcat(output, "WARNING: Invalid content for a tag in Active-response", '\n');
                }
            }
        }

        free_strarray(ca_verification);
    }

    if (enable_ca_verification) {
        char **wcom_ca_store = OS_GetContents(&xml, castore);
        if (!wcom_ca_store) {
            if (output == NULL){
                minfo("No option <ca_store> defined. Wazuh default CA (%s) will be used.", DEF_CA_STORE);
            } else {
                wm_strcat(output, "INFO: No option <ca_store> defined. Wazuh default CA (%s) will be used.", '\n');
            }
        }
    }
    else {
        if (output == NULL){
            minfo("WPK verification with CA is disabled.");
        } else {
            wm_strcat(output, "INFO: WPK verification with CA is disabled.", '\n');
        }
    }

    OS_ClearXML(&xml);
    return 0;
}