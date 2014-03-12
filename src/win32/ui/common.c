/* @(#) $Id: ./src/win32/ui/common.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "shared.h"
#include "os_win32ui.h"
#include "os_win.h"
#include "os_xml/os_xml.h"
#include "os_net/os_net.h"
#include "validate_op.h"


/* Generate server info (for the main status) */
int gen_server_info(HWND hwnd)
{
    memset(ui_server_info, '\0', 2048 +1);
    snprintf(ui_server_info, 2048,
            "Agent: %s (%s)  -  %s\r\n\r\n"
            "Status: %s",
            config_inst.agentname,
            config_inst.agentid,
            config_inst.agentip,
            config_inst.status);


    /* Initializing top */
    if(config_inst.version)
    {
        SetDlgItemText(hwnd, UI_SERVER_TOP, config_inst.version);
        SetDlgItemText(hwnd, UI_SERVER_INFO, ui_server_info);
    }

    /* Initializing auth key */
    SetDlgItemText(hwnd, UI_SERVER_AUTH, config_inst.key);

    /* Initializing server ip */
    SetDlgItemText(hwnd, UI_SERVER_TEXT, config_inst.server);

    /* Set status data */
    SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)"http://www.ossec.net");
    if (config_inst.install_date)
    {
        SendMessage(hStatus, SB_SETTEXT, 1, (LPARAM)config_inst.install_date);
    }

    return(0);
}


/* Reads the first line of a specific file  --must free after */
char *cat_file(char *file, FILE *fp2)
{
    FILE *fp;

    if(!fp2)
    {
        fp = fopen(file, "r");
    }
    else
    {
        fp = fp2;
    }

    if(fp)
    {
        char buf[1024 +1];
        char *ret = NULL;

        buf[1024] = '\0';
        if(fgets(buf, 1024, fp) != NULL)
        {
            ret = strchr(buf, '\n');
            if(ret)
            {
                *ret = '\0';
            }
            ret = strchr(buf, '\r');
            if(ret)
            {
                *ret = '\0';
            }

            ret = strdup(buf);
        }

        if(!fp2)
        {
            fclose(fp);
        }
        return(ret);
    }

    return(NULL);
}


/* Check if a file exists */
int is_file(char *file)
{
    FILE *fp;
    fp = fopen(file, "r");
    if(fp)
    {
        fclose(fp);
        return(1);
    }
    return(0);
}


/* Clear configuration */
void config_clear()
{
    if(config_inst.version)
    {
        free(config_inst.version);
    }

    if(config_inst.key)
    {
        free(config_inst.key);
    }

    if(config_inst.agentid)
    {
        free(config_inst.agentid);
    }

    if(config_inst.server)
    {
        free(config_inst.server);
    }

    if(config_inst.install_date)
    {
        free(config_inst.install_date);
    }

    /* Initializing config instance */
    config_inst.dir = NULL;
    config_inst.key = FL_NOKEY;
    config_inst.server = strdup(FL_NOSERVER);
    config_inst.config = NULL;

    config_inst.agentid = NULL;
    config_inst.agentname= NULL;
    config_inst.agentip = NULL;

    config_inst.version = NULL;
    config_inst.install_date = NULL;
    config_inst.status = ST_UNKNOWN;
    config_inst.msg_sent = 0;
}


/* Initializes the config */
void init_config()
{
    /* Initializing config instance */
    config_inst.dir = NULL;
    config_inst.key = FL_NOKEY;
    config_inst.server = NULL;
    config_inst.config = NULL;

    config_inst.agentid = NULL;
    config_inst.agentname= NULL;
    config_inst.agentip = NULL;

    config_inst.version = NULL;
    config_inst.install_date = NULL;
    config_inst.status = ST_UNKNOWN;
    config_inst.msg_sent = 0;
    config_inst.admin_access = 1;


    /* Checking if ui is on the right path
     * and has the proper permissions
     */
    if(!is_file(CONFIG))
    {
        if(chdir(DEFDIR))
        {
            config_inst.admin_access = 0;
        }

        if(!is_file(CONFIG))
        {
            config_inst.admin_access = 0;
        }
    }
}


/* Reads ossec config */
int config_read(HWND hwnd)
{
    char *tmp_str;
    char *delim = " - ";


    /* Clearing config */
    config_clear();


    /* Getting OSSEC status */
    if(CheckServiceRunning())
    {
        config_inst.status = ST_RUNNING;
    }
    else
    {
        config_inst.status = ST_STOPPED;
    }


    /* Getting version/install date */
    config_inst.version = cat_file(VERSION_FILE, NULL);
    if(config_inst.version)
    {
        config_inst.install_date = strstr(config_inst.version, delim);
        if(config_inst.install_date)
        {
            *config_inst.install_date = '\0';
            config_inst.install_date += strlen(delim);
        }
    }


    /* Getting number of messages sent */
    tmp_str = cat_file(SENDER_FILE, NULL);
    if(tmp_str)
    {
        unsigned long int tmp_val = 0;
        char *to_free = tmp_str;

        tmp_val = atol(tmp_str);
        if(tmp_val)
        {
            config_inst.msg_sent = tmp_val * 9999;

            tmp_str = strchr(tmp_str, ':');
            if(tmp_str)
            {
                tmp_str++;
                tmp_val = atol(tmp_str);
                config_inst.msg_sent += tmp_val;
            }
        }

        free(to_free);
    }


    /* Getting agent id, name and ip */
    tmp_str = cat_file(AUTH_FILE, NULL);
    if(tmp_str)
    {
        /* Getting base 64 */
        config_inst.key = encode_base64(strlen(tmp_str),tmp_str);
        if(config_inst.key == NULL)
        {
            config_inst.key = FL_NOKEY;
        }

        /* Getting id */
        config_inst.agentid = tmp_str;

        tmp_str = strchr(tmp_str, ' ');
        if(tmp_str)
        {
            *tmp_str = '\0';
            tmp_str++;

            /* Getting name */
            config_inst.agentname = tmp_str;
            tmp_str = strchr(tmp_str, ' ');
            if(tmp_str)
            {
                *tmp_str = '\0';
                tmp_str++;

                /* Getting ip */
                config_inst.agentip = tmp_str;

                tmp_str = strchr(tmp_str, ' ');
                if(tmp_str)
                {
                    *tmp_str = '\0';
                }
            }
        }
    }


    if(config_inst.agentip == NULL)
    {
        config_inst.agentid = strdup(ST_NOTSET);
        config_inst.agentname = strdup("Auth key not imported.");
        config_inst.agentip = ST_NOTSET;

        config_inst.status = ST_MISSING_IMPORT;
    }


    /* Getting server ip */
    if(!get_ossec_server())
    {
        if(strcmp(config_inst.status, ST_MISSING_IMPORT) == 0)
        {
            config_inst.status = ST_MISSING_ALL;
        }
        else
        {
            config_inst.status = ST_MISSING_SERVER;
        }
    }

    return(0);
}


/* Get OSSEC Server IP */
int get_ossec_server()
{
    OS_XML xml;

    char *str = NULL;


    /* Definitions */
    char *(xml_serverip[])={"ossec_config","client","server-ip", NULL};
    char *(xml_serverhost[])={"ossec_config","client","server-hostname", NULL};


    /* Reading XML */
    if(OS_ReadXML(CONFIG, &xml) < 0)
    {
        return(0);
    }


    /* We need to remove the entry for the server */
    if(config_inst.server)
    {
        free(config_inst.server);
        config_inst.server = NULL;
    }
    config_inst.server_type = 0;


    /* Getting ip */
    str = OS_GetOneContentforElement(&xml, xml_serverip);
    if(str && (OS_IsValidIP(str, NULL) == 1))
    {
        config_inst.server_type = SERVER_IP_USED;
        config_inst.server = str;

        OS_ClearXML(&xml);
        return(1);
    }
    /* If we dont find the ip, try the server-hostname */
    else
    {
        if(str)
        {
            free(str);
            str = NULL;
        }

        str = OS_GetOneContentforElement(&xml, xml_serverhost);
        if(str)
        {
            char *s_ip;
            s_ip = OS_GetHost(str, 0);
            if(s_ip)
            {
                /* Clearing the host memory */
                free(s_ip);

                /* Assigning the hostname to the server info */
                config_inst.server_type = SERVER_HOST_USED;
                config_inst.server = str;
                OS_ClearXML(&xml);
                return(1);
            }
            free(str);
        }
    }


    /* Setting up final server name when not available */
    config_inst.server = strdup(FL_NOSERVER);


    OS_ClearXML(&xml);
    return(0);
}


/* Run a cmd.exe command */
int run_cmd(char *cmd, HWND hwnd)
{
    int result;
    int cmdlen;
    char *comspec;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD exit_code;

    /* Get cmd location from environment */
    comspec = getenv("COMSPEC");
    if (comspec == NULL || strncmp(comspec, "", strlen(comspec) == 0))
    {
        MessageBox(hwnd, "Could not determine the location of "
                         "cmd.exe using the COMSPEC environment variable.",
                         "Error -- Failure Locating cmd.exe",MB_OK);
        return(0);
    }

    /* Build command */
    cmdlen = strlen(comspec) + 5 + strlen(cmd);
    char finalcmd[cmdlen];
    snprintf(finalcmd, cmdlen, "%s /c %s", comspec, cmd);

    /* Log command being run */
    log2file("%s: INFO: Running the following command (%s)", ARGV0, finalcmd);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if(!CreateProcess(NULL, finalcmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                      &si, &pi))
    {
        MessageBox(hwnd, "Unable to run command.",
                         "Error -- Failure Running Command",MB_OK);
        return(0);
    }

    /* Wait until process exits */
    WaitForSingleObject(pi.hProcess, INFINITE);

    /* Get exit code from command */
    result = GetExitCodeProcess(pi.hProcess, &exit_code);

    /* Close process and thread */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!result)
    {
        MessageBox(hwnd, "Could not determine exit code from command.",
                         "Error -- Failure Running Command",MB_OK);

        return(0);
    }

    return(exit_code);
}


/* Set OSSEC Server IP */
int set_ossec_server(char *ip, HWND hwnd)
{
    FILE *fp;
    char **xml_pt = NULL;
    char *(xml_serverip[])={"ossec_config","client","server-ip", NULL};
    char *(xml_serverhost[])={"ossec_config","client","server-hostname", NULL};
    char *cacls;
    int cmdlen;

    /* Build command line to change permissions */
    cacls = "echo y|cacls \"%s\" /T /G Administrators:f";
    cmdlen = strlen(cacls) + strlen(NEWCONFIG);
    char cmd[cmdlen];
    snprintf(cmd, cmdlen, cacls, NEWCONFIG);

    /* Verifying IP Address */
    if(OS_IsValidIP(ip, NULL) != 1)
    {
        char *s_ip;
        s_ip = OS_GetHost(ip, 0);

        if(!s_ip)
        {
            MessageBox(hwnd, "Invalid Server IP Address.\r\n"
                             "It must be the valid Ipv4 address of the "
                             "OSSEC server or its resolvable hostname.",
                             "Error -- Failure Setting IP",MB_OK);
            return(0);
        }
        config_inst.server_type = SERVER_HOST_USED;
        xml_pt = xml_serverhost;
    }
    else
    {
        config_inst.server_type = SERVER_IP_USED;
        xml_pt = xml_serverip;
    }

    /* Create file */
    fp = fopen(NEWCONFIG, "w");
    if(fp)
    {
        fclose(fp);
    }
    else
    {
        MessageBox(hwnd, "Could not create configuration file.",
                         "Error -- Failure Setting IP",MB_OK);
        return(0);
    }

    /* Change permissions */
    if (run_cmd(cmd, hwnd))
    {
        MessageBox(hwnd, "Unable to set permissions on new configuration file.",
                         "Error -- Failure Setting IP",MB_OK);

        /* Remove config */
        if(unlink(NEWCONFIG))
        {
            MessageBox(hwnd, "Unable to remove new configuration file.",
                             "Error -- Failure Setting IP",MB_OK);
        }

        return(0);
    }

    /* Reading the XML. Printing error and line number. */
    if(OS_WriteXML(CONFIG, NEWCONFIG, xml_pt,
                   NULL, ip) != 0)
    {
        MessageBox(hwnd, "Unable to set OSSEC Server IP Address.\r\n"
                         "(Internal error on the XML Write).",
                         "Error -- Failure Setting IP",MB_OK);
        return(0);
    }

    /* Renaming config files */
    unlink(LASTCONFIG);
    rename(CONFIG, LASTCONFIG);
    rename(NEWCONFIG, CONFIG);

    return(1);
}


/* Set OSSEC Authentication Key */
int set_ossec_key(char *key, HWND hwnd)
{
    FILE *fp;
    char *cacls;
    int cmdlen;

    /* Build command line to change permissions */
    cacls = "echo y|cacls \"%s\" /T /G Administrators:f";
    cmdlen = strlen(cacls) + strlen(AUTH_FILE);
    char cmd[cmdlen];
    snprintf(cmd, cmdlen, cacls, AUTH_FILE);

    /* Create file */
    fp = fopen(AUTH_FILE, "w");
    if(fp)
    {
        fclose(fp);
    }
    else
    {
        MessageBox(hwnd, "Could not open auth key file.",
                         "Error -- Failure Importing Key", MB_OK);
        return(0);
    }

    /* Change permissions */
    if (run_cmd(cmd, hwnd))
    {
        MessageBox(hwnd, "Unable to set permissions on auth key file.",
                         "Error -- Failure Importing Key", MB_OK);

        /* Remove config */
        if(unlink(AUTH_FILE))
        {
            MessageBox(hwnd, "Unable to remove auth key file.",
                             "Error -- Failure Importing Key", MB_OK);
        }

        return(0);
    }

    fp = fopen(AUTH_FILE, "w");
    if(fp)
    {
        fprintf(fp, "%s", key);
        fclose(fp);
    }
    else
    {
        MessageBox(hwnd, "Could not open auth key file for write.",
                         "Error -- Failure Importing Key", MB_OK);
        return(0);
    }

    return(1);
}


/* EOF */
