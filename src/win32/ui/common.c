/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_win32ui.h"
#include "../os_win.h"
#include "os_xml/os_xml.h"
#include "os_net/os_net.h"
#include "validate_op.h"


/* Generate server info (for the main status) */
int gen_server_info(HWND hwnd)
{
    memset(ui_server_info, '\0', 2048 + 1);
    snprintf(ui_server_info, 2048,
             "Agent: %s (%s)  -  %s\r\n\r\n"
             "Status: %s",
             config_inst.agentname,
             config_inst.agentid,
             config_inst.agentip,
             config_inst.status);

    /* Initialize top */
    if (config_inst.version) {
        SetDlgItemText(hwnd, UI_SERVER_TOP, config_inst.version);
        SetDlgItemText(hwnd, UI_SERVER_INFO, ui_server_info);
    }

    /* Initialize auth key */
    SetDlgItemText(hwnd, UI_SERVER_AUTH, config_inst.key);

    /* Initialize server IP */
    SetDlgItemText(hwnd, UI_SERVER_TEXT, config_inst.server);

    /* Set status data */
    SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)"http://www.ossec.net");
    if (config_inst.install_date) {
        SendMessage(hStatus, SB_SETTEXT, 1, (LPARAM)config_inst.install_date);
    }

    return (0);
}

/* Read the first line of a specific file  --must free after */
char *cat_file(char *file, FILE *fp2)
{
    FILE *fp;

    if (!fp2) {
        fp = fopen(file, "r");
    } else {
        fp = fp2;
    }

    if (fp) {
        char buf[1024 + 1];
        char *ret = NULL;

        buf[1024] = '\0';
        if (fgets(buf, 1024, fp) != NULL) {
            ret = strchr(buf, '\n');
            if (ret) {
                *ret = '\0';
            }
            ret = strchr(buf, '\r');
            if (ret) {
                *ret = '\0';
            }

            ret = strdup(buf);
        }

        if (!fp2) {
            fclose(fp);
        }
        return (ret);
    }

    return (NULL);
}


/* Check if a file exists */
int is_file(char *file)
{
    FILE *fp;
    fp = fopen(file, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Clear configuration */
void config_clear()
{
    if (config_inst.version) {
        free(config_inst.version);
    }

    if (config_inst.key) {
        free(config_inst.key);
    }

    if (config_inst.agentid) {
        free(config_inst.agentid);
    }

    if (config_inst.server) {
        free(config_inst.server);
    }

    if (config_inst.install_date) {
        free(config_inst.install_date);
    }

    /* Initialize config instance */
    config_inst.dir = NULL;
    config_inst.key = FL_NOKEY;
    config_inst.server = strdup(FL_NOSERVER);
    config_inst.config = NULL;

    config_inst.agentid = NULL;
    config_inst.agentname = NULL;
    config_inst.agentip = NULL;

    config_inst.version = NULL;
    config_inst.install_date = NULL;
    config_inst.status = ST_UNKNOWN;
    config_inst.msg_sent = 0;
}

/* Initialize the config */
void init_config()
{
    /* Initialize config instance */
    config_inst.dir = NULL;
    config_inst.key = FL_NOKEY;
    config_inst.server = NULL;
    config_inst.config = NULL;

    config_inst.agentid = NULL;
    config_inst.agentname = NULL;
    config_inst.agentip = NULL;

    config_inst.version = NULL;
    config_inst.install_date = NULL;
    config_inst.status = ST_UNKNOWN;
    config_inst.msg_sent = 0;
    config_inst.admin_access = 1;

    /* Check if ui is on the right path and has the proper permissions */
    if (!is_file(CONFIG)) {
        if (chdir(DEFDIR)) {
            config_inst.admin_access = 0;
        }

        if (!is_file(CONFIG)) {
            config_inst.admin_access = 0;
        }
    }
}

/* Read ossec config */
int config_read(__attribute__((unused)) HWND hwnd)
{
    char *tmp_str;
    char *delim = " - ";

    /* Clear config */
    config_clear();

    /* Get OSSEC status */
    if (CheckServiceRunning()) {
        config_inst.status = ST_RUNNING;
    } else {
        config_inst.status = ST_STOPPED;
    }

    /* Get version/install date */
    config_inst.version = cat_file(VERSION_FILE, NULL);
    if (config_inst.version) {
        config_inst.install_date = strstr(config_inst.version, delim);
        if (config_inst.install_date) {
            *config_inst.install_date = '\0';
            config_inst.install_date += strlen(delim);
        }
    }

    /* Get number of messages sent */
    tmp_str = cat_file(SENDER_FILE, NULL);
    if (tmp_str) {
        unsigned long int tmp_val = 0;
        char *to_free = tmp_str;

        tmp_val = atol(tmp_str);
        if (tmp_val) {
            config_inst.msg_sent = tmp_val * 9999;

            tmp_str = strchr(tmp_str, ':');
            if (tmp_str) {
                tmp_str++;
                tmp_val = atol(tmp_str);
                config_inst.msg_sent += tmp_val;
            }
        }

        free(to_free);
    }

    /* Get agent ID, name and IP */
    tmp_str = cat_file(AUTH_FILE, NULL);
    if (tmp_str) {
        /* Get base 64 */
        config_inst.key = encode_base64(strlen(tmp_str), tmp_str);
        if (config_inst.key == NULL) {
            config_inst.key = FL_NOKEY;
        }

        /* Get ID */
        config_inst.agentid = tmp_str;

        tmp_str = strchr(tmp_str, ' ');
        if (tmp_str) {
            *tmp_str = '\0';
            tmp_str++;

            /* Get name */
            config_inst.agentname = tmp_str;
            tmp_str = strchr(tmp_str, ' ');
            if (tmp_str) {
                *tmp_str = '\0';
                tmp_str++;

                /* Get IP */
                config_inst.agentip = tmp_str;

                tmp_str = strchr(tmp_str, ' ');
                if (tmp_str) {
                    *tmp_str = '\0';
                }
            }
        }
    }

    if (config_inst.agentip == NULL) {
        config_inst.agentid = strdup(ST_NOTSET);
        config_inst.agentname = strdup("Auth key not imported.");
        config_inst.agentip = ST_NOTSET;

        config_inst.status = ST_MISSING_IMPORT;
    }

    /* Get server IP */
    if (!get_ossec_server()) {
        if (strcmp(config_inst.status, ST_MISSING_IMPORT) == 0) {
            config_inst.status = ST_MISSING_ALL;
        } else {
            config_inst.status = ST_MISSING_SERVER;
        }
    }

    return (0);
}

/* Get OSSEC Server IP */
int get_ossec_server()
{
    OS_XML xml;
    char *str = NULL;

    /* Definitions */
    const char *(xml_serverip[]) = {"ossec_config", "client", "server-ip", NULL};
    const char *(xml_serverhost[]) = {"ossec_config", "client", "server-hostname", NULL};

    /* Read XML */
    if (OS_ReadXML(CONFIG, &xml) < 0) {
        return (0);
    }

    /* We need to remove the entry for the server */
    if (config_inst.server) {
        free(config_inst.server);
        config_inst.server = NULL;
    }
    config_inst.server_type = 0;

    /* Get IP */
    str = OS_GetOneContentforElement(&xml, xml_serverip);
    if (str && (OS_IsValidIP(str, NULL) == 1)) {
        config_inst.server_type = SERVER_IP_USED;
        config_inst.server = str;

        OS_ClearXML(&xml);
        return (1);
    }
    /* If we don't find the IP, try the server hostname */
    else {
        if (str) {
            free(str);
            str = NULL;
        }

        str = OS_GetOneContentforElement(&xml, xml_serverhost);
        if (str) {
            char *s_ip;
            s_ip = OS_GetHost(str, 0);
            if (s_ip) {
                /* Clear the host memory */
                free(s_ip);

                /* Assign the hostname to the server info */
                config_inst.server_type = SERVER_HOST_USED;
                config_inst.server = str;
                OS_ClearXML(&xml);
                return (1);
            }
            free(str);
        }
    }

    /* Set up final server name when not available */
    config_inst.server = strdup(FL_NOSERVER);

    OS_ClearXML(&xml);
    return (0);
}

/* Run a cmd.exe command */
int run_cmd(char *cmd, HWND hwnd)
{
    int result;
    int cmdlen;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD exit_code;

    /* Build command */
    cmdlen = strlen(COMSPEC) + 5 + strlen(cmd);
    char finalcmd[cmdlen];
    snprintf(finalcmd, cmdlen, "%s /c %s", COMSPEC, cmd);

    /* Log command being run */
    log2file("%s: INFO: Running the following command (%s)", ARGV0, finalcmd);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, finalcmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                       &si, &pi)) {
        MessageBox(hwnd, "Unable to run command.",
                   "Error -- Failure Running Command", MB_OK);
        return (0);
    }

    /* Wait until process exits */
    WaitForSingleObject(pi.hProcess, INFINITE);

    /* Get exit code from command */
    result = GetExitCodeProcess(pi.hProcess, &exit_code);

    /* Close process and thread */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!result) {
        MessageBox(hwnd, "Could not determine exit code from command.",
                   "Error -- Failure Running Command", MB_OK);

        return (0);
    }

    return (exit_code);
}

/* Set OSSEC Server IP */
int set_ossec_server(char *ip, HWND hwnd)
{
    const char **xml_pt = NULL;
    const char *(xml_serverip[]) = {"ossec_config", "client", "server-ip", NULL};
    const char *(xml_serverhost[]) = {"ossec_config", "client", "server-hostname", NULL};

    char config_tmp[] = CONFIG;
    char *conf_file = basename_ex(config_tmp);

    char tmp_path[strlen(TMP_DIR) + 1 + strlen(conf_file) + 6 + 1];

    snprintf(tmp_path, sizeof(tmp_path), "%s/%sXXXXXX", TMP_DIR, conf_file);

    /* Verify IP Address */
    if (OS_IsValidIP(ip, NULL) != 1) {
        char *s_ip;
        s_ip = OS_GetHost(ip, 0);

        if (!s_ip) {
            MessageBox(hwnd, "Invalid Server IP Address.\r\n"
                       "It must be the valid IPv4 address of the "
                       "OSSEC server or the resolvable hostname.",
                       "Error -- Failure Setting IP", MB_OK);
            return (0);
        }
        config_inst.server_type = SERVER_HOST_USED;
        xml_pt = xml_serverhost;
    } else {
        config_inst.server_type = SERVER_IP_USED;
        xml_pt = xml_serverip;
    }

    /* Create temporary file */
    if (mkstemp_ex(tmp_path) == -1) {
        MessageBox(hwnd, "Could not create temporary file.",
                   "Error -- Failure Setting IP", MB_OK);
        return (0);
    }

    /* Read the XML. Print error and line number. */
    if (OS_WriteXML(CONFIG, tmp_path, xml_pt, NULL, ip) != 0) {
        MessageBox(hwnd, "Unable to set OSSEC Server IP Address.\r\n"
                   "(Internal error on the XML Write).",
                   "Error -- Failure Setting IP", MB_OK);

        if (unlink(tmp_path)) {
            MessageBox(hwnd, "Could not delete temporary file.",
                       "Error -- Failure Deleting Temporary File", MB_OK);
        }

        return (0);
    }

    /* Rename config files */
    if (rename_ex(CONFIG, LASTCONFIG)) {
        MessageBox(hwnd, "Unable to backup configuration.",
                   "Error -- Failure Backing Up Configuration", MB_OK);

        if (unlink(tmp_path)) {
            MessageBox(hwnd, "Could not delete temporary file.",
                       "Error -- Failure Deleting Temporary File", MB_OK);
        }

        return (0);
    }

    if (rename_ex(tmp_path, CONFIG)) {
        MessageBox(hwnd, "Unable rename temporary file.",
                   "Error -- Failure Renaming Temporary File", MB_OK);

        if (unlink(tmp_path)) {
            MessageBox(hwnd, "Could not delete temporary file.",
                       "Error -- Failure Deleting Temporary File", MB_OK);
        }

        return (0);
    }

    return (1);
}

/* Set OSSEC Authentication Key */
int set_ossec_key(char *key, HWND hwnd)
{
    FILE *fp;

    char auth_file_tmp[] = AUTH_FILE;
    char *keys_file = basename_ex(auth_file_tmp);

    char tmp_path[strlen(TMP_DIR) + 1 + strlen(keys_file) + 6 + 1];

    snprintf(tmp_path, sizeof(tmp_path), "%s/%sXXXXXX", TMP_DIR, keys_file);

    /* Create temporary file */
    if (mkstemp_ex(tmp_path) == -1) {
        MessageBox(hwnd, "Could not create temporary file.",
                   "Error -- Failure Setting IP", MB_OK);
        return (0);
    }

    fp = fopen(tmp_path, "w");
    if (fp) {
        fprintf(fp, "%s", key);
        fclose(fp);
    } else {
        MessageBox(hwnd, "Could not open temporary file for write.",
                   "Error -- Failure Importing Key", MB_OK);

        if (unlink(tmp_path)) {
            MessageBox(hwnd, "Could not delete temporary file.",
                       "Error -- Failure Deleting Temporary File", MB_OK);
        }

        return (0);
    }

    if (rename_ex(tmp_path, AUTH_FILE)) {
        MessageBox(hwnd, "Unable to rename temporary file.",
                   "Error -- Failure Renaming Temporary File", MB_OK);

        if (unlink(tmp_path)) {
            MessageBox(hwnd, "Could not delete temporary file.",
                       "Error -- Failure Deleting Temporary File", MB_OK);
        }

        return (0);
    }

    return (1);
}
