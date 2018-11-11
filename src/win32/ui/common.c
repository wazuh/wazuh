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

/* Duplicate string */
void dupStr(char *src, char **dst)
{
	if (!src || !*src) return;
	
	if (*dst != NULL)
	{
		free(*dst);
		*dst = NULL;
	}
	
	os_strdup(src, *dst);
}

/* Generate server info (for the main status) */
int gen_server_info(HWND hwnd)
{
    memset(ui_server_info, '\0', 2048 + 1);
    snprintf(ui_server_info, 2048, "Agent: %s (%s) - %s\r\n\r\nStatus: %s", config_inst.agentname, config_inst.agentid, config_inst.agentip, config_inst.status);
    
    /* Initialize top */
    if (config_inst.version) {
        SetDlgItemText(hwnd, UI_SERVER_TOP, config_inst.version);
        SetDlgItemText(hwnd, UI_SERVER_INFO, ui_server_info);
    }
    
    /* Initialize auth key */
    if (config_inst.key) SetDlgItemText(hwnd, UI_SERVER_AUTH, config_inst.key);
    
    /* Initialize server IP */
    if (config_inst.server) SetDlgItemText(hwnd, UI_SERVER_TEXT, config_inst.server);
    
    /* Set status data */
    SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)"https://wazuh.com");
    if (config_inst.revision) SendMessage(hStatus, SB_SETTEXT, 1, (LPARAM)config_inst.revision);
    
    return (0);
}

/* Read the first line of a specific file  --must free after */
char *cat_file(char *file)
{
    FILE *fp = fopen(file, "r");
    if (fp) {
        char buf[1024 + 1] = {'\0'};
        char *ret = NULL;
		
        if (fgets(buf, 1024, fp) != NULL) {
            ret = strchr(buf, '\n');
            if (ret) *ret = '\0';
			
            ret = strchr(buf, '\r');
            if (ret) *ret = '\0';
			
            ret = strdup(buf);
        }
        
        fclose(fp);
		
        return (ret);
    }
    
    return (NULL);
}

/* Check if a file exists */
int is_file(char *file)
{
    FILE *fp = fopen(file, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Clear configuration */
void config_clear()
{
	/* Initialize config instance */
	if (config_inst.dir != NULL) {
		free(config_inst.dir);
		config_inst.dir = NULL;
	}
	
	if (config_inst.config != NULL) {
		free(config_inst.config);
		config_inst.config = NULL;
	}
	
	if (config_inst.agentid != NULL) {
		free(config_inst.agentid);
		config_inst.agentid = NULL;
	}
	
	if (config_inst.agentname != NULL) {
		free(config_inst.agentname);
		config_inst.agentname = NULL;
	}
	
	if (config_inst.agentip != NULL) {
		free(config_inst.agentip);
		config_inst.agentip = NULL;
	}
	
	if (config_inst.version != NULL) {
		free(config_inst.version);
		config_inst.version = NULL;
	}
	
    if (config_inst.revision != NULL) {
		free(config_inst.revision);
		config_inst.revision = NULL;
	}
	
	/* Set default values -- dupStr() takes care of freeing these variables */
	dupStr(FL_NOKEY, &config_inst.key);
	dupStr(FL_NOSERVER, &config_inst.server);
	dupStr(ST_UNKNOWN, &config_inst.status);
	
	config_inst.msg_sent = 0;
}

/* Initialize the config */
void init_config()
{
	/* Initialize config instance */
	config_inst.dir = NULL;
	config_inst.config = NULL;
	dupStr(FL_NOKEY, &config_inst.key);
	config_inst.server = NULL;
	
	config_inst.agentid = NULL;
	config_inst.agentname = NULL;
	config_inst.agentip = NULL;

	config_inst.version = NULL;
	config_inst.revision = NULL;
	dupStr(ST_UNKNOWN, &config_inst.status);
	
	config_inst.msg_sent = 0;
	config_inst.admin_access = 1;
	
	/* Check if ui is on the right path and has the proper permissions */
	if (!is_file(CONFIG)) {
		if (chdir(DEFDIR)) config_inst.admin_access = 0;
		if (!is_file(CONFIG)) config_inst.admin_access = 0;
	}
}

/* Read ossec config */
int config_read(__attribute__((unused)) HWND hwnd)
{
    char *tmp_str = NULL;
    char buffer[4096] = {'\0'};
	
	/* Clear config */
    config_clear();
	
	/* Get OSSEC status */
    if (CheckServiceRunning()) {
        dupStr(ST_RUNNING, &config_inst.status);
    } else {
        dupStr(ST_STOPPED, &config_inst.status);
    }
	
	/* Get version/revision */
    if (tmp_str = cat_file(VERSION_FILE), tmp_str) {
        snprintf(buffer, sizeof(buffer), "Wazuh %s", tmp_str);
        dupStr(buffer, &config_inst.version);
        
        free(tmp_str);
        tmp_str = NULL;
    }
	
	if (tmp_str = cat_file(REVISION_FILE), tmp_str) {
        snprintf(buffer, sizeof(buffer), "Revision %s", tmp_str);
        dupStr(buffer, &config_inst.revision);
        
        free(tmp_str);
        tmp_str = NULL;
    }
	
	/* Get number of messages sent */
    if (tmp_str = cat_file(SENDER_FILE), tmp_str) {
        unsigned long int tmp_val = 0;
        char *ptr = NULL;
        
        tmp_val = atol(tmp_str);
        if (tmp_val) {
            config_inst.msg_sent = (tmp_val * 9999);
			
            ptr = strchr(tmp_str, ':');
            if (ptr) {
                ptr++;
                snprintf(buffer, sizeof(buffer), "%s", ptr);
                
                tmp_val = atol(ptr);
                config_inst.msg_sent += tmp_val;
            }
        }
		
        free(tmp_str);
        tmp_str = NULL;
    }
	
	/* Get agent ID, name and IP */
    if (tmp_str = cat_file(AUTH_FILE), tmp_str) {
        /* Get base 64 */
        char *b64_key = encode_base64(strlen(tmp_str), tmp_str);
        if (b64_key == NULL)
        {
            dupStr(FL_NOKEY, &config_inst.key);
        } else {
            dupStr(b64_key, &config_inst.key);
            free(b64_key);
        }
        
        int pos = 0;
        char *ptr = strchr(tmp_str, ' ');
        if (ptr) {
            *ptr = '\0';
            ptr++;
            
            /* Get ID */
            dupStr(tmp_str + pos, &config_inst.agentid);
            
            /* Save position */
            pos = (ptr - tmp_str);
            
            ptr = strchr(ptr, ' ');
            if (ptr) {
                *ptr = '\0';
                ptr++;
                
                /* Get name */
                dupStr(tmp_str + pos, &config_inst.agentname);
                
                /* Save position */
                pos = (ptr - tmp_str);
                
                ptr = strchr(ptr, ' ');
                if (ptr) *ptr = '\0';
                
                /* Get IP address */
                dupStr(tmp_str + pos, &config_inst.agentip);
            }
        }
        
        free(tmp_str);
        tmp_str = NULL;
    }
	
	if (config_inst.agentip == NULL) {
        dupStr(ST_NOTSET, &config_inst.agentid);
		dupStr("Auth key not imported.", &config_inst.agentname);
		dupStr(ST_NOTSET, &config_inst.agentip);
		dupStr(ST_MISSING_IMPORT, &config_inst.status);
    }
	
	/* Get server IP */
    if (!get_ossec_server()) {
        if (strcmp(config_inst.status, ST_MISSING_IMPORT) == 0) {
            dupStr(ST_MISSING_ALL, &config_inst.status);
        } else {
            dupStr(ST_MISSING_SERVER, &config_inst.status);
        }
    }
	
	return (0);
}

/* Get OSSEC Server IP */
int get_ossec_server()
{
    OS_XML xml;
    char *str = NULL;
    int success = 0;
    
    /* Definitions */
    const char *(xml_serverip[]) = {"ossec_config", "client", "server-ip", NULL};
    const char *(xml_serverhost[]) = {"ossec_config", "client", "server-hostname", NULL};
    const char *(xml_serveraddr[]) = {"ossec_config", "client", "server", "address", NULL};
    
    /* Read XML */
    if (OS_ReadXML(CONFIG, &xml) < 0) return (0);
    
    /* We need to remove the entry for the server */
    if (config_inst.server) {
        free(config_inst.server);
        config_inst.server = NULL;
    }
    config_inst.server_type = 0;
    
    /* Get IP address of manager */
    if (str = OS_GetOneContentforElement(&xml, xml_serveraddr), str) {
        if (OS_IsValidIP(str, NULL) == 1) {
            config_inst.server_type = SERVER_IP_USED;
            dupStr(str, &config_inst.server);
            success = 1;
            goto ret;
        } else {
            /* If we don't find the IP, try the server hostname */
            char *s_ip = OS_GetHost(str, 0);
            if (s_ip) {
                /* Clear the host memory */
                free(s_ip);
                
                /* Assign the hostname to the server info */
                config_inst.server_type = SERVER_HOST_USED;
                dupStr(str, &config_inst.server);
                success = 1;
                goto ret;
            }
        }
        
        free(str);
        str = NULL;
    }
    
    if (str = OS_GetOneContentforElement(&xml, xml_serverip), str) {
        if (OS_IsValidIP(str, NULL) == 1) {
            config_inst.server_type = SERVER_IP_USED;
            dupStr(str, &config_inst.server);
            success = 1;
            goto ret;
        }
        
        free(str);
        str = NULL;
    }
    
    if (str = OS_GetOneContentforElement(&xml, xml_serverhost), str) {
        char *s_ip = OS_GetHost(str, 0);
        if (s_ip) {
            free(s_ip);
            config_inst.server_type = SERVER_HOST_USED;
            dupStr(str, &config_inst.server);
            success = 1;
            goto ret;
        }
    }
    
    /* Set up final server name when not available */
    dupStr(FL_NOSERVER, &config_inst.server);
    
ret:
    OS_ClearXML(&xml);
    if (str) free(str);
    return success;
}

/* Set OSSEC Server IP */
int set_ossec_server(char *ip, HWND hwnd)
{
    const char **xml_pt = NULL;
    const char *(xml_serveraddr[]) = {"ossec_config", "client", "server", "address", NULL};
    char *conf_file = basename_ex(CONFIG);
	
	char tmp_path[strlen(TMP_DIR) + 1 + strlen(conf_file) + 6 + 1];
    snprintf(tmp_path, sizeof(tmp_path), "%s/%sXXXXXX", TMP_DIR, conf_file);
	
	/* Verify IP Address */
    if (OS_IsValidIP(ip, NULL) != 1) {
        char *s_ip = OS_GetHost(ip, 0);
        if (!s_ip) {
            MessageBox(hwnd, "Invalid Server IP Address.\r\nIt must be the valid IPv4 address of the OSSEC server or the resolvable hostname.", "Error -- Failure Setting IP", MB_OK);
            return (0);
        }
        free(s_ip);
        config_inst.server_type = SERVER_HOST_USED;
        xml_pt = xml_serveraddr;
    } else {
        config_inst.server_type = SERVER_IP_USED;
        xml_pt = xml_serveraddr;
    }
	
	/* Create temporary file */
    if (mkstemp_ex(tmp_path) == -1) {
        MessageBox(hwnd, "Could not create temporary file.", "Error -- Failure Setting IP", MB_OK);
        return (0);
    }
	
	/* Read the XML. Print error and line number. */
    if (OS_WriteXML(CONFIG, tmp_path, xml_pt, NULL, ip) != 0) {
        MessageBox(hwnd, "Unable to set OSSEC Server IP Address.\r\n(Internal error on the XML Write).", "Error -- Failure Setting IP", MB_OK);
        
        if (unlink(tmp_path)) MessageBox(hwnd, "Could not delete temporary file.", "Error -- Failure Deleting Temporary File", MB_OK);
        
        return (0);
    }
	
    /* Rename config files */
    if (rename_ex(CONFIG, LASTCONFIG)) {
        MessageBox(hwnd, "Unable to backup configuration.", "Error -- Failure Backing Up Configuration", MB_OK);
        
        if (unlink(tmp_path)) MessageBox(hwnd, "Could not delete temporary file.", "Error -- Failure Deleting Temporary File", MB_OK);
        
        return (0);
    }
	
	if (rename_ex(tmp_path, CONFIG)) {
        MessageBox(hwnd, "Unable rename temporary file.", "Error -- Failure Renaming Temporary File", MB_OK);
        
        if (unlink(tmp_path)) MessageBox(hwnd, "Could not delete temporary file.", "Error -- Failure Deleting Temporary File", MB_OK);
        
        return (0);
    }
	
	return (1);
}

/* Set OSSEC Authentication Key */
int set_ossec_key(char *key, HWND hwnd)
{
    char auth_file_tmp[] = AUTH_FILE;
    char *keys_file = basename_ex(auth_file_tmp);
	
    char tmp_path[strlen(TMP_DIR) + 1 + strlen(keys_file) + 6 + 1];
    snprintf(tmp_path, sizeof(tmp_path), "%s/%sXXXXXX", TMP_DIR, keys_file);
	
	/* Create temporary file */
    if (mkstemp_ex(tmp_path) == -1) {
        MessageBox(hwnd, "Could not create temporary file.", "Error -- Failure Setting IP", MB_OK);
        return (0);
    }
	
	FILE *fp = fopen(tmp_path, "w");
    if (fp) {
        fprintf(fp, "%s", key);
        fclose(fp);
    } else {
        MessageBox(hwnd, "Could not open temporary file for write.", "Error -- Failure Importing Key", MB_OK);
        
        if (unlink(tmp_path)) MessageBox(hwnd, "Could not delete temporary file.", "Error -- Failure Deleting Temporary File", MB_OK);
        
        return (0);
    }
	
	if (rename_ex(tmp_path, AUTH_FILE)) {
        MessageBox(hwnd, "Unable to rename temporary file.", "Error -- Failure Renaming Temporary File", MB_OK);
        
        if (unlink(tmp_path)) MessageBox(hwnd, "Could not delete temporary file.", "Error -- Failure Deleting Temporary File", MB_OK);
        
        return (0);
    }
	
    return (1);
}
