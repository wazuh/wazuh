/* @(#) $Id$ */

/* Copyright (C) 2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
 
#ifdef WIN32 
#include "shared.h"
#include "rootcheck.h"


/** Registry checking values **/

/* Global variables */
HKEY rk_sub_tree;
 
/* Default values */
#define MAX_KEY_LENGTH 255
#define MAX_KEY	2048
#define MAX_VALUE_NAME 16383



/* os_check_ads.
 * Check if file has NTFS ADS.
 */
int os_check_ads(char *full_path)
{
    HANDLE file_h; 
    WIN32_STREAM_ID sid;
    void *context = NULL;

    char stream_name[MAX_PATH +1]; 
    char final_name[MAX_PATH +1]; 

    DWORD dwRead, shs, dw1, dw2;


    /* Opening file */
    file_h = CreateFile(full_path, 
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS,
            NULL);

    if (file_h == INVALID_HANDLE_VALUE) 
    { 
        return 0;
    }


    /* Zeroing memory */
    ZeroMemory(&sid, sizeof(WIN32_STREAM_ID));

    /* Getting stream header size -- should be 20 bytes */
    shs = (LPBYTE)&sid.cStreamName - (LPBYTE)&sid+ sid.dwStreamNameSize;


    while(1)
    {
        if(BackupRead(file_h, (LPBYTE) &sid, shs, &dwRead, 
                    FALSE, FALSE, &context) == 0)
        {
            break;
        }
        if(dwRead == 0)
        {
            break;
        }

        stream_name[0] = '\0';
        stream_name[MAX_PATH] = '\0';
        if(BackupRead(file_h, (LPBYTE)stream_name, 
                    sid.dwStreamNameSize, 
                    &dwRead, FALSE, FALSE, &context))
        {
            if(dwRead != 0)
            {
                char *tmp_pt;
                char op_msg[OS_SIZE_1024 +1];

                snprintf(final_name, MAX_PATH, "%s%S", full_path, 
                        (WCHAR *)stream_name);
                tmp_pt = strrchr(final_name, ':');
                if(tmp_pt)
                {
                    *tmp_pt = '\0';
                }

                snprintf(op_msg, OS_SIZE_1024, "NTFS Alternate data stream "
                                               "found: '%s'. Possible hidden"
                                               " content.",
                                               final_name);
                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
        }

        /* Getting next */			
        if(!BackupSeek(file_h, sid.Size.LowPart, sid.Size.HighPart, 
                    &dw1, &dw2, &context))
        {
            break;
        }
    }

    CloseHandle(file_h);
    return(0);
}


/** char *__os_winreg_getkey(char *reg_entry)
 * Gets registry high level key.
 */
char *__os_winreg_getkey(char *reg_entry)
{
    char *ret = NULL;
    char *tmp_str;

    /* Getting only the sub tree first */
    tmp_str = strchr(reg_entry, '\\');
    if(tmp_str)
    {
        *tmp_str = '\0';
        ret = tmp_str+1;
    }

    /* Setting sub tree */
    if((strcmp(reg_entry, "HKEY_LOCAL_MACHINE") == 0) ||
       (strcmp(reg_entry, "HKLM") == 0)) 
    {
        rk_sub_tree = HKEY_LOCAL_MACHINE;
    }
    else if(strcmp(reg_entry, "HKEY_CLASSES_ROOT") == 0)
    {
        rk_sub_tree = HKEY_CLASSES_ROOT;
    }
    else if(strcmp(reg_entry, "HKEY_CURRENT_CONFIG") == 0)
    {
        rk_sub_tree = HKEY_CURRENT_CONFIG;
    }
    else if(strcmp(reg_entry, "HKEY_USERS") == 0)
    {
        rk_sub_tree = HKEY_USERS;
    }
    else
    {
        /* Returning tmp_str to the previous value */
        if(tmp_str && (*tmp_str == '\0'))
            *tmp_str = '\\';
        return(NULL);
    }

    /* Checking if ret has nothing else. */
    if(ret && (*ret == '\0'))
        ret = NULL;

    /* fixing tmp_str and the real name of the registry */
    if(tmp_str && (*tmp_str == '\0'))
        *tmp_str = '\\';

    return(ret);
}


/* int __os_winreg_open_key(char *subkey)
 * Open the registry key
 */
int __os_winreg_open_key(char *subkey, char *full_key_name)
{
    HKEY oshkey;

    
    if(RegOpenKeyEx(rk_sub_tree, subkey, 0, KEY_READ,&oshkey) != ERROR_SUCCESS)
    {
        merror(SK_REG_OPEN, ARGV0, subkey);
        return(0);
    }

    RegCloseKey(oshkey);
    return(1);
}


/* is_registry: Check if the entry is present in the registry
 */
int is_registry(char *entry_name)
{

    char *rk;
    
    rk = __os_winreg_getkey(entry_name);
    if(rk_sub_tree == NULL)
    {
        merror(SK_INV_REG, ARGV0, entry_name);
        return(0);
    }

    if(__os_winreg_open_key(rk, entry_name) == 0)
    {
        return(0);
    }

    return(1);
}
  


#endif /* WIN32 */

/* EOF */
