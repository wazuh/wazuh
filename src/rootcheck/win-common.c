/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"

#ifdef WIN32

/* Global variables */
HKEY rk_sub_tree;

/* Default values */
#define MAX_KEY_LENGTH   255
#define MAX_KEY         2048
#define MAX_VALUE_NAME 16383


/* Check if file has NTFS ADS */
int os_check_ads(const char *full_path)
{
    HANDLE file_h;
    WIN32_STREAM_ID sid;
    void *context = NULL;
    char stream_name[MAX_PATH + 1];
    char final_name[MAX_PATH + 1];
    DWORD dwRead, shs, dw1, dw2;

    /* Open file */
    file_h = wCreateFile(full_path,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS,
                        NULL);

    if (file_h == INVALID_HANDLE_VALUE) {
        return 0;
    }

    /* Zero memory */
    ZeroMemory(&sid, sizeof(WIN32_STREAM_ID));

    /* Get stream header size -- should be 20 bytes */
    shs = (LPBYTE)&sid.cStreamName - (LPBYTE)&sid + sid.dwStreamNameSize;

    while (1) {
        if (BackupRead(file_h, (LPBYTE) &sid, shs, &dwRead,
                       FALSE, FALSE, &context) == 0) {
            break;
        }
        if (dwRead == 0) {
            break;
        }

        stream_name[0] = '\0';
        stream_name[MAX_PATH] = '\0';
        if (BackupRead(file_h, (LPBYTE)stream_name,
                       sid.dwStreamNameSize,
                       &dwRead, FALSE, FALSE, &context)) {
            if (dwRead != 0) {
                DWORD i = 0;
                int max_path_size = 0;
                char *tmp_pt;
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(final_name, MAX_PATH, "%s", full_path);
                max_path_size = strlen(final_name);

                /* Copy from wide char to char */
                while ((i < dwRead) && (max_path_size < MAX_PATH)) {
                    if (stream_name[i] != 0) {
                        final_name[max_path_size] = stream_name[i];
                        max_path_size++;
                        final_name[max_path_size] = '\0';
                    }
                    i++;
                }

                tmp_pt = strrchr(final_name, ':');
                if (tmp_pt) {
                    *tmp_pt = '\0';
                }

                snprintf(op_msg, OS_SIZE_1024, "NTFS Alternate data stream "
                         "found: '%s'. Possible hidden"
                         " content.",
                         final_name);
                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
        }

        /* Get next */
        if (!BackupSeek(file_h, sid.Size.LowPart, sid.Size.HighPart,
                        &dw1, &dw2, &context)) {
            break;
        }
    }
    BackupRead(file_h, (LPBYTE)stream_name,
                       sid.dwStreamNameSize,
                       &dwRead, TRUE, FALSE, &context);
    CloseHandle(file_h);
    return (0);
}

/* Get registry high level key */
char *__os_winreg_getkey(char *reg_entry)
{
    char *ret = NULL;
    char *tmp_str;

    /* Get only the sub tree first */
    tmp_str = strchr(reg_entry, '\\');
    if (tmp_str) {
        *tmp_str = '\0';
        ret = tmp_str + 1;
    }

    /* Set sub tree */
    if ((strcmp(reg_entry, "HKEY_LOCAL_MACHINE") == 0) ||
            (strcmp(reg_entry, "HKLM") == 0)) {
        rk_sub_tree = HKEY_LOCAL_MACHINE;
    } else if (strcmp(reg_entry, "HKEY_CLASSES_ROOT") == 0) {
        rk_sub_tree = HKEY_CLASSES_ROOT;
    } else if (strcmp(reg_entry, "HKEY_CURRENT_CONFIG") == 0) {
        rk_sub_tree = HKEY_CURRENT_CONFIG;
    } else if (strcmp(reg_entry, "HKEY_USERS") == 0) {
        rk_sub_tree = HKEY_USERS;
    } else if ((strcmp(reg_entry, "HKCU") == 0) ||
               (strcmp(reg_entry, "HKEY_CURRENT_USER") == 0)) {
        rk_sub_tree = HKEY_CURRENT_USER;
    } else {
        /* Set sub tree to null */
        rk_sub_tree = NULL;

        /* Return tmp_str to the previous value */
        if (tmp_str && (*tmp_str == '\0')) {
            *tmp_str = '\\';
        }
        return (NULL);
    }

    /* Check if ret has nothing else */
    if (ret && (*ret == '\0')) {
        ret = NULL;
    }

    /* Fixing tmp_str and the real name of the registry */
    if (tmp_str && (*tmp_str == '\0')) {
        *tmp_str = '\\';
    }

    return (ret);
}

/* Query the key and get the value of a specific entry */
int __os_winreg_querykey(HKEY hKey,
        __attribute__((unused))char *p_key,
        __attribute__((unused)) char *full_key_name,
                         char *reg_option, char *reg_value)
{
    int rc;
    DWORD i, j;

    /* QueryInfo and EnumKey variables */
    TCHAR class_name_b[MAX_PATH + 1];
    DWORD class_name_s = MAX_PATH;

    /* Number of sub keys */
    DWORD subkey_count = 0;

    /* Number of values */
    DWORD value_count;

    /* Variables for RegEnumValue */
    TCHAR value_buffer[MAX_VALUE_NAME + 1];
    TCHAR data_buffer[MAX_VALUE_NAME + 1];
    DWORD value_size;
    DWORD data_size;

    /* Data type for RegEnumValue */
    DWORD data_type = 0;

    /* Storage var */
    char var_storage[MAX_VALUE_NAME + 1];

    /* Initialize the memory for some variables */
    class_name_b[0] = '\0';
    class_name_b[MAX_PATH] = '\0';

    /* We use the class_name, subkey_count and the value count */
    rc = RegQueryInfoKey(hKey, class_name_b, &class_name_s, NULL,
                         &subkey_count, NULL, NULL, &value_count,
                         NULL, NULL, NULL, NULL);
    if (rc != ERROR_SUCCESS) {
        return (0);
    }

    /* Get values (if available) */
    if (value_count) {
        char *mt_data;

        /* Clear the values for value_size and data_size */
        value_buffer[MAX_VALUE_NAME] = '\0';
        data_buffer[MAX_VALUE_NAME] = '\0';
        var_storage[MAX_VALUE_NAME] = '\0';

        /* Get each value */
        for (i = 0; i < value_count; i++) {
            value_size = MAX_VALUE_NAME;
            data_size = MAX_VALUE_NAME;

            value_buffer[0] = '\0';
            data_buffer[0] = '\0';
            var_storage[0] = '\0';

            rc = RegEnumValue(hKey, i, value_buffer, &value_size,
                              NULL, &data_type, (LPBYTE)data_buffer, &data_size);

            /* No more values available */
            if (rc != ERROR_SUCCESS) {
                break;
            }

            /* Check if no value name is specified */
            if (value_buffer[0] == '\0') {
                value_buffer[0] = '@';
                value_buffer[1] = '\0';
            }

            /* Check if the entry name matches the reg_option */
            if (strcasecmp(value_buffer, reg_option) != 0) {
                continue;
            }

            /* If a value is not present and the option matches,
             * we can return ok
             */
            if (!reg_value) {
                return (1);
            }

            /* Write value into a string */
            switch (data_type) {
                    int size_available;

                case REG_SZ:
                case REG_EXPAND_SZ:
                    snprintf(var_storage, sizeof(var_storage), "%s", data_buffer);
                    break;
                case REG_MULTI_SZ:
                    /* Printing multiple strings */
                    size_available = MAX_VALUE_NAME;
                    mt_data = data_buffer;

                    while (*mt_data) {
                        if (size_available >= (int)strlen(mt_data) + 1) {
                            strncat(var_storage, mt_data, size_available);
                            size_available -= strlen(mt_data);
                            strncat(var_storage, " ", 2);
                            size_available -= 1;
                        }
                        mt_data += strlen(mt_data) + 1;
                    }

                    break;
                case REG_DWORD:
                    snprintf(var_storage, MAX_VALUE_NAME,
                             "%x", (unsigned int)*data_buffer);
                    break;
                default:
                    size_available = MAX_VALUE_NAME - 2;
                    for (j = 0; j < data_size; j++) {
                        char tmp_c[12];

                        snprintf(tmp_c, 12, "%02x",
                                 (unsigned int)data_buffer[j]);

                        if (size_available > 2) {
                            strncat(var_storage, tmp_c, size_available);
                            size_available = MAX_VALUE_NAME -
                                             (strlen(var_storage) + 2);
                        }
                    }
                    break;
            }

            /* Check if value matches */
            if (pt_matches(var_storage, reg_value)) {
                return (1);
            }

            return (0);
        }
    }

    return (0);
}

/* Open the registry key */
int __os_winreg_open_key(char *subkey, char *full_key_name, unsigned long arch,
                         char *reg_option, char *reg_value)
{
    int ret = 1;
    HKEY oshkey;

    if (RegOpenKeyEx(rk_sub_tree, subkey, 0, KEY_READ | arch, &oshkey) != ERROR_SUCCESS) {
        return (0);
    }

    /* If option is set, return the value of query key */
    if (reg_option) {
        ret = __os_winreg_querykey(oshkey, subkey, full_key_name,
                                   reg_option, reg_value);
    }

    RegCloseKey(oshkey);
    return (ret);
}

/* Check if the entry is present in the registry */
int is_registry(char *entry_name, char *reg_option, char *reg_value)
{
    char *rk;

    rk = __os_winreg_getkey(entry_name);
    if (rk_sub_tree == NULL || rk == NULL) {
        mterror(ARGV0, SK_INV_REG, entry_name);
        return (0);
    }

    return __os_winreg_open_key(rk, entry_name, KEY_WOW64_32KEY, reg_option, reg_value) || __os_winreg_open_key(rk, entry_name, KEY_WOW64_64KEY, reg_option, reg_value);
}

#else

/* Non-Windows defs */
int os_check_ads(__attribute__((unused)) const char *full_path)
{
    return (0);
}
int is_registry(__attribute__((unused)) char *entry_name,
                __attribute__((unused)) char *reg_option,
                __attribute__((unused)) char *reg_value)
{
    return (0);
}

#endif /* !WIN32 */
