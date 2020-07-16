/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include <openssl/evp.h>

#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/windows/winreg_wrappers.h"
#endif

/* Default values */
#define MAX_KEY_LENGTH   260
#define MAX_KEY         2048
#define MAX_VALUE_NAME 16383

/* Global variables */
HKEY sub_tree;

// SQLite Development
/*
static const char *fim_entry_type[] = {
    "file",
    "registry"
};
*/

/* Prototypes */
void os_winreg_open_key(char *subkey, char *fullkey_name, int pos);

/* Check if the registry entry is valid */
char *os_winreg_sethkey(char *reg_entry)
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
    if (strcmp(reg_entry, "HKEY_LOCAL_MACHINE") == 0) {
        sub_tree = HKEY_LOCAL_MACHINE;
    } else if (strcmp(reg_entry, "HKEY_CLASSES_ROOT") == 0) {
        sub_tree = HKEY_CLASSES_ROOT;
    } else if (strcmp(reg_entry, "HKEY_CURRENT_CONFIG") == 0) {
        sub_tree = HKEY_CURRENT_CONFIG;
    } else if (strcmp(reg_entry, "HKEY_USERS") == 0) {
        sub_tree = HKEY_USERS;
    } else {
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

    /* Fix tmp_str and the real name of the registry */
    if (tmp_str && (*tmp_str == '\0')) {
        *tmp_str = '\\';
    }

    return (ret);
}

/* Query the key and get all its values */
void os_winreg_querykey(HKEY hKey, char *p_key, char *full_key_name, int pos)
{
    int rc;
    DWORD i, j;

    /* QueryInfo and EnumKey variables */
    TCHAR sub_key_name_b[MAX_KEY_LENGTH + 2];
    TCHAR class_name_b[MAX_PATH + 1];
    DWORD sub_key_name_s;
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

    /* Initializing the memory for some variables */
    class_name_b[0] = '\0';
    class_name_b[MAX_PATH] = '\0';
    sub_key_name_b[0] = '\0';
    sub_key_name_b[MAX_KEY_LENGTH] = '\0';
    sub_key_name_b[MAX_KEY_LENGTH + 1] = '\0';

    FILETIME file_time = { 0 };

    /* We use the class_name, subkey_count and the value count */
    rc = RegQueryInfoKey(hKey, class_name_b, &class_name_s, NULL,
                         &subkey_count, NULL, NULL, &value_count,
                         NULL, NULL, NULL, &file_time);

    /* Check return code of QueryInfo */
    if (rc != ERROR_SUCCESS) {
        return;
    }

    /* Check if we have sub keys */
    if (subkey_count) {
        /* Open each subkey and call open_key */
        for (i = 0; i < subkey_count; i++) {
            sub_key_name_s = MAX_KEY_LENGTH;
            rc = RegEnumKeyEx(hKey, i, sub_key_name_b, &sub_key_name_s,
                              NULL, NULL, NULL, NULL);

            /* Checking for the rc */
            if (rc == ERROR_SUCCESS) {
                char new_key[MAX_KEY + 2];
                char new_key_full[MAX_KEY + 2];
                new_key[MAX_KEY + 1] = '\0';
                new_key_full[MAX_KEY + 1] = '\0';

                if (p_key) {
                    snprintf(new_key, MAX_KEY,
                             "%s\\%s", p_key, sub_key_name_b);
                    snprintf(new_key_full, MAX_KEY,
                             "%s\\%s", full_key_name, sub_key_name_b);
                } else {
                    snprintf(new_key, MAX_KEY, "%s", sub_key_name_b);
                    snprintf(new_key_full, MAX_KEY,
                             "%s\\%s", full_key_name, sub_key_name_b);
                }

                /* Open subkey */
                os_winreg_open_key(new_key, new_key_full, pos);
            }
        }
    }

    /* Registry ignore list */
    if (full_key_name && syscheck.registry_ignore) {
        int ign_it = 0;
        while (syscheck.registry_ignore[ign_it].entry != NULL) {
            if (syscheck.registry_ignore[ign_it].arch == syscheck.registry[pos].arch && strcasecmp(syscheck.registry_ignore[ign_it].entry, full_key_name) == 0) {
                mdebug2(FIM_IGNORE_ENTRY, "registry", full_key_name, syscheck.registry_ignore[ign_it].entry);
                return;
            }
            ign_it++;
        }
    }

    if (full_key_name && syscheck.registry_ignore_regex) {
        int ign_it = 0;
        while (syscheck.registry_ignore_regex[ign_it].regex != NULL) {
            if (syscheck.registry_ignore_regex[ign_it].arch == syscheck.registry[pos].arch &&
                OSMatch_Execute(full_key_name, strlen(full_key_name),
                                syscheck.registry_ignore_regex[ign_it].regex)) {
                mdebug2(FIM_IGNORE_SREGEX, "registry", full_key_name, syscheck.registry_ignore_regex[ign_it].regex->raw);
                return;
            }
            ign_it++;
        }
    }

    /* Get values (if available) */
    if (value_count) {
        char *mt_data;
        char buffer[OS_SIZE_2048];
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        EVP_DigestInit(ctx, EVP_sha1());

        /* Clear the values for value_size and data_size */
        value_buffer[MAX_VALUE_NAME] = '\0';
        data_buffer[MAX_VALUE_NAME] = '\0';

        /* Get each value */
        buffer[0] = '\0';
        for (i = 0; i < value_count; i++) {
            value_size = MAX_VALUE_NAME;
            data_size = MAX_VALUE_NAME;

            value_buffer[0] = '\0';
            data_buffer[0] = '\0';

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

            /* Write value name and data in the file (for checksum later) */
            EVP_DigestUpdate(ctx, value_buffer, strlen(value_buffer));
            switch (data_type) {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    EVP_DigestUpdate(ctx, data_buffer, strlen(data_buffer));
                    break;
                case REG_MULTI_SZ:
                    /* Print multiple strings */
                    mt_data = data_buffer;

                    while (*mt_data) {
                        EVP_DigestUpdate(ctx, mt_data, strlen(mt_data));
                        mt_data += strlen(mt_data) + 1;
                    }
                    break;
                case REG_DWORD:
                    snprintf(buffer, OS_SIZE_2048, "%08x", *((unsigned int*)data_buffer));
                    EVP_DigestUpdate(ctx, buffer, strlen(buffer));
                    buffer[0] = '\0';
                    break;
                default:
                    for (j = 0; j < data_size; j++) {
                        snprintf(buffer, 3, "%02x", (unsigned int)data_buffer[j] & 0xFF);
                        EVP_DigestUpdate(ctx, buffer, strlen(buffer));
                        buffer[0] = '\0';
                    }
                    break;
            }
        }

        fim_entry_data *data;
        char path[MAX_PATH + 7];
        unsigned char digest[EVP_MAX_MD_SIZE];
        int result;
        unsigned int digest_size;

        os_calloc(1, sizeof(fim_entry_data), data);
        init_fim_data_entry(data);

        // Set registry entry type
        data->entry_type = FIM_TYPE_REGISTRY;
        data->mode = FIM_SCHEDULED;
        snprintf(path, MAX_PATH + 7, "%s%s", syscheck.registry[pos].arch == ARCH_64BIT ? "[x64] " : "[x32] ", full_key_name);
        data->last_event = time(NULL);
        data->options |= CHECK_SHA1SUM | CHECK_MTIME;
        data->mtime = get_windows_file_time_epoch(file_time);
        data->scanned = 1;

        EVP_DigestFinal_ex(ctx, digest, &digest_size);
        OS_SHA1_Hexdigest(digest, data->hash_sha1);
        EVP_MD_CTX_destroy(ctx);

        fim_get_checksum(data);

        if (result = fim_registry_event(path, data, pos), result == -1) {
            mdebug1(FIM_REGISTRY_EVENT_FAIL, path);
        }

        free_entry_data(data);
    }
}

/* Open the registry key */
void os_winreg_open_key(char *subkey, char *fullkey_name, int pos)
{
    HKEY oshkey;

    if (RegOpenKeyEx(sub_tree, subkey, 0, KEY_READ | (syscheck.registry[pos].arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &oshkey) != ERROR_SUCCESS) {
        mdebug1(FIM_REG_OPEN, subkey, syscheck.registry[pos].arch == ARCH_32BIT ? "[x32]" : "[x64]");
        return;
    }

    os_winreg_querykey(oshkey, subkey, fullkey_name, pos);
    RegCloseKey(oshkey);
    return;
}

void os_winreg_check()
{
    int i = 0;
    char *rk;

    /* Debug entries */
    mdebug1(FIM_WINREGISTRY_START);

    /* Get sub class and a valid registry entry */
    while (syscheck.registry[i].entry != NULL) {
        sub_tree = NULL;
        rk = NULL;

        /* Ignored entries are zeroed */
        if (*syscheck.registry[i].entry == '\0') {
            i++;
            continue;
        }

        /* Read syscheck registry entry */
        mdebug2(FIM_READING_REGISTRY, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32] ", syscheck.registry[i].entry);

        rk = os_winreg_sethkey(syscheck.registry[i].entry);
        if (sub_tree == NULL) {
            mdebug1(FIM_INV_REG, syscheck.registry[i].entry, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32]");
            *syscheck.registry[i].entry = '\0';
            i++;
            continue;
        }

        os_winreg_open_key(rk, syscheck.registry[i].entry, i);
        i++;
    }

    mdebug1(FIM_WINREGISTRY_ENDED);

    return;
}
#endif /* WIN32 */
