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
#include "../syscheck.h"
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


typedef struct __registry_key_t {
    HKEY root_key_handle;
    registry *configuration;
    char *full_key;
    char *sub_key;
} registry_key_t;

/* Prototypes */
void fim_open_key(char *subkey, char *fullkey_name, int pos);

/* Check if the registry entry is valid */
int fim_init_registry_key(registry_key_t *rkey, char *full_key, registry *configuration) {
    char *ret = NULL;
    char *tmp_str;

    if (rkey == NULL || full_key == NULL || configuration == NULL) {
        return -1;
    }

    /* Verify valid root tree */
    if (strncmp(full_key, "HKEY_LOCAL_MACHINE", 18) == 0) {
        rkey->root_key_handle = HKEY_LOCAL_MACHINE;
    } else if (strncmp(full_key, "HKEY_CLASSES_ROOT", 17) == 0) {
        rkey->root_key_handle = HKEY_CLASSES_ROOT;
    } else if (strncmp(full_key, "HKEY_CURRENT_CONFIG", 19) == 0) {
        rkey->root_key_handle = HKEY_CURRENT_CONFIG;
    } else if (strncmp(full_key, "HKEY_USERS", 10) == 0) {
        rkey->root_key_handle = HKEY_USERS;
    } else {
        return -1;
    }

    rkey->full_key = full_key;
    rkey->configuration = configuration;
    rkey->sub_key = strchr(rkey->full_key, '\\');
    return 0;
}

registry *fim_registry_configuration(const char *key, registry *arch) {
    int it = 0;
    int top = 0;
    registry *ret = NULL;

    for (it = 0; syscheck.registry[it].entry; it++) {
        if (arch != syscheck.registry[it].arch) {
            continue;
        }

        match = w_compare_str(syscheck.registry[it].entry, key);

        if (top < match) {
            ret = syscheck.registry[it];
            top = match;
        }
    }

    if (ret == NULL) {
        mdebug2(FIM_CONFIGURATION_NOTFOUND, "registry", path);
    }

    return ret;
}

int fim_init_child_registry_key(const registry_key_t *parent, registry_key_t *child, const char *full_key) {
    registry *child_configuration;

    if (parent == NULL || child == NULL || full_key == NULL) {
        return -1;
    }

    child_configuration = fim_registry_configuration(full_key, parent->configuration->arch);

    if (child_configuration == NULL) {
        return -1;
    }

    child->root_key_handle = parent->root_key_handle;
    child->full_key = full_key;
    child->configuration = child_configuration;
    child->sub_key = strchr(child->full_key, '\\');
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

        fim_file_data *data;
        char path[MAX_PATH + 7];
        unsigned char digest[EVP_MAX_MD_SIZE];
        int result;
        unsigned int digest_size;

        os_calloc(1, sizeof(fim_file_data), data);
        init_fim_data_entry(data);

        // Set registry entry type
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
void fim_open_key(registry_key_t *rkey) {
    HKEY sub_key_handle = NULL;
    REGSAM access_rights = KEY_READ;
    int rc;
    DWORD subkey_count = 0;
    DWORD value_count;
    FILETIME file_time = { 0 };

    if (rkey == NULL) {
        return
    }

    access_rights |= (rkey->configuration->arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);

    if (RegOpenKeyEx(rkey->root_key_handle, rkey->sub_key, 0, access_rights, &sub_key_handle) != ERROR_SUCCESS) {
        mdebug1(FIM_REG_OPEN, rkey->subkey, rkey->configuration->arch == ARCH_32BIT ? "[x32]" : "[x64]");
        return;
    }

    /* We use the class_name, subkey_count and the value count */
    if (RegQueryInfoKey(sub_key_handle, NULL, NULL, NULL,
                         &subkey_count, NULL, NULL, &value_count,
                         NULL, NULL, NULL, &file_time) != ERROR_SUCCESS) {
        return;
    }

    /* Query each subkey and call open_key */
    for (i = 0; i < subkey_count; i++) {
        char new_key[MAX_KEY + 2];
        char new_key_full[MAX_KEY + 2];
        WCHAR sub_key_name_b[MAX_KEY_LENGTH + 1];
        registry_key_t child_key;
        sub_key_name_s = MAX_KEY_LENGTH;
        rc = ;

        /* Checking for the rc */
        if (RegEnumKeyEx(sub_key_handle, i, sub_key_name_b, &sub_key_name_s,
                            NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            continue;
        }

        new_key[MAX_KEY + 1] = '\0';
        new_key_full[MAX_KEY + 1] = '\0';

        snprintf(new_key, MAX_KEY, "%s\\%s", rkey->full_key, sub_key_name_b);

        if (fim_init_child_registry_key(rkey, &child_key, new_key)) {
            mwarn("Failed to create child registry '%s'", new_key);
            continue;
        }

        /* Open subkey */
        fim_open_key(&child_key);
    }

//    os_winreg_querykey(sub_key_handle, subkey, fullkey_name, pos);
    RegCloseKey(sub_key_handle);
    return;
}

void fim_registry_scan() {
    registry_key_t rkey;
    int i = 0;
    char *rk;

    /* Debug entries */
    mdebug1(FIM_WINREGISTRY_START);

    /* Get sub class and a valid registry entry */
    for (i = 0; syscheck.registry[i].entry; i++) {
        rkey.root_key_handle = NULL;

        /* Ignored entries are zeroed */
        if (*syscheck.registry[i].entry == '\0') {
            continue;
        }

        /* Read syscheck registry entry */
        mdebug2(FIM_READING_REGISTRY, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32] ", syscheck.registry[i].entry);

        if (fim_init_registry_key(&rkey, syscheck.registry[i].entry, syscheck.registry[i]) != 0) {
            mdebug1(FIM_INV_REG, syscheck.registry[i].entry, syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "[x32]");
            *syscheck.registry[i].entry = '\0';
            continue;
        }

        fim_open_key(&rkey);
    }

    mdebug1(FIM_WINREGISTRY_ENDED);

    return;
}
#endif /* WIN32 */
