/* Copyright (C) 2015-2019, Wazuh Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"

/* Default values */
#define MAX_KEY_LENGTH   255
#define MAX_KEY         2048
#define MAX_VALUE_NAME 16383

char *(os_winreg_ignore_list[]) = {"SOFTWARE\\Classes", "test123", NULL};

HKEY sub_tree;
void os_winreg_open_key(char *subkey);


void os_winreg_querykey(HKEY hKey, char *p_key)
{
    int i, rc;
    DWORD j;

    /* QueryInfo and EnumKey variables */
    TCHAR sub_key_name_b[MAX_KEY_LENGTH + 1];
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

    /* Initialize the memory for some variables */
    class_name_b[0] = '\0';
    class_name_b[MAX_PATH] = '\0';
    sub_key_name_b[0] = '\0';
    sub_key_name_b[MAX_KEY_LENGTH] = '\0';

    /* We only use the class_name, subkey_count and value count */
    rc = RegQueryInfoKey(hKey, class_name_b, &class_name_s, NULL,
                         &subkey_count, NULL, NULL, &value_count,
                         NULL, NULL, NULL, NULL);

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

            /* Check for the rc */
            if (rc == ERROR_SUCCESS) {
                char new_key[MAX_KEY_LENGTH + 2];
                new_key[MAX_KEY_LENGTH + 1] = '\0';

                if (p_key) {
                    snprintf(new_key, MAX_KEY_LENGTH,
                             "%s\\%s", p_key, sub_key_name_b);
                } else {
                    snprintf(new_key, MAX_KEY_LENGTH, "%s", sub_key_name_b);
                }

                /* Open subkey */
                os_winreg_open_key(new_key);
            }
        }
    }

    /* Get Values (if available) */
    if (value_count) {
        /* MD5 and SHA-1 */
        os_md5 mf_sum;
        os_sha1 sf_sum;

        /* Clear the values for value_size and data_size */
        value_buffer[MAX_VALUE_NAME] = '\0';
        data_buffer[MAX_VALUE_NAME] = '\0';

        for (i = 0; i < value_count; i++) {
            value_size = MAX_VALUE_NAME;
            data_size = MAX_VALUE_NAME;

            value_buffer[0] = '\0';
            data_buffer[0] = '\0';

            rc = RegEnumValue(hKey, i, value_buffer, &value_size,
                              NULL, &data_type, data_buffer, &data_size);

            /* No more values available */
            if (rc != ERROR_SUCCESS) {
                break;
            }

            /* Check if no value name is specified */
            if (value_buffer[0] == '\0') {
                value_buffer[0] = '@';
                value_buffer[1] = '\0';
            }
            printf("   (%d) %s=", i + 1, value_buffer);
            switch (data_type) {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    printf("%s\n", data_buffer);
                    break;
                case REG_MULTI_SZ:
                    /* Print multiple strings */
                    printf("MULTI_SZ:");
                    char *mt_data;

                    mt_data = data_buffer;
                    while (*mt_data) {
                        printf("%s ", mt_data);
                        mt_data += strlen(mt_data) + 1;
                    }
                    printf("\n");
                    break;
                case REG_DWORD:
                    printf("%08x\n", (unsigned int)*data_buffer);
                    break;
                default:
                    printf("UNSUPPORTED(%d-%d):", (int)data_type, data_size);
                    for (j = 0; j < data_size; j++) {
                        printf("%02x", (unsigned int)data_buffer[j]);
                    }
                    printf("\n");
                    break;
            }
        }
    }
}

/* Open the registry key */
void os_winreg_open_key(char *subkey)
{
    int i = 0;
    HKEY oshkey;

    /* Registry ignore list */
    if (subkey) {
        while (os_winreg_ignore_list[i] != NULL) {
            if (strcasecmp(os_winreg_ignore_list[i], subkey) == 0) {
                return;
            }
            i++;
        }
    }

    if (RegOpenKeyEx(sub_tree, subkey, 0, KEY_READ, &oshkey) != ERROR_SUCCESS) {
        return;
    }

    os_winreg_querykey(oshkey, subkey);
    RegCloseKey(sub_tree);
}

/* Main function to read the registry */
int main(void)
{
    sub_tree = HKEY_LOCAL_MACHINE;
    char *rk = NULL;

    os_winreg_open_key(rk);

    return (0);
}

