/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

/* Default values */
#define MAX_KEY_LENGTH   255
#define MAX_KEY         2048
#define MAX_VALUE_NAME 16383

/* Places to story the registry values */
#define SYS_WIN_REG     "syscheck/syscheckregistry.db"
#define SYS_REG_TMP     "syscheck/syscheck_sum.tmp"

/* Global variables */
HKEY sub_tree;
int ig_count = 0;
int run_count = 0;

/* Prototypes */
void os_winreg_open_key(char *subkey, char *fullkey_name, int arch, const char * tag);


int os_winreg_changed(char *key, char *md5, char *sha1, int arch)
{
    char buf[MAX_LINE + 1];
    char keyname[MAX_LINE + 1];

    buf[MAX_LINE] = '\0';

    snprintf(keyname, MAX_LINE, arch == ARCH_64BIT ? "[x64] %s" : "%s", key);

    /* Seek to the beginning of the db */
    fseek(syscheck.reg_fp, 0, SEEK_SET);

    while (fgets(buf, MAX_LINE, syscheck.reg_fp) != NULL) {
        if ((buf[0] != '#') && (buf[0] != ' ') && (buf[0] != '\n')) {
            char *n_buf;

            /* Remove the \n before reading */
            n_buf = strchr(buf, '\n');
            if (n_buf == NULL) {
                continue;
            }

            *n_buf = '\0';

            n_buf = strchr(buf, ' ');
            if (n_buf == NULL) {
                continue;
            }

            if (strcmp(n_buf + 1, keyname) != 0) {
                continue;
            }

            /* Entry found, check if checksum is the same */
            *n_buf = '\0';
            if ((strncmp(buf, md5, sizeof(os_md5) - 1) == 0) &&
                    (strcmp(buf + sizeof(os_md5) - 1, sha1) == 0)) {
                /* File didn't change */
                return (0);
            }

            /* File did change */
            return (1);
        }
    }

    fseek(syscheck.reg_fp, 0, SEEK_END);
    fprintf(syscheck.reg_fp, "%s%s %s\n", md5, sha1, keyname);
    return (1);
}

/* Notify of registry changes */
int notify_registry(char *msg, __attribute__((unused)) int send_now)
{
    if (SendMSG(syscheck.queue, msg,
                SYSCHECK_REG, SYSCHECK_MQ) < 0) {
        merror(QUEUE_SEND);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            merror_exit(QUEUE_FATAL, DEFAULTQPATH);
        }

        /* If we reach here, we can try to send it again */
        SendMSG(syscheck.queue, msg, SYSCHECK_REG, SYSCHECK_MQ);
    }

    return (0);
}

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
void os_winreg_querykey(HKEY hKey, char *p_key, char *full_key_name, int arch, const char * tag)
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

    /* We use the class_name, subkey_count and the value count */
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
                os_winreg_open_key(new_key, new_key_full, arch, tag);
            }
        }
    }

    /* Get values (if available) */
    if (value_count) {
        /* md5 and sha1 sum */
        os_md5 mf_sum;
        os_sha1 sf_sum;
        FILE *checksum_fp;
        char *mt_data;

        /* Clear the values for value_size and data_size */
        value_buffer[MAX_VALUE_NAME] = '\0';
        data_buffer[MAX_VALUE_NAME] = '\0';
        checksum_fp = fopen(SYS_REG_TMP, "w");
        if (!checksum_fp) {
            printf("%s: (1103): Could not open file '%s' due to [(%d)-(%s)].", ARGV0, SYS_REG_TMP, errno, strerror(errno));
            return;
        }

        /* Get each value */
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
            fprintf(checksum_fp, "%s=", value_buffer);
            switch (data_type) {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    fprintf(checksum_fp, "%s\n", data_buffer);
                    break;
                case REG_MULTI_SZ:
                    /* Print multiple strings */
                    mt_data = data_buffer;

                    while (*mt_data) {
                        fprintf(checksum_fp, "%s ", mt_data);
                        mt_data += strlen(mt_data) + 1;
                    }
                    fprintf(checksum_fp, "\n");
                    break;
                case REG_DWORD:
                    fprintf(checksum_fp, "%08x\n", (unsigned int)*data_buffer);
                    break;
                default:
                    for (j = 0; j < data_size; j++) {
                        fprintf(checksum_fp, "%02x",
                                (unsigned int)data_buffer[j]);
                    }
                    fprintf(checksum_fp, "\n");
                    break;
            }
        }

        /* Generate checksum of the values */
        fclose(checksum_fp);

        if (OS_MD5_SHA1_File(SYS_REG_TMP, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_TEXT) == -1) {
            merror(FOPEN_ERROR, SYS_REG_TMP, errno, strerror(errno));
            return;
        }

        /* Look for p_key on the reg db */
        if (os_winreg_changed(full_key_name, mf_sum, sf_sum, arch)) {
            char reg_changed[MAX_LINE + 1];
            snprintf(reg_changed, MAX_LINE, "::::%s:%s::::::!:::::::::::%s %s%s",
                     mf_sum, sf_sum, tag ? tag : "", arch == ARCH_64BIT ? "[x64] " : "", full_key_name);

            /* Notify server */
            notify_registry(reg_changed, 0);
        }

        ig_count++;
    }
}

/* Open the registry key */
void os_winreg_open_key(char *subkey, char *fullkey_name, int arch, const char *tag)
{
    int i = 0;
    HKEY oshkey;

    /* Sleep X every Y files */
    if (ig_count >= syscheck.sleep_after) {
        sleep(syscheck.tsleep);
        ig_count = 1;
    }
    ig_count++;

    /* Registry ignore list */
    if (fullkey_name && syscheck.registry_ignore) {
        while (syscheck.registry_ignore[i].entry != NULL) {
            if (syscheck.registry_ignore[i].arch == arch && strcasecmp(syscheck.registry_ignore[i].entry, fullkey_name) == 0) {
                mdebug1("Ignoring registry '%s' ignore '%s', continuing...", fullkey_name, syscheck.registry_ignore[i].entry);
                return;
            }
            i++;
        }
    } else if (fullkey_name && syscheck.registry_ignore_regex) {
        i = 0;
        while (syscheck.registry_ignore_regex[i].regex != NULL) {
            if (syscheck.registry_ignore[i].arch == arch &&
                OSMatch_Execute(fullkey_name, strlen(fullkey_name),
                                syscheck.registry_ignore_regex[i].regex)) {
                mdebug1("Ignoring registry '%s' ignore '%s', continuing...", fullkey_name, syscheck.registry_ignore_regex[i].regex->raw);
                return;
            }
            i++;
        }
    }

    if (RegOpenKeyEx(sub_tree, subkey, 0, KEY_READ | (arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &oshkey) != ERROR_SUCCESS) {
        mwarn(SK_REG_OPEN, subkey);
        return;
    }

    os_winreg_querykey(oshkey, subkey, fullkey_name, arch, tag);
    RegCloseKey(oshkey);
    return;
}

/* Main function to read the registry */
void os_winreg_check()
{
    int i = 0;
    char *rk;

    /* Debug entries */
    mdebug1("Starting os_winreg_check");

    /* Zero ig_count before checking */
    ig_count = 1;

    /* Check if the registry fp is open */
    if (syscheck.reg_fp == NULL) {
        syscheck.reg_fp = fopen(SYS_WIN_REG, "w+");
        if (!syscheck.reg_fp) {
            merror(FOPEN_ERROR, SYS_WIN_REG, errno, strerror(errno));
            return;
        }
    }

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
        mdebug1("Attempt to read: %s%s", syscheck.registry[i].arch == ARCH_64BIT ? "[x64] " : "", syscheck.registry[i].entry);

        rk = os_winreg_sethkey(syscheck.registry[i].entry);
        if (sub_tree == NULL) {
            merror(SK_INV_REG, syscheck.registry[i].entry);
            *syscheck.registry[i].entry = '\0';
            i++;
            continue;
        }

        os_winreg_open_key(rk, syscheck.registry[i].entry, syscheck.registry[i].arch, syscheck.registry[i].tag);
        i++;
    }

    /* Notify of db completed */
    if (run_count > 1) {
        sleep(syscheck.tsleep * 5);
    }

    run_count++;
    return;
}
#endif /* WIN32 */
