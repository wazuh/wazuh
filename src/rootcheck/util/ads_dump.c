/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <windows.h>

/* ads_dump
 * Dumps every NTFS ADS found in a directory (recursive)
 */

/* Prototypes */
int os_get_streams(char *full_path);
int read_sys_dir(char *dir_name);
int read_sys_file(char *file_name);

/* Global variables */
int ads_found = 0;


/* Print out streams of a file */
int os_get_streams(char *full_path)
{
    HANDLE file_h;
    WIN32_STREAM_ID sid;
    void *context = NULL;
    char stream_name[MAX_PATH + 1];
    char final_name[MAX_PATH + 1];
    DWORD dwRead, shs, dw1, dw2;

    /* Open file */
    file_h = CreateFile(full_path,
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
                char *tmp_pt;
                snprintf(final_name, MAX_PATH, "%s%S", full_path,
                         (WCHAR *)stream_name);
                tmp_pt = strrchr(final_name, ':');
                if (tmp_pt) {
                    *tmp_pt = '\0';
                }
                printf("Found NTFS ADS: '%s' \n", final_name);
                ads_found = 1;
            }
        }

        /* Get next */
        if (!BackupSeek(file_h, sid.Size.LowPart, sid.Size.HighPart,
                        &dw1, &dw2, &context)) {
            break;
        }
    }

    CloseHandle(file_h);
    return (0);
}

int read_sys_file(char *file_name)
{
    struct stat statbuf;

    /* Get streams */
    os_get_streams(file_name);
    if (stat(file_name, &statbuf) < 0) {
        return (0);
    }

    /* If directory, read the directory */
    else if (S_ISDIR(statbuf.st_mode)) {
        return (read_sys_dir(file_name));
    }

    return (0);
}

int read_sys_dir(char *dir_name)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    /* Get the number of nodes. The total number on opendir
     * must be the same.
     */
    if (stat(dir_name, &statbuf) < 0) {
        return (-1);
    }

    /* Must be a directory */
    if (!S_ISDIR(statbuf.st_mode)) {
        return (-1);
    }

    /* Open the directory given */
    dp = opendir(dir_name);
    if (!dp) {
        return (-1);
    }

    /* Read every entry in the directory */
    while ((entry = readdir(dp)) != NULL) {
        char f_name[MAX_PATH + 2];

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        /* Create new file + path string */
        snprintf(f_name, MAX_PATH + 1, "%s\\%s", dir_name, entry->d_name);

        read_sys_file(f_name);
    }

    closedir(dp);

    return (0);
}

int main(int argc, char **argv)
{
    printf("%s: NTFS ADS dumper (GPL v2)\n", argv[0]);
    printf("by Daniel B. Cid - dcid at ossec.net\n\n");

    /* Print every NTFS ADS found */
    if (argc < 2) {
        printf("%s dir\n", argv[0]);
        exit(1);
    }

    /* Get streams */
    read_sys_file(argv[1]);

    if (ads_found == 0) {
        printf("No NTFS ADS found.\n");
    }
    return (0);
}

