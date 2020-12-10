/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle operation with files
 */

#include "shared.h"
#include "version_op.h"

#include "../external/zlib/zlib.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#endif
#endif

#ifndef WIN32
#include <regex.h>
#else
#include <aclapi.h>
#endif

/* Vista product information */
#ifdef WIN32

#ifndef PRODUCT_UNLICENSED
#define PRODUCT_UNLICENSED 0xABCDABCD
#endif
#ifndef PRODUCT_UNLICENSED_C
#define PRODUCT_UNLICENSED_C "Product Unlicensed "
#endif

#ifndef PRODUCT_BUSINESS
#define PRODUCT_BUSINESS 0x00000006
#endif
#ifndef PRODUCT_BUSINESS_C
#define PRODUCT_BUSINESS_C "Business Edition "
#endif

#ifndef PRODUCT_BUSINESS_N
#define PRODUCT_BUSINESS_N 0x00000010
#endif
#ifndef PRODUCT_BUSINESS_N_C
#define PRODUCT_BUSINESS_N_C "Business Edition "
#endif

#ifndef PRODUCT_CLUSTER_SERVER
#define PRODUCT_CLUSTER_SERVER 0x00000012
#endif
#ifndef PRODUCT_CLUSTER_SERVER_C
#define PRODUCT_CLUSTER_SERVER_C "Cluster Server Edition "
#endif

#ifndef PRODUCT_CLUSTER_SERVER_V
#define PRODUCT_CLUSTER_SERVER_V 0x00000040
#endif
#ifndef PRODUCT_CLUSTER_SERVER_V_C
#define PRODUCT_CLUSTER_SERVER_V_C "Server Hyper Core V "
#endif

#ifndef PRODUCT_DATACENTER_SERVER
#define PRODUCT_DATACENTER_SERVER 0x00000008
#endif
#ifndef PRODUCT_DATACENTER_SERVER_C
#define PRODUCT_DATACENTER_SERVER_C "Datacenter Edition (full) "
#endif

#ifndef PRODUCT_DATACENTER_SERVER_CORE
#define PRODUCT_DATACENTER_SERVER_CORE 0x0000000C
#endif
#ifndef PRODUCT_DATACENTER_SERVER_CORE_C
#define PRODUCT_DATACENTER_SERVER_CORE_C "Datacenter Edition (core) "
#endif

#ifndef PRODUCT_DATACENTER_SERVER_CORE_V
#define PRODUCT_DATACENTER_SERVER_CORE_V 0x00000027
#endif
#ifndef PRODUCT_DATACENTER_SERVER_CORE_V_C
#define PRODUCT_DATACENTER_SERVER_CORE_V_C "Datacenter Edition (core) "
#endif

#ifndef PRODUCT_DATACENTER_SERVER_V
#define PRODUCT_DATACENTER_SERVER_V 0x00000025
#endif
#ifndef PRODUCT_DATACENTER_SERVER_V_C
#define PRODUCT_DATACENTER_SERVER_V_C "Datacenter Edition (full) "
#endif

#ifndef PRODUCT_ENTERPRISE
#define PRODUCT_ENTERPRISE 0x00000004
#endif
#ifndef PRODUCT_ENTERPRISE_C
#define PRODUCT_ENTERPRISE_C "Enterprise Edition "
#endif

#ifndef PRODUCT_ENTERPRISE_N
#define PRODUCT_ENTERPRISE_N 0x0000001B
#endif
#ifndef PRODUCT_ENTERPRISE_N_C
#define PRODUCT_ENTERPRISE_N_C "Enterprise Edition "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER
#define PRODUCT_ENTERPRISE_SERVER 0x0000000A
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_C
#define PRODUCT_ENTERPRISE_SERVER_C "Enterprise Edition (full) "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_CORE
#define PRODUCT_ENTERPRISE_SERVER_CORE 0x0000000E
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_CORE_C
#define PRODUCT_ENTERPRISE_SERVER_CORE_C "Enterprise Edition (core) "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_CORE_V
#define PRODUCT_ENTERPRISE_SERVER_CORE_V 0x00000029
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_CORE_V_C
#define PRODUCT_ENTERPRISE_SERVER_CORE_V_C "Enterprise Edition (core) "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_IA64
#define PRODUCT_ENTERPRISE_SERVER_IA64 0x0000000F
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_IA64_C
#define PRODUCT_ENTERPRISE_SERVER_IA64_C "Enterprise Edition for Itanium-based Systems "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_V
#define PRODUCT_ENTERPRISE_SERVER_V 0x00000026
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_V_C
#define PRODUCT_ENTERPRISE_SERVER_V_C "Enterprise Edition (full) "
#endif

#ifndef PRODUCT_HOME_BASIC
#define PRODUCT_HOME_BASIC 0x00000002
#endif
#ifndef PRODUCT_HOME_BASIC_C
#define PRODUCT_HOME_BASIC_C "Home Basic Edition "
#endif

#ifndef PRODUCT_HOME_BASIC_N
#define PRODUCT_HOME_BASIC_N 0x00000005
#endif
#ifndef PRODUCT_HOME_BASIC_N_C
#define PRODUCT_HOME_BASIC_N_C "Home Basic Edition "
#endif

#ifndef PRODUCT_HOME_PREMIUM
#define PRODUCT_HOME_PREMIUM 0x00000003
#endif
#ifndef PRODUCT_HOME_PREMIUM_C
#define PRODUCT_HOME_PREMIUM_C "Home Premium Edition "
#endif

#ifndef PRODUCT_HOME_PREMIUM_N
#define PRODUCT_HOME_PREMIUM_N 0x0000001A
#endif
#ifndef PRODUCT_HOME_PREMIUM_N_C
#define PRODUCT_HOME_PREMIUM_N_C "Home Premium Edition "
#endif

#ifndef PRODUCT_HOME_SERVER
#define PRODUCT_HOME_SERVER 0x00000013
#endif
#ifndef PRODUCT_HOME_SERVER_C
#define PRODUCT_HOME_SERVER_C "Home Server Edition "
#endif

#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT
#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT 0x0000001E
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT_C
#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT_C "Essential Business Server Management Server "
#endif

#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING
#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING 0x00000020
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING_C
#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING_C "Essential Business Server Messaging Server "
#endif

#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY
#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY 0x0000001F
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY_C
#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY_C "Essential Business Server Security Server "
#endif

#ifndef PRODUCT_SERVER_FOR_SMALLBUSINESS
#define PRODUCT_SERVER_FOR_SMALLBUSINESS 0x00000018
#endif
#ifndef PRODUCT_SERVER_FOR_SMALLBUSINESS_C
#define PRODUCT_SERVER_FOR_SMALLBUSINESS_C "Small Business Edition "
#endif

#ifndef PRODUCT_SMALLBUSINESS_SERVER
#define PRODUCT_SMALLBUSINESS_SERVER 0x00000009
#endif
#ifndef PRODUCT_SMALLBUSINESS_SERVER_C
#define PRODUCT_SMALLBUSINESS_SERVER_C "Small Business Server "
#endif

#ifndef PRODUCT_SMALLBUSINESS_SERVER_PREMIUM
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM 0x00000019
#endif
#ifndef PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_C
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_C "Small Business Server Premium Edition "
#endif

#ifndef PRODUCT_STANDARD_SERVER
#define PRODUCT_STANDARD_SERVER 0x00000007
#endif
#ifndef PRODUCT_STANDARD_SERVER_C
#define PRODUCT_STANDARD_SERVER_C "Standard Edition "
#endif

#ifndef PRODUCT_STANDARD_SERVER_CORE
#define PRODUCT_STANDARD_SERVER_CORE 0x0000000D
#endif
#ifndef PRODUCT_STANDARD_SERVER_CORE_C
#define PRODUCT_STANDARD_SERVER_CORE_C "Standard Edition (core) "
#endif

#ifndef PRODUCT_STANDARD_SERVER_CORE_V
#define PRODUCT_STANDARD_SERVER_CORE_V 0x00000028
#endif
#ifndef PRODUCT_STANDARD_SERVER_CORE_V_C
#define PRODUCT_STANDARD_SERVER_CORE_V_C "Standard Edition "
#endif

#ifndef PRODUCT_STANDARD_SERVER_V
#define PRODUCT_STANDARD_SERVER_V 0x00000024
#endif
#ifndef PRODUCT_STANDARD_SERVER_V_C
#define PRODUCT_STANDARD_SERVER_V_C "Standard Edition "
#endif

#ifndef PRODUCT_STARTER
#define PRODUCT_STARTER 0x0000000B
#endif
#ifndef PRODUCT_STARTER_C
#define PRODUCT_STARTER_C "Starter Edition "
#endif

#ifndef PRODUCT_STORAGE_ENTERPRISE_SERVER
#define PRODUCT_STORAGE_ENTERPRISE_SERVER 0x00000017
#endif
#ifndef PRODUCT_STORAGE_ENTERPRISE_SERVER_C
#define PRODUCT_STORAGE_ENTERPRISE_SERVER_C "Storage Server Enterprise Edition "
#endif

#ifndef PRODUCT_STORAGE_EXPRESS_SERVER
#define PRODUCT_STORAGE_EXPRESS_SERVER 0x00000014
#endif
#ifndef PRODUCT_STORAGE_EXPRESS_SERVER_C
#define PRODUCT_STORAGE_EXPRESS_SERVER_C "Storage Server Express Edition "
#endif

#ifndef PRODUCT_STORAGE_STANDARD_SERVER
#define PRODUCT_STORAGE_STANDARD_SERVER 0x00000015
#endif
#ifndef PRODUCT_STORAGE_STANDARD_SERVER_C
#define PRODUCT_STORAGE_STANDARD_SERVER_C "Storage Server Standard Edition "
#endif

#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER
#define PRODUCT_STORAGE_WORKGROUP_SERVER 0x00000016
#endif
#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER_C
#define PRODUCT_STORAGE_WORKGROUP_SERVER_C "Storage Server Workgroup Edition "
#endif

#ifndef PRODUCT_ULTIMATE
#define PRODUCT_ULTIMATE 0x00000001
#endif
#ifndef PRODUCT_ULTIMATE_C
#define PRODUCT_ULTIMATE_C "Ultimate Edition "
#endif

#ifndef PRODUCT_ULTIMATE_N
#define PRODUCT_ULTIMATE_N 0x0000001C
#endif
#ifndef PRODUCT_ULTIMATE_N_C
#define PRODUCT_ULTIMATE_N_C "Ultimate Edition "
#endif

#ifndef PRODUCT_WEB_SERVER
#define PRODUCT_WEB_SERVER 0x00000011
#endif
#ifndef PRODUCT_WEB_SERVER_C
#define PRODUCT_WEB_SERVER_C "Web Server Edition "
#endif

#ifndef PRODUCT_WEB_SERVER_CORE
#define PRODUCT_WEB_SERVER_CORE 0x0000001D
#endif
#ifndef PRODUCT_WEB_SERVER_CORE_C
#define PRODUCT_WEB_SERVER_CORE_C "Web Server Edition "
#endif

#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL 0x0000003C
#endif
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL_C
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL_C "Essential Server Solution Additional "
#endif

#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC 0x0000003E
#endif
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC_C
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC_C "Essential Server Solution Additional SVC "
#endif

#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT 0x0000003B
#endif
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT_C
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT_C "Essential Server Solution Management "
#endif

#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC 0x0000003D
#endif
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC_C
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC_C "Essential Server Solution Management SVC "
#endif

#ifndef PRODUCT_HOME_PREMIUM_SERVER
#define PRODUCT_HOME_PREMIUM_SERVER 0x00000022
#endif
#ifndef PRODUCT_HOME_PREMIUM_SERVER_C
#define PRODUCT_HOME_PREMIUM_SERVER_C "Home Server 2011 "
#endif

#ifndef PRODUCT_HYPERV
#define PRODUCT_HYPERV 0x0000002A
#endif
#ifndef PRODUCT_HYPERV_C
#define PRODUCT_HYPERV_C "Hyper-V Server "
#endif

#ifndef PRODUCT_MULTIPOINT_PREMIUM_SERVER
#define PRODUCT_MULTIPOINT_PREMIUM_SERVER 0x0000004D
#endif
#ifndef PRODUCT_MULTIPOINT_PREMIUM_SERVER_C
#define PRODUCT_MULTIPOINT_PREMIUM_SERVER_C "MultiPoint Server Premium (full installation) "
#endif

#ifndef PRODUCT_MULTIPOINT_STANDARD_SERVER
#define PRODUCT_MULTIPOINT_STANDARD_SERVER 0x0000004C
#endif
#ifndef PRODUCT_MULTIPOINT_STANDARD_SERVER_C
#define PRODUCT_MULTIPOINT_STANDARD_SERVER_C "MultiPoint Server Standard (full installation) "
#endif

#ifndef PRODUCT_STANDARD_SERVER_SOLUTIONS
#define PRODUCT_STANDARD_SERVER_SOLUTIONS 0x00000034
#endif
#ifndef PRODUCT_STANDARD_SERVER_SOLUTIONS_C
#define PRODUCT_STANDARD_SERVER_SOLUTIONS_C "Server Solutions Premium "
#endif

#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER_CORE
#define PRODUCT_STORAGE_WORKGROUP_SERVER_CORE 0x0000002D
#endif
#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER_CORE_C
#define PRODUCT_STORAGE_WORKGROUP_SERVER_CORE_C "Storage Server Workgroup (core installation) "
#endif

#define mkstemp(x) 0
#define mkdir(x, y) mkdir(x)
#endif /* WIN32 */

const char *__local_name = "unset";

/* Set the name of the starting program */
void OS_SetName(const char *name)
{
    __local_name = name;
    return;
}


time_t File_DateofChange(const char *file)
{
    struct stat file_status;

    if (stat(file, &file_status) < 0) {
        return (-1);
    }

    return (file_status.st_mtime);
}


ino_t File_Inode(const char *file)
{
    struct stat buffer;
    return stat(file, &buffer) ? 0 : buffer.st_ino;
}


int IsDir(const char *file)
{
    struct stat file_status;
    if (stat(file, &file_status) < 0) {
        return (-1);
    }
    if (S_ISDIR(file_status.st_mode)) {
        return (0);
    }
    return (-1);
}


int check_path_type(const char *dir)
{
    DIR *dp;
    int retval;

    if (dp = opendir(dir), dp) {
        retval = 2;
        closedir(dp);
    } else if (errno == ENOTDIR){
        retval = 1;
    } else {
        retval = 0;
    }
    return retval;
}


int IsFile(const char *file)
{
    struct stat buf;
	return (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 0 : -1;
}

#ifndef WIN32

int IsSocket(const char * file) {
    struct stat buf;
	return (!stat(file, &buf) && S_ISSOCK(buf.st_mode)) ? 0 : -1;
}


int IsLink(const char * file) {
    struct stat buf;
	return (!lstat(file, &buf) && S_ISLNK(buf.st_mode)) ? 0 : -1;
}

#endif // WIN32


off_t FileSize(const char * path) {
    struct stat buf;
    return stat(path, &buf) ? -1 : buf.st_size;
}


#ifndef WIN32

float DirSize(const char *path) {
    struct dirent *dir;
    struct stat buf;
    DIR *directory;
    float folder_size = 0.0;
    float file_size = 0.0;
    char *entry;

    if (directory = opendir(path), directory == NULL) {
        mdebug2("Couldn't open directory '%s'.", path);
        return -1;
    }

    while ((dir = readdir(directory)) != NULL) {
        // Ignore . and ..
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
            continue;
        }

        os_malloc(strlen(path) + strlen(dir->d_name) + 2, entry);
        snprintf(entry, strlen(path) + 2 + strlen(dir->d_name), "%s/%s", path, dir->d_name);

        if (stat(entry, &buf) == -1) {
            os_free(entry);
            closedir(directory);
            return 0;
        }

        // Recursion if the path points to a directory
        switch (buf.st_mode & S_IFMT) {
        case S_IFDIR:
            folder_size += DirSize(entry);
            break;

        case S_IFREG:
            if (file_size = FileSize(entry), file_size != -1) {
                folder_size += file_size;
            }

            break;

        default:
            break;
        }

        os_free(entry);
    }

    closedir(directory);

    return folder_size;
}

#endif

int CreatePID(const char *name, int pid)
{
    char file[256];
    FILE *fp;

    if (isChroot()) {
        snprintf(file, 255, "%s/%s-%d.pid", OS_PIDFILE, name, pid);
    } else {
        snprintf(file, 255, "%s%s/%s-%d.pid", DEFAULTDIR,
                 OS_PIDFILE, name, pid);
    }

    fp = fopen(file, "a");
    if (!fp) {
        return (-1);
    }

    fprintf(fp, "%d\n", pid);
    if (chmod(file, 0640) != 0) {
        merror(CHMOD_ERROR, file, errno, strerror(errno));
        fclose(fp);
        return (-1);
    }

    if (fclose(fp)) {
        merror("Could not write PID file '%s': %s (%d)", file, strerror(errno), errno);
        return -1;
    }

    return (0);
}


char *GetRandomNoise()
{
    FILE *fp;
    char buf[2048 + 1];
    size_t n;

    /* Reading urandom */
    fp = fopen("/dev/urandom", "r");
    if(!fp)
    {
        return(NULL);
    }

    n = fread(buf, 1, 2048, fp);
    fclose(fp);

    if (n == 2048) {
        buf[2048] = '\0';
        return(strdup(buf));
    } else {
        return NULL;
    }
}


int DeletePID(const char *name)
{
    char file[256];

    if (isChroot()) {
        snprintf(file, 255, "%s/%s-%d.pid", OS_PIDFILE, name, (int)getpid());
    } else {
        snprintf(file, 255, "%s%s/%s-%d.pid", DEFAULTDIR,
                 OS_PIDFILE, name, (int)getpid());
    }

    if (File_DateofChange(file) < 0) {
        return (-1);
    }

    if (unlink(file)) {
        mferror(DELETE_ERROR, file, errno, strerror(errno));
        return (-1);
    }

    return (0);
}


void DeleteState() {
    char path[PATH_MAX + 1];

    if (strcmp(__local_name, "unset")) {
#ifdef WIN32
        snprintf(path, sizeof(path), "%s.state", __local_name);
#else
        snprintf(path, sizeof(path), "%s" OS_PIDFILE "/%s.state", isChroot() ? "" : DEFAULTDIR, __local_name);
#endif
        unlink(path);
    } else {
        merror("At DeleteState(): __local_name is unset.");
    }
}


int UnmergeFiles(const char *finalpath, const char *optdir, int mode)
{
    int ret = 1;
    int state_ok;
    size_t i = 0, n = 0, files_size = 0;
    char *files;
    char * copy;
    char final_name[2048 + 1];
    char buf[2048 + 1];
    FILE *fp;
    FILE *finalfp;

    finalfp = fopen(finalpath, mode == OS_BINARY ? "rb" : "r");
    if (!finalfp) {
        merror("Unable to read merged file: '%s' due to [(%d)-(%s)].", finalpath, errno, strerror(errno));
        return (0);
    }

    while (1) {
        /* Read header portion */
        if (fgets(buf, sizeof(buf) - 1, finalfp) == NULL) {
            break;
        }

        /* Initiator */
        if (buf[0] != '!') {
            continue;
        }

        /* Get file size and name */
        files_size = (size_t) atol(buf + 1);

        files = strchr(buf, '\n');
        if (files) {
            *files = '\0';
        }

        files = strchr(buf, ' ');
        if (!files) {
            ret = 0;
            continue;
        }
        files++;
        state_ok = 1;

        if (optdir) {
            snprintf(final_name, 2048, "%s/%s", optdir, files);

            // Check that final_name is inside optdir

            if (w_ref_parent_folder(final_name)) {
                merror("Unmerging '%s': unable to unmerge '%s' (it contains '..')", finalpath, final_name);
                state_ok = 0;
            }
        } else {
            strncpy(final_name, files, 2048);
            final_name[2048] = '\0';
        }

        // Create directory

        copy = strdup(final_name);

        if (mkdir_ex(dirname(copy))) {
            merror("Unmerging '%s': couldn't create directory '%s'", finalpath, files);
            state_ok = 0;
        }

        free(copy);

        /* Open filename */

        if (state_ok) {
            if (fp = fopen(final_name, mode == OS_BINARY ? "wb" : "w"), !fp) {
                ret = 0;
                merror("Unable to unmerge file '%s' due to [(%d)-(%s)].", final_name, errno, strerror(errno));
            }
        } else {
            fp = NULL;
            ret = 0;
        }

        if (files_size < sizeof(buf) - 1) {
            i = files_size;
            files_size = 0;
        } else {
            i = sizeof(buf) - 1;
            files_size -= sizeof(buf) - 1;
        }

        while ((n = fread(buf, 1, i, finalfp)) > 0) {
            buf[n] = '\0';

            if (fp) {
                fwrite(buf, n, 1, fp);
            }

            if (files_size == 0) {
                break;
            } else {
                if (files_size < sizeof(buf) - 1) {
                    i = files_size;
                    files_size = 0;
                } else {
                    i = sizeof(buf) - 1;
                    files_size -= sizeof(buf) - 1;
                }
            }
        }

        if (fp) {
            fclose(fp);
        }
    }

    fclose(finalfp);
    return (ret);
}


int TestUnmergeFiles(const char *finalpath, int mode)
{
    int ret = 1;
    size_t i = 0, n = 0, files_size = 0, read_bytes = 0,data_size = 0;
    char *files;
    char buf[2048 + 1];
    FILE *finalfp;

    finalfp = fopen(finalpath, mode == OS_BINARY ? "rb" : "r");
    if (!finalfp) {
        merror("Unable to read merged file: '%s'.", finalpath);
        return (0);
    }

    while (1) {
        /* Read header portion */
        if (fgets(buf, sizeof(buf) - 1, finalfp) == NULL) {
            break;
        }

        /* Initiator */
        switch(buf[0]) {
            case '#':
                continue;
            case '!':
                goto parse;
            default:
                ret = 0;
                goto end;
        }

parse:
        /* Get file size and name */
        files_size = (size_t) atol(buf + 1);
        data_size = files_size;

        files = strchr(buf, '\n');
        if (files) {
            *files = '\0';
        }

        files = strchr(buf, ' ');
        if (!files) {
            ret = 0;
            continue;
        }
        files++;

        /* Check for file name */
        if(*files == '\0') {
            ret = 0;
            goto end;
        }

        if (files_size < sizeof(buf) - 1) {
            i = files_size;
            files_size = 0;
        } else {
            i = sizeof(buf) - 1;
            files_size -= sizeof(buf) - 1;
        }

        read_bytes = 0;
        while ((n = fread(buf, 1, i, finalfp)) > 0) {
            buf[n] = '\0';
            read_bytes += n;

            if (files_size == 0) {
                break;
            } else {
                if (files_size < sizeof(buf) - 1) {
                    i = files_size;
                    files_size = 0;
                } else {
                    i = sizeof(buf) - 1;
                    files_size -= sizeof(buf) - 1;
                }
            }
        }

        if(read_bytes != data_size){
            ret = 0;
            goto end;
        }

    }
end:
    fclose(finalfp);
    return (ret);
}


int MergeAppendFile(const char *finalpath, const char *files, const char *tag, int path_offset)
{
    size_t n = 0;
    long files_size = 0;
    char buf[2048 + 1];
    FILE *fp;
    FILE *finalfp;
    char newpath[PATH_MAX];
    DIR *dir;
    struct dirent *ent = NULL;

    /* Create a new entry */

    if (files == NULL) {
        finalfp = fopen(finalpath, "w");
        if (!finalfp) {
            merror("Unable to create merged file: '%s' due to [(%d)-(%s)].", finalpath, errno, strerror(errno));
            return (0);
        }

        if (tag) {
            fprintf(finalfp, "#%s\n", tag);
        }

        fclose(finalfp);

        if (chmod(finalpath, 0660) < 0) {
            merror(CHMOD_ERROR, finalpath, errno, strerror(errno));
            return 0;
        }

        return (1);
    }

    if (path_offset < 0) {
        char filename[PATH_MAX];
        char * basedir;

        // Create default basedir

        strncpy(filename, files, sizeof(filename));
        filename[sizeof(filename) - 1] = '\0';
        basedir = dirname(filename);
        path_offset = strlen(basedir);

        if (basedir[path_offset - 1] != '/') {
            path_offset++;
        }
    }

    /* Is a file */
    if (dir = opendir(files), !dir) {

        finalfp = fopen(finalpath, "a");
        if (!finalfp) {
            merror("Unable to append merged file: '%s' due to [(%d)-(%s)].", finalpath, errno, strerror(errno));
            return (0);
        }

        fp = fopen(files, "r");

        if (!fp) {
            merror("Unable to merge file '%s' due to [(%d)-(%s)].", files, errno, strerror(errno));
            fclose(finalfp);
            return (0);
        }

        fseek(fp, 0, SEEK_END);
        files_size = ftell(fp);

        if (tag) {
            fprintf(finalfp, "#%s\n", tag);
        }

        fprintf(finalfp, "!%ld %s\n", files_size, files + path_offset);
        fseek(fp, 0, SEEK_SET);

        while ((n = fread(buf, 1, sizeof(buf) - 1, fp)) > 0) {
            buf[n] = '\0';
            fwrite(buf, n, 1, finalfp);
        }

        fclose(fp);
        fclose(finalfp);
    }
    else { /* Is a directory */
        mdebug2("Merging directory: %s", files);

        while ((ent = readdir(dir)) != NULL) {
            // Skip . and ..
            if (ent->d_name[0] != '.' || (ent->d_name[1] && (ent->d_name[1] != '.' || ent->d_name[2]))) {
                snprintf(newpath, PATH_MAX, "%s/%s", files, ent->d_name);
                MergeAppendFile(finalpath, newpath, tag, path_offset);
            }
        }

        closedir(dir);
    }

    return (1);
}


int checkBinaryFile(const char *f_name) {
    FILE *fp;
    char str[OS_MAXSTR + 1];
    fpos_t fp_pos;
    int64_t offset;
    int64_t rbytes;

    str[OS_MAXSTR] = '\0';

    fp = fopen(f_name, "r");

     if (!fp) {
        merror("Unable to open file '%s' due to [(%d)-(%s)].", f_name, errno, strerror(errno));
        return 1;
    }

    /* Get initial file location */
    fgetpos(fp, &fp_pos);

    for (offset = w_ftell(fp); fgets(str, OS_MAXSTR + 1, fp) != NULL; offset += rbytes) {
        rbytes = w_ftell(fp) - offset;

        /* Flow control */
        if (rbytes <= 0) {
            fclose(fp);
            return 1;
        }

        /* Get the last occurrence of \n */
        if (str[rbytes - 1] == '\n') {
            str[rbytes - 1] = '\0';

            if ((long)strlen(str) != rbytes - 1)
            {
                mdebug2("Line contains some zero-bytes (valid=" FTELL_TT "/ total=" FTELL_TT ").", FTELL_INT64 strlen(str), FTELL_INT64 rbytes - 1);
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}


int MergeFiles(const char *finalpath, char **files, const char *tag)
{
    int i = 0, ret = 1;
    size_t n = 0;
    long files_size = 0;

    char *tmpfile;
    char buf[2048 + 1];
    FILE *fp;
    FILE *finalfp;

    finalfp = fopen(finalpath, "w");
    if (!finalfp) {
        merror("Unable to create merged file: '%s' due to [(%d)-(%s)].", finalpath, errno, strerror(errno));
        return (0);
    }

    if (tag) {
        fprintf(finalfp, "#%s\n", tag);
    }

    while (files[i]) {
        fp = fopen(files[i], "r");
        if (!fp) {
            merror("Unable to merge file '%s' due to [(%d)-(%s)].", files[i], errno, strerror(errno));
            i++;
            ret = 0;
            continue;
        }

        fseek(fp, 0, SEEK_END);
        files_size = ftell(fp);

        /* Remove last entry */
        tmpfile = strrchr(files[i], '/');
        if (tmpfile) {
            tmpfile++;
        } else {
            tmpfile = files[i];
        }

        fprintf(finalfp, "!%ld %s\n", files_size, tmpfile);

        fseek(fp, 0, SEEK_SET);
        while ((n = fread(buf, 1, sizeof(buf) - 1, fp)) > 0) {
            buf[n] = '\0';
            fwrite(buf, n, 1, finalfp);
        }

        fclose(fp);
        i++;
    }

    fclose(finalfp);
    return (ret);
}


#ifndef WIN32
/* Get basename of path */
char *basename_ex(char *path)
{
    return (basename(path));
}

/* Rename file or directory */
int rename_ex(const char *source, const char *destination)
{
    if (rename(source, destination)) {
        mferror(RENAME_ERROR, source, destination, errno, strerror(errno));

        return (-1);
    }

    return (0);
}

/* Create a temporary file */
int mkstemp_ex(char *tmp_path)
{
    int fd;
    mode_t old_mask = umask(0177);

    fd = mkstemp(tmp_path);
    umask(old_mask);

    if (fd == -1) {
        mferror(MKSTEMP_ERROR, tmp_path, errno, strerror(errno));

        return (-1);
    }

    /* mkstemp() only implicitly does this in POSIX 2008 */
    if (fchmod(fd, 0600) == -1) {
        close(fd);

        mferror(CHMOD_ERROR, tmp_path, errno, strerror(errno));

        if (unlink(tmp_path)) {
            mferror(DELETE_ERROR, tmp_path, errno, strerror(errno));
        }

        return (-1);
    }

    close(fd);
    return (0);
}


/* Get uname. Memory must be freed after use */
const char *getuname()
{
    struct utsname uts_buf;
    static char muname[512] = "";
    os_info *read_version;

    if (!muname[0]){
        if (read_version = get_unix_version(), read_version){
            snprintf(muname, 512, "%s |%s |%s |%s |%s [%s|%s: %s] - %s %s",
                    read_version->sysname,
                    read_version->nodename,
                    read_version->release,
                    read_version->version,
                    read_version->machine,
                    read_version->os_name,
                    read_version->os_platform,
                    read_version->os_version,
                    __ossec_name, __ossec_version);

            free_osinfo(read_version);
        }
        else if (uname(&uts_buf) >= 0) {
            snprintf(muname, 512, "%s %s %s %s %s - %s %s",
                     uts_buf.sysname,
                     uts_buf.nodename,
                     uts_buf.release,
                     uts_buf.version,
                     uts_buf.machine,
                     __ossec_name, __ossec_version);
        } else {
            snprintf(muname, 512, "No system info available - %s %s",
                     __ossec_name, __ossec_version);
        }
    }

    return muname;
}


/* Daemonize a process without closing stdin/stdout/stderr */
void goDaemonLight()
{
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        merror(FORK_ERROR, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    /* Become session leader */
    if (setsid() < 0) {
        merror(SETSID_ERROR, errno, strerror(errno));
        return;
    }

    /* Fork again */
    pid = fork();
    if (pid < 0) {
        merror(FORK_ERROR, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    dup2(1, 2);

    /* Go to / */
    if (chdir("/") == -1) {
        merror(CHDIR_ERROR, "/", errno, strerror(errno));
    }

    nowDaemon();
}

/* Daemonize a process */
void goDaemon()
{
    int fd;
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        merror(FORK_ERROR, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    /* Become session leader */
    if (setsid() < 0) {
        merror(SETSID_ERROR, errno, strerror(errno));
        return;
    }

    /* Fork again */
    pid = fork();
    if (pid < 0) {
        merror(FORK_ERROR, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    /* Dup stdin, stdout and stderr to /dev/null */
    if ((fd = open("/dev/null", O_RDWR)) >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);

        close(fd);
    }

    /* Go to / */
    if (chdir("/") == -1) {
        merror(CHDIR_ERROR, "/", errno, strerror(errno));
    }

    nowDaemon();
}

#else /* WIN32 */

int checkVista()
{
    /* Check if the system is Vista (must be called during the startup) */
    isVista = 0;

    OSVERSIONINFOEX osvi = { .dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX) };
    BOOL bOsVersionInfoEx;

    if (bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi), !bOsVersionInfoEx) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx((OSVERSIONINFO *)&osvi)) {
            merror("Cannot get Windows version number.");
            return -1;
        }
    }

    if (osvi.dwMajorVersion >= 6) {
        isVista = 1;
    }

    return (isVista);
}


int get_creation_date(char *dir, SYSTEMTIME *utc) {
    HANDLE hdle;
    FILETIME creation_date;
    int retval = 1;

    if (hdle = CreateFile(dir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL), hdle == INVALID_HANDLE_VALUE) {
        return retval;
    }

    if (!GetFileTime(hdle, &creation_date, NULL, NULL)) {
        goto end;
    }

    FileTimeToSystemTime(&creation_date, utc);
    retval = 0;
end:
    CloseHandle(hdle);
    return retval;
}


char *basename_ex(char *path)
{
    return (PathFindFileNameA(path));
}


int rename_ex(const char *source, const char *destination)
{
    if (!MoveFileEx(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        mferror("Could not move (%s) to (%s) which returned (%lu)", source, destination, GetLastError());

        return (-1);
    }

    return (0);
}


int mkstemp_ex(char *tmp_path)
{
    DWORD dwResult;
    int result;
    int status = -1;

    HANDLE h = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea[2];
    SECURITY_ATTRIBUTES sa;

    PSID pAdminGroupSID = NULL;
    PSID pSystemGroupSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = {SECURITY_NT_AUTHORITY};


    if (result = _mktemp_s(tmp_path, strlen(tmp_path) + 1), result) {
        mferror("Could not create temporary file (%s) which returned %d [(%d)-(%s)].", tmp_path, result, errno, strerror(errno));
        return (-1);
    }

    /* Create SID for the BUILTIN\Administrators group */
    result = AllocateAndInitializeSid(
                 &SIDAuthNT,
                 2,
                 SECURITY_BUILTIN_DOMAIN_RID,
                 DOMAIN_ALIAS_RID_ADMINS,
                 0, 0, 0, 0, 0, 0,
                 &pAdminGroupSID
             );

    if (!result) {
        mferror("Could not create BUILTIN\\Administrators group SID which returned (%lu)", GetLastError());

        goto cleanup;
    }

    /* Create SID for the SYSTEM group */
    result = AllocateAndInitializeSid(
                 &SIDAuthNT,
                 1,
                 SECURITY_LOCAL_SYSTEM_RID,
                 0, 0, 0, 0, 0, 0, 0,
                 &pSystemGroupSID
             );

    if (!result) {
        mferror("Could not create SYSTEM group SID which returned (%lu)", GetLastError());

        goto cleanup;
    }

    /* Initialize an EXPLICIT_ACCESS structure for an ACE */
    ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

    /* Add Administrators group */
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pAdminGroupSID;

    /* Add SYSTEM group */
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pSystemGroupSID;

    /* Set entries in ACL */
    dwResult = SetEntriesInAcl(2, ea, NULL, &pACL);

    if (dwResult != ERROR_SUCCESS) {
        mferror("Could not set ACL entries which returned (%lu)", dwResult);

        goto cleanup;
    }

    /* Initialize security descriptor */
    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(
              LPTR,
              SECURITY_DESCRIPTOR_MIN_LENGTH
          );

    if (pSD == NULL) {
        mferror("Could not initialize SECURITY_DESCRIPTOR because of a LocalAlloc() failure which returned (%lu)", GetLastError());

        goto cleanup;
    }

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        mferror("Could not initialize SECURITY_DESCRIPTOR because of an InitializeSecurityDescriptor() failure which returned (%lu)", GetLastError());

        goto cleanup;
    }

    /* Set owner */
    if (!SetSecurityDescriptorOwner(pSD, NULL, FALSE)) {
        mferror("Could not set owner which returned (%lu)", GetLastError());

        goto cleanup;
    }

    /* Set group owner */
    if (!SetSecurityDescriptorGroup(pSD, NULL, FALSE)) {
        mferror("Could not set group owner which returned (%lu)", GetLastError());

        goto cleanup;
    }

    /* Add ACL to security descriptor */
    if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE)) {
        mferror("Could not set SECURITY_DESCRIPTOR DACL which returned (%lu)", GetLastError());

        goto cleanup;
    }

    /* Initialize security attributes structure */
    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    h = CreateFileA(
            tmp_path,
            GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

    if (h == INVALID_HANDLE_VALUE) {
        mferror("Could not create temporary file (%s) which returned (%lu)", tmp_path, GetLastError());

        goto cleanup;
    }

    if (!CloseHandle(h)) {
        mferror("Could not close file handle to (%s) which returned (%lu)", tmp_path, GetLastError());

        goto cleanup;
    }

    /* Success */
    status = 0;

cleanup:
    if (pAdminGroupSID) {
        FreeSid(pAdminGroupSID);
    }

    if (pSystemGroupSID) {
        FreeSid(pSystemGroupSID);
    }

    if (pACL) {
        LocalFree(pACL);
    }

    if (pSD) {
        LocalFree(pSD);
    }

    return (status);
}


const char *getuname()
{
    int ret_size = OS_SIZE_1024 - 2;
    static char ret[OS_SIZE_1024 + 1] = "";
    char os_v[128 + 1];
    int add_infoEx = 1;

    typedef void (WINAPI * PGNSI)(LPSYSTEM_INFO);
    typedef BOOL (WINAPI * PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

    /* See http://msdn.microsoft.com/en-us/library/windows/desktop/ms724429%28v=vs.85%29.aspx */
    OSVERSIONINFOEX osvi;
    SYSTEM_INFO si = {0};
    PGNSI pGNSI;
    PGPI pGPI;
    BOOL bOsVersionInfoEx;
    DWORD dwType;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi))) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx((OSVERSIONINFO *)&osvi)) {
            return (NULL);
        }
    }

    if (ret[0] != '\0') {
        return ret;
    }

    switch (osvi.dwPlatformId) {
        /* Test for the Windows NT product family */
        case VER_PLATFORM_WIN32_NT:
            if (osvi.dwMajorVersion == 6 && (osvi.dwMinorVersion == 0 || osvi.dwMinorVersion == 1) ) {
                if (osvi.dwMinorVersion == 0) {
                    if (osvi.wProductType == VER_NT_WORKSTATION ) {
                        strncat(ret, "Microsoft Windows Vista ", ret_size - 1);
                    } else {
                        strncat(ret, "Microsoft Windows Server 2008 ", ret_size - 1);
                    }
                } else if (osvi.dwMinorVersion == 1) {
                    if (osvi.wProductType == VER_NT_WORKSTATION ) {
                        strncat(ret, "Microsoft Windows 7 ", ret_size - 1);
                    } else {
                        strncat(ret, "Microsoft Windows Server 2008 R2 ", ret_size - 1);
                    }
                }

                ret_size -= strlen(ret) + 1;


                /* Get product version */
                pGPI = (PGPI) GetProcAddress(
                              GetModuleHandle(TEXT("kernel32.dll")),
                              "GetProductInfo");

                if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
                    pGPI( 6, 0, 0, 0, &dwType);
                else
                    pGPI( 6, 1, 0, 0, &dwType);

                switch (dwType) {
                    case PRODUCT_UNLICENSED:
                        strncat(ret, PRODUCT_UNLICENSED_C, ret_size - 1);
                        break;
                    case PRODUCT_BUSINESS:
                        strncat(ret, PRODUCT_BUSINESS_C, ret_size - 1);
                        break;
                    case PRODUCT_BUSINESS_N:
                        strncat(ret, PRODUCT_BUSINESS_N_C, ret_size - 1);
                        break;
                    case PRODUCT_CLUSTER_SERVER:
                        strncat(ret, PRODUCT_CLUSTER_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER_CORE:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_CORE_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER_CORE_V:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_CORE_V_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER_V:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_V_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE:
                        strncat(ret, PRODUCT_ENTERPRISE_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_N:
                        strncat(ret, PRODUCT_ENTERPRISE_N_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_CORE:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_CORE_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_CORE_V:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_CORE_V_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_IA64:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_IA64_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_V:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_V_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_BASIC:
                        strncat(ret, PRODUCT_HOME_BASIC_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_BASIC_N:
                        strncat(ret, PRODUCT_HOME_BASIC_N_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_PREMIUM:
                        strncat(ret, PRODUCT_HOME_PREMIUM_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_PREMIUM_N:
                        strncat(ret, PRODUCT_HOME_PREMIUM_N_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_SERVER:
                        strncat(ret, PRODUCT_HOME_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT:
                        strncat(ret, PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT_C, ret_size - 1);
                        break;
                    case PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING:
                        strncat(ret, PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING_C, ret_size - 1);
                        break;
                    case PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY:
                        strncat(ret, PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY_C, ret_size - 1);
                        break;
                    case PRODUCT_SERVER_FOR_SMALLBUSINESS:
                        strncat(ret, PRODUCT_SERVER_FOR_SMALLBUSINESS_C, ret_size - 1);
                        break;
                    case PRODUCT_SMALLBUSINESS_SERVER:
                        strncat(ret, PRODUCT_SMALLBUSINESS_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
                        strncat(ret, PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER:
                        strncat(ret, PRODUCT_STANDARD_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER_CORE:
                        strncat(ret, PRODUCT_STANDARD_SERVER_CORE_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER_CORE_V:
                        strncat(ret, PRODUCT_STANDARD_SERVER_CORE_V_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER_V:
                        strncat(ret, PRODUCT_STANDARD_SERVER_V_C, ret_size - 1);
                        break;
                    case PRODUCT_STARTER:
                        strncat(ret, PRODUCT_STARTER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_ENTERPRISE_SERVER:
                        strncat(ret, PRODUCT_STORAGE_ENTERPRISE_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_EXPRESS_SERVER:
                        strncat(ret, PRODUCT_STORAGE_EXPRESS_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_STANDARD_SERVER:
                        strncat(ret, PRODUCT_STORAGE_STANDARD_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_WORKGROUP_SERVER:
                        strncat(ret, PRODUCT_STORAGE_WORKGROUP_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_ULTIMATE:
                        strncat(ret, PRODUCT_ULTIMATE_C, ret_size - 1);
                        break;
                    case PRODUCT_ULTIMATE_N:
                        strncat(ret, PRODUCT_ULTIMATE_N_C, ret_size - 1);
                        break;
                    case PRODUCT_WEB_SERVER:
                        strncat(ret, PRODUCT_WEB_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_WEB_SERVER_CORE:
                        strncat(ret, PRODUCT_WEB_SERVER_CORE_C, ret_size - 1);
                        break;

                }
                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion == 6 && (osvi.dwMinorVersion == 2 || osvi.dwMinorVersion == 3)) {
                // Read Windows Version from registry
                DWORD dwRet;
                HKEY RegistryKey;
                const DWORD size = 1024;
                TCHAR value[size];
                DWORD dwCount = size;
                add_infoEx = 0;

                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), 0, KEY_READ | KEY_WOW64_64KEY , &RegistryKey) != ERROR_SUCCESS) {
                    merror("Error opening Windows registry.");
                }

                dwRet = RegQueryValueEx(RegistryKey, TEXT("ProductName"), NULL, NULL, (LPBYTE)value, &dwCount);
                if (dwRet != ERROR_SUCCESS) {
                    merror("Error reading Windows registry. (Error %u)",(unsigned int)dwRet);
                    strncat(ret, "Microsoft Windows undefined version", ret_size - 1);
                }
                else {
                    RegCloseKey(RegistryKey);
                    strncat(ret, "Microsoft ", ret_size - 1);
                    strncat(ret, value, ret_size - 1);
                }
                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2) {
                pGNSI = (PGNSI)(LPSYSTEM_INFO)GetProcAddress(
                            GetModuleHandle("kernel32.dll"),
                            "GetNativeSystemInfo");
                if (NULL != pGNSI) {
                    pGNSI(&si);
                } else {
                    mwarn("It was not possible to retrieve GetNativeSystemInfo from kernek32.dll");
                }

                if ( GetSystemMetrics(89) )
                    strncat(ret, "Microsoft Windows Server 2003 R2 ",
                            ret_size - 1);
                else if (osvi.wProductType == VER_NT_WORKSTATION &&
                         si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
                    strncat(ret,
                            "Microsoft Windows XP Professional x64 Edition ",
                            ret_size - 1 );
                } else {
                    strncat(ret, "Microsoft Windows Server 2003, ", ret_size - 1);
                }

                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) {
                strncat(ret, "Microsoft Windows XP ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0) {
                strncat(ret, "Microsoft Windows 2000 ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion <= 4) {
                strncat(ret, "Microsoft Windows NT ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            } else {
                strncat(ret, "Microsoft Windows Unknown ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            }

            /* Test for specific product on Windows NT 4.0 SP6 and later */
            if (add_infoEx){
                if (bOsVersionInfoEx) {
                    /* Test for the workstation type */
                    if (osvi.wProductType == VER_NT_WORKSTATION &&
                            si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
                        if ( osvi.dwMajorVersion == 4 ) {
                            strncat(ret, "Workstation 4.0 ", ret_size - 1);
                        } else if ( osvi.wSuiteMask & VER_SUITE_PERSONAL ) {
                            strncat(ret, "Home Edition ", ret_size - 1);
                        } else {
                            strncat(ret, "Professional ", ret_size - 1);
                        }

                        /* Fix size */
                        ret_size -= strlen(ret) + 1;
                    }

                    /* Test for the server type */
                    else if ( osvi.wProductType == VER_NT_SERVER ||
                              osvi.wProductType == VER_NT_DOMAIN_CONTROLLER ) {
                        if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2) {
                            if (si.wProcessorArchitecture ==
                                    PROCESSOR_ARCHITECTURE_IA64 ) {
                                if ( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                    strncat(ret,
                                            "Datacenter Edition for Itanium-based Systems ",
                                            ret_size - 1);
                                else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                    strncat(ret,
                                            "Enterprise Edition for Itanium-based Systems ",
                                            ret_size - 1);

                                ret_size -= strlen(ret) + 1;
                            } else if ( si.wProcessorArchitecture ==
                                        PROCESSOR_ARCHITECTURE_AMD64 ) {
                                if ( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                    strncat(ret, "Datacenter x64 Edition ",
                                            ret_size - 1 );
                                else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                    strncat(ret, "Enterprise x64 Edition ",
                                            ret_size - 1 );
                                else
                                    strncat(ret, "Standard x64 Edition ",
                                            ret_size - 1 );

                                ret_size -= strlen(ret) + 1;
                            } else {
                                if ( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                    strncat(ret, "Datacenter Edition ",
                                            ret_size - 1 );
                                else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE ) {
                                    strncat(ret, "Enterprise Edition ", ret_size - 1);
                                } else if ( osvi.wSuiteMask == VER_SUITE_BLADE ) {
                                    strncat(ret, "Web Edition ", ret_size - 1 );
                                } else {
                                    strncat(ret, "Standard Edition ", ret_size - 1);
                                }

                                ret_size -= strlen(ret) + 1;
                            }
                        } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0) {
                            if ( osvi.wSuiteMask & VER_SUITE_DATACENTER ) {
                                strncat(ret, "Datacenter Server ", ret_size - 1);
                            } else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE ) {
                                strncat(ret, "Advanced Server ", ret_size - 1 );
                            } else {
                                strncat(ret, "Server ", ret_size - 1);
                            }

                            ret_size -= strlen(ret) + 1;
                        } else if (osvi.dwMajorVersion <= 4) { /* Windows NT 4.0 */
                            if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                strncat(ret, "Server 4.0, Enterprise Edition ",
                                        ret_size - 1 );
                            else {
                                strncat(ret, "Server 4.0 ", ret_size - 1);
                            }

                            ret_size -= strlen(ret) + 1;
                        }
                    }
                }
                /* Test for specific product on Windows NT 4.0 SP5 and earlier */
                else {
                    HKEY hKey;
                    char szProductType[81];
                    DWORD dwBufLen = 80;
                    LONG lRet;

                    lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                                         "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
                                         0, KEY_QUERY_VALUE, &hKey );
                    if (lRet == ERROR_SUCCESS) {
                        char __wv[32];

                        lRet = RegQueryValueEx( hKey, "ProductType", NULL, NULL,
                                                (LPBYTE) szProductType, &dwBufLen);
                        RegCloseKey( hKey );

                        if ((lRet == ERROR_SUCCESS) && (dwBufLen < 80) ) {
                            if (lstrcmpi( "WINNT", szProductType) == 0 ) {
                                strncat(ret, "Workstation ", ret_size - 1);
                            } else if (lstrcmpi( "LANMANNT", szProductType) == 0 ) {
                                strncat(ret, "Server ", ret_size - 1);
                            } else if (lstrcmpi( "SERVERNT", szProductType) == 0 ) {
                                strncat(ret, "Advanced Server " , ret_size - 1);
                            }

                            ret_size -= strlen(ret) + 1;

                            memset(__wv, '\0', 32);
                            snprintf(__wv, 31,
                                     "%d.%d ",
                                     (int)osvi.dwMajorVersion,
                                     (int)osvi.dwMinorVersion);

                            strncat(ret, __wv, ret_size - 1);
                            ret_size -= strlen(__wv) + 1;
                        }
                    }
                }
            }
            /* Display service pack (if any) and build number */
            if ( osvi.dwMajorVersion == 4 &&
                    lstrcmpi( osvi.szCSDVersion, "Service Pack 6" ) == 0 ) {
                HKEY hKey;
                LONG lRet;
                char __wp[64];

                memset(__wp, '\0', 64);
                /* Test for SP6 versus SP6a */
                lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                                     "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\Q246009",
                                     0, KEY_QUERY_VALUE, &hKey );
                if ( lRet == ERROR_SUCCESS )
                    snprintf(__wp, 63, "Service Pack 6a [Ver: %i.%i.%d]",
                             (int)osvi.dwMajorVersion,
                             (int)osvi.dwMinorVersion,
                             (int)osvi.dwBuildNumber & 0xFFFF );
                else { /* Windows NT 4.0 prior to SP6a */
                    snprintf(__wp, 63, "%s [Ver: %i.%i.%d]",
                             osvi.szCSDVersion,
                             (int)osvi.dwMajorVersion,
                             (int)osvi.dwMinorVersion,
                             (int)osvi.dwBuildNumber & 0xFFFF );
                }

                strncat(ret, __wp, ret_size - 1);
                ret_size -= strlen(__wp) + 1;
                RegCloseKey( hKey );
            } else if (osvi.dwMajorVersion == 6 && (osvi.dwMinorVersion == 2 || osvi.dwMinorVersion == 3)) {
                // Read Windows Version number from registry
                char __wp[64];
                memset(__wp, '\0', 64);
                DWORD dwRet;
                HKEY RegistryKey;
                const DWORD size = 30;
                TCHAR winver[size];
                TCHAR wincomp[size];
                DWORD winMajor = 0;
                DWORD winMinor = 0;
                DWORD dwCount = size;
                unsigned long type=REG_DWORD;

                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), 0, KEY_READ | KEY_WOW64_64KEY, &RegistryKey) != ERROR_SUCCESS) {
                    merror("Error opening Windows registry.");
                }

                // Windows 10
                dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentMajorVersionNumber"), NULL, &type, (LPBYTE)&winMajor, &dwCount);
                if (dwRet == ERROR_SUCCESS) {
                    dwCount = size;
                    dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentMinorVersionNumber"), NULL, &type, (LPBYTE)&winMinor, &dwCount);
                    if (dwRet != ERROR_SUCCESS) {
                        merror("Error reading 'CurrentMinorVersionNumber' from Windows registry. (Error %u)",(unsigned int)dwRet);
                    }
                    else {
                        dwCount = size;
                        dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentBuildNumber"), NULL, NULL, (LPBYTE)wincomp, &dwCount);
                        if (dwRet != ERROR_SUCCESS) {
                            merror("Error reading 'CurrentBuildNumber' from Windows registry. (Error %u)",(unsigned int)dwRet);
                            snprintf(__wp, 63, " [Ver: %d.%d]", (unsigned int)winMajor, (unsigned int)winMinor);
                        }
                        else {
                            snprintf(__wp, 63, " [Ver: %d.%d.%s]", (unsigned int)winMajor, (unsigned int)winMinor, wincomp);
                        }
                    }
                    RegCloseKey(RegistryKey);
                }
                // Windows 6.2 or 6.3
                else {
                    dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentVersion"), NULL, NULL, (LPBYTE)winver, &dwCount);
                    if (dwRet != ERROR_SUCCESS) {
                        merror("Error reading 'Current Version' from Windows registry. (Error %u)",(unsigned int)dwRet);
                        snprintf(__wp, 63, " [Ver: 6.2]");
                    }
                    else {
                        dwCount = size;
                        dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentBuildNumber"), NULL, NULL, (LPBYTE)wincomp, &dwCount);
                        if (dwRet != ERROR_SUCCESS) {
                            merror("Error reading 'CurrentBuildNumber' from Windows registry. (Error %u)",(unsigned int)dwRet);
                            snprintf(__wp, 63, " [Ver: 6.2]");
                        }
                        else {
                            snprintf(__wp, 63, " [Ver: %s.%s]", winver,wincomp);
                        }
                        RegCloseKey(RegistryKey);
                    }
                }

                strncat(ret, __wp, ret_size - 1);
                ret_size -= strlen(ret) + 1;
            } else {
                char __wp[64];

                memset(__wp, '\0', 64);

                snprintf(__wp, 63, "%s [Ver: %i.%i.%d]",
                         osvi.szCSDVersion,
                         (int)osvi.dwMajorVersion,
                         (int)osvi.dwMinorVersion,
                         (int)osvi.dwBuildNumber & 0xFFFF );

                strncat(ret, __wp, ret_size - 1);
                ret_size -= strlen(__wp) + 1;
            }
            break;

        /* Test for Windows Me/98/95 */
        case VER_PLATFORM_WIN32_WINDOWS:
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0) {
                strncat(ret, "Microsoft Windows 95 ", ret_size - 1);
                ret_size -= strlen(ret) + 1;
            }

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10) {
                strncat(ret, "Microsoft Windows 98 ", ret_size - 1);
                ret_size -= strlen(ret) + 1;
            }

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90) {
                strncat(ret, "Microsoft Windows Millennium Edition",
                        ret_size - 1);

                ret_size -= strlen(ret) + 1;
            }
            break;

        case VER_PLATFORM_WIN32s:
            strncat(ret, "Microsoft Win32s", ret_size - 1);
            ret_size -= strlen(ret) + 1;
            break;
    }

    /* Add OSSEC-HIDS version */
    snprintf(os_v, 128, " - %s %s", __ossec_name, __ossec_version);
    strncat(ret, os_v, ret_size - 1);

    return (ret);
}


void w_ch_exec_dir() {
    TCHAR path[2048] = { 0 };
    DWORD last_error;
    int ret;

    /* Get full path to the directory this executable lives in */
    ret = GetModuleFileName(NULL, path, sizeof(path));

    /* Check for errors */
    if (!ret) {
        print_out(GMF_ERROR);

        /* Get last error */
        last_error = GetLastError();

        /* Look for errors */
        switch (last_error) {
        case ERROR_INSUFFICIENT_BUFFER:
            print_out(GMF_BUFF_ERROR, ret, sizeof(path));
            break;
        default:
            print_out(GMF_UNKN_ERROR, last_error);
        }

        exit(EXIT_FAILURE);
    }

    /* Remove file name from path */
    PathRemoveFileSpec(path);

    /* Move to correct directory */
    if (chdir(path)) {
        print_out(CHDIR_ERROR, path, errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

#endif /* WIN32 */


int rmdir_ex(const char *name) {
    if (rmdir(name) == 0) {
        return 0;
    }

    switch (errno) {
    case ENOTDIR:   // Not a directory

#ifdef WIN32
    case EINVAL:    // Not a directory
#endif
        return unlink(name);

#if EEXIST != ENOTEMPTY
    case EEXIST:
#endif
    case ENOTEMPTY: // Directory not empty
        // Erase content and try to erase again
        return cldir_ex(name) || rmdir(name) ? -1 : 0;

    default:
        return -1;
    }
}


int cldir_ex(const char *name) {
    return cldir_ex_ignore(name, NULL);
}


int cldir_ex_ignore(const char * name, const char ** ignore) {
    DIR *dir;
    struct dirent *dirent = NULL;
    char path[PATH_MAX + 1];

    // Erase content

    dir = opendir(name);

    if (!dir) {
        return -1;
    }

    while (dirent = readdir(dir), dirent) {
        // Skip "." and ".."
        if ((dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) || w_str_in_array(dirent->d_name, ignore)) {
            continue;
        }

        if (snprintf(path, PATH_MAX + 1, "%s/%s", name, dirent->d_name) > PATH_MAX) {
            closedir(dir);
            return -1;
        }

        if (rmdir_ex(path) < 0) {
            closedir(dir);
            return -1;
        }
    }

    return closedir(dir);
}


int TempFile(File *file, const char *source, int copy) {
    FILE *fp_src;
    int fd;
    char template[OS_FLSIZE + 1];
    mode_t old_mask;

    snprintf(template, OS_FLSIZE, "%s.XXXXXX", source);
    old_mask = umask(0177);

    fd = mkstemp(template);
    umask(old_mask);

    if (fd < 0) {
        return -1;
    }

    fp_src = fopen(source,"r");

#ifndef WIN32
    struct stat buf;

    if (stat(source, &buf) == 0) {
        if (fchmod(fd, buf.st_mode) < 0) {
            if (fp_src) {
                fclose(fp_src);
            }
            close(fd);
            unlink(template);
            return -1;
        }
    } else {
        mdebug1(FSTAT_ERROR, source, errno, strerror(errno));
    }

#endif

    if (file->fp = fdopen(fd, "w"), !file->fp) {
        if (fp_src) {
            fclose(fp_src);
        }
        close(fd);
        unlink(template);
        return -1;
    }

    if (copy) {
        size_t count_r;
        size_t count_w;
        char buffer[4096];

        if (fp_src) {
            while (!feof(fp_src)) {
                count_r = fread(buffer, 1, 4096, fp_src);

                if (ferror(fp_src)) {
                    fclose(fp_src);
                    fclose(file->fp);
                    unlink(template);
                    return -1;
                }

                count_w = fwrite(buffer, 1, count_r, file->fp);

                if (count_w != count_r || ferror(file->fp)) {
                    fclose(fp_src);
                    fclose(file->fp);
                    unlink(template);
                    return -1;
                }
            }
        }
    }

    if (fp_src) {
        fclose(fp_src);
    }

    file->name = strdup(template);
    return 0;
}


int OS_MoveFile(const char *src, const char *dst) {
    FILE *fp_src;
    FILE *fp_dst;
    size_t count_r;
    size_t count_w;
    char buffer[4096];
    int status = 0;

    if (rename(src, dst) == 0) {
        return 0;
    }

    mdebug1("Couldn't rename %s: %s", dst, strerror(errno));

    fp_src = fopen(src, "r");

    if (!fp_src) {
        merror("Couldn't open file '%s'", src);
        return -1;
    }

    fp_dst = fopen(dst, "w");

    if (!fp_dst) {
        merror("Couldn't open file '%s'", dst);
        fclose(fp_src);
        unlink(src);
        return -1;
    }

    while (!feof(fp_src)) {
        count_r = fread(buffer, 1, 4096, fp_src);

        if (ferror(fp_src)) {
            merror("Couldn't read file '%s'", src);
            status = -1;
            break;
        }

        count_w = fwrite(buffer, 1, count_r, fp_dst);

        if (count_w != count_r || ferror(fp_dst)) {
            merror("Couldn't write file '%s'", dst);
            status = -1;
            break;
        }
    }

    fclose(fp_src);
    fclose(fp_dst);
    return status ? status : unlink(src);
}


int w_copy_file(const char *src, const char *dst, char mode, char * message, int silent) {
    FILE *fp_src;
    FILE *fp_dst;
    size_t count_r;
    size_t count_w;
    char buffer[4096];
    int status = 0;

    fp_src = fopen(src, "r");

    if (!fp_src) {
        if(!silent) {
            merror("At w_copy_file(): Couldn't open file '%s'", src);
        }
        return -1;
    }

    /* Append to file */
    if (mode == 'a') {
        fp_dst = fopen(dst, "a");
    }
    else {
        fp_dst = fopen(dst, "w");
    }


    if (!fp_dst) {
        if (!silent) {
            merror("At w_copy_file(): Couldn't open file '%s'", dst);
        }
        fclose(fp_src);
        return -1;
    }

    /* Write message to the destination file */
    if (message) {
        count_r = strlen(message);
        count_w = fwrite(message, 1, count_r, fp_dst);

        if (count_w != count_r || ferror(fp_dst)) {
            if (!silent) {
                merror("Couldn't write file '%s'", dst);
            }
            status = -1;
            fclose(fp_src);
            fclose(fp_dst);
            return status;
        }
    }

    while (!feof(fp_src)) {
        count_r = fread(buffer, 1, 4096, fp_src);

        if (ferror(fp_src)) {
            if (!silent) {
                merror("Couldn't read file '%s'", src);
            }
            status = -1;
            break;
        }

        count_w = fwrite(buffer, 1, count_r, fp_dst);

        if (count_w != count_r || ferror(fp_dst)) {
            if (!silent) {
                merror("Couldn't write file '%s'", dst);
            }
            status = -1;
            break;
        }
    }

    fclose(fp_src);
    fclose(fp_dst);
    return status;
}


int mkdir_ex(const char * path) {
    char sep;
    char * temp = strdup(path);
    char * psep;
    char * next;

#ifndef WIN32
    for (next = temp; psep = strchr(next, '/'), psep; next = psep + 1) {
#else
    for (next = temp; psep = strchr(next, '/'), psep || (psep = strchr(next, '\\'), psep); next = psep + 1) {
#endif

        sep = *psep;
        *psep = '\0';

        if (*temp && mkdir(temp, 0770) < 0) {
            switch (errno) {
            case EEXIST:
                if (IsDir(temp) < 0) {
                    merror("Couldn't make dir '%s': not a directory.", temp);
                    free(temp);
                    return -1;
                }

                break;

            case EISDIR:
                break;

            default:
                merror("Couldn't make dir '%s': %s", temp, strerror(errno));
                free(temp);
                return -1;
            }
        }

        *psep = sep;
    }

    free(temp);

    if (mkdir(path, 0770) < 0) {
        switch (errno) {
        case EEXIST:
            if (IsDir(path) < 0) {
                merror("Couldn't make dir '%s': not a directory.", path);
                return -1;
            }

            break;

        case EISDIR:
            break;

        default:
            merror("Couldn't make dir '%s': %s", path, strerror(errno));
            return -1;
        }
    }

    return 0;
}


int w_ref_parent_folder(const char * path) {
    const char * str;
    char * ptr;

    switch (path[0]) {
    case '\0':
        return 0;

    case '.':
        switch (path[1]) {
        case '\0':
            return 0;

        case '.':
            switch (path[2]) {
            case '\0':
                return 1;

            case '/':
#ifdef WIN32
            case '\\':
#endif
                return 1;
            }
        }
    }

#ifdef WIN32
    for (str = path; ptr = strstr(str, "/.."), ptr || (ptr = strstr(str, "\\.."), ptr); str = ptr + 3) {
        if (ptr[3] == '\0' || ptr[3] == '/' || ptr[3] == '\\') {
#else
    for (str = path; ptr = strstr(str, "/.."), ptr; str = ptr + 3) {
        if (ptr[3] == '\0' || ptr[3] == '/') {
#endif
            return 1;
        }
    }

    return 0;
}


cJSON* getunameJSON()
{
    os_info *read_info;
    cJSON* root = cJSON_CreateObject();

#ifndef WIN32
    if (read_info = get_unix_version(), read_info) {
#else
    if (read_info = get_win_version(), read_info) {
#endif
        if (read_info->os_name && (strcmp(read_info->os_name, "unknown") != 0)){
            cJSON_AddStringToObject(root, "os_name", read_info->os_name);
        }
        if (read_info->os_major){
            cJSON_AddStringToObject(root, "os_major", read_info->os_major);
        }
        if (read_info->os_minor){
            cJSON_AddStringToObject(root, "os_minor", read_info->os_minor);
        }
        if (read_info->os_patch){
            cJSON_AddStringToObject(root, "os_patch", read_info->os_patch);
        }
        if (read_info->os_build){
            cJSON_AddStringToObject(root, "os_build", read_info->os_build);
        }
        if (read_info->os_version && (strcmp(read_info->os_version, "unknown") != 0)){
            cJSON_AddStringToObject(root, "os_version", read_info->os_version);
        }
        if (read_info->os_codename){
            cJSON_AddStringToObject(root, "os_codename", read_info->os_codename);
        }
        if (read_info->os_platform){
            cJSON_AddStringToObject(root, "os_platform", read_info->os_platform);
        }
        if (read_info->sysname){
            cJSON_AddStringToObject(root, "sysname", read_info->sysname);
        }
        if (read_info->nodename && (strcmp(read_info->nodename, "unknown") != 0)){
            cJSON_AddStringToObject(root, "hostname", read_info->nodename);
        }
        if (read_info->release){
            cJSON_AddStringToObject(root, "release", read_info->release);
        }
        if (read_info->version){
            cJSON_AddStringToObject(root, "version", read_info->version);
        }
        if (read_info->machine && (strcmp(read_info->machine, "unknown") != 0)){
            cJSON_AddStringToObject(root, "architecture", read_info->machine);
        }
        if (read_info->os_release){
            cJSON_AddStringToObject(root, "os_release", read_info->os_release);
        }

        free_osinfo(read_info);
        return root;
    }
    else
        return NULL;
}


wino_t get_fp_inode(FILE * fp) {
#ifdef WIN32
    int fd;
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION fileInfo;

    if (fd = _fileno(fp), fd < 0) {
        return -1;
    }

    if (h = (HANDLE)_get_osfhandle(fd), h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    return GetFileInformationByHandle(h, &fileInfo) ? (wino_t)fileInfo.nFileIndexHigh << 32 | fileInfo.nFileIndexLow : (wino_t)-1;

#else

    struct stat buf;
    int fd;
    return fd = fileno(fp), fd < 0 ? (wino_t)-1 : fstat(fd, &buf) ? (wino_t)-1 : buf.st_ino;
#endif
}


long get_fp_size(FILE * fp) {
    long offset;
    long size;

    // Get initial position

    if (offset = ftell(fp), offset < 0) {
        return -1;
    }

    // Move to end

    if (fseek(fp, 0, SEEK_END) < 0) {
        return -1;
    }

    // Get ending position

    if (size = ftell(fp), size < 0) {
        return -1;
    }

    // Restore original offset

    if (fseek(fp, offset, SEEK_SET) < 0) {
        return -1;
    }

    return size;
}

static int qsort_strcmp(const void *s1, const void *s2) {
    return strcmp(*(const char **)s1, *(const char **)s2);
}


char ** wreaddir(const char * name) {
    DIR * dir;
    struct dirent * dirent = NULL;
    char ** files;
    unsigned int i = 0;

    if (dir = opendir(name), !dir) {
        return NULL;
    }

    os_malloc(sizeof(char *), files);

    while (dirent = readdir(dir), dirent) {
        // Skip "." and ".."
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        os_realloc(files, (i + 2) * sizeof(char *), files);
        if(!files){
           merror_exit(MEM_ERROR, errno, strerror(errno));
        }
        files[i++] = strdup(dirent->d_name);
    }

    files[i] = NULL;
    qsort(files, i, sizeof(char *), qsort_strcmp);
    closedir(dir);
    return files;
}


FILE * wfopen(const char * pathname, const char * mode) {
#ifdef WIN32
    HANDLE hFile;
    DWORD dwDesiredAccess = 0;
    const DWORD dwShareMode = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwCreationDisposition = 0;
    const DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    int flags = _O_TEXT;
    int fd;
    FILE * fp;
    int i;

    for (i = 0; mode[i]; ++i) {
        switch (mode[i]) {
        case '+':
            dwDesiredAccess |= GENERIC_WRITE | GENERIC_READ;
            flags &= ~_O_RDONLY;
            break;
        case 'a':
            dwDesiredAccess = GENERIC_WRITE;
            dwCreationDisposition = OPEN_ALWAYS;
            flags = _O_CREAT;
            break;
        case 'b':
            flags &= ~_O_TEXT;
            break;
        case 'r':
            dwDesiredAccess = GENERIC_READ;
            dwCreationDisposition = OPEN_EXISTING;
            flags |= _O_RDONLY;
            break;
        case 't':
            flags |= _O_TEXT;
            break;
        case 'w':
            dwDesiredAccess = GENERIC_WRITE;
            dwCreationDisposition = CREATE_ALWAYS;
        }
    }

    if (!(dwDesiredAccess && dwCreationDisposition)) {
        errno = EINVAL;
        return NULL;
    }

    hFile = CreateFile(pathname, dwDesiredAccess, dwShareMode, NULL, dwCreationDisposition, dwFlagsAndAttributes, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    if (fd = _open_osfhandle((intptr_t)hFile, flags), fd < 0) {
        CloseHandle(hFile);
        return NULL;
    }

    if (fp = _fdopen(fd, mode), fp == NULL) {
        CloseHandle(hFile);
        return NULL;
    }

    return fp;

#else
    return fopen(pathname, mode);
#endif
}


int w_remove_line_from_file(char *file, int line){
    FILE *fp_src;
    FILE *fp_dst;
    size_t count_w;
    char buffer[OS_SIZE_65536 + 1];
    char destination[PATH_MAX] = {0};

    fp_src = fopen(file, "r");

    if (!fp_src) {
        merror("At remove_line_from_file(): Couldn't open file '%s'", file);
        return -1;
    }

    snprintf(destination, PATH_MAX, "%s.back", file);

    /* Write to file */
    fp_dst = fopen(destination, "w");

    if (!fp_dst) {
        mdebug1("At remove_line_from_file(): Couldn't open file '%s'", destination);
        fclose(fp_src);
        return -1;
    }

    /* Write message to the destination file */
    int i = 0;
    while (fgets(buffer, OS_SIZE_65536 + 1, fp_src) != NULL) {

        if(i != line){
            count_w = fwrite(buffer, 1, strlen(buffer) , fp_dst);

            if (count_w != strlen(buffer) || ferror(fp_dst)) {
                merror("At remove_line_from_file(): Couldn't write file '%s'", destination);
                break;
            }
        }
        i++;
    }

    fclose(fp_src);
    fclose(fp_dst);

    return w_copy_file(destination, file, 'w', NULL, 0);
}


int w_compress_gzfile(const char *filesrc, const char *filedst) {
    FILE *fd;
    gzFile gz_fd;
    char *buf;
    int len;
    int err;

    /* Set umask */
    umask(0027);

    /* Read file */
    fd = wfopen(filesrc, "rb");
    if (!fd) {
        merror("in w_compress_gzfile(): fopen error %s (%d):'%s'",
                filesrc,
                errno,
                strerror(errno));
        return -1;
    }

    /* Open compressed file */
    gz_fd = gzopen(filedst, "w");
    if (!gz_fd) {
        fclose(fd);
        merror("in w_compress_gzfile(): gzopen error %s (%d):'%s'",
                filedst,
                errno,
                strerror(errno));
        return -1;
    }

    os_calloc(OS_SIZE_8192 + 1, sizeof(char), buf);
    for (;;) {
        len = fread(buf, 1, OS_SIZE_8192, fd);
        if (len <= 0) {
            break;
        }

        if (gzwrite(gz_fd, buf, (unsigned)len) != len) {
            merror("in w_compress_gzfile(): Compression error: %s",
                    gzerror(gz_fd, &err));
            fclose(fd);
            gzclose(gz_fd);
            os_free(buf);
            return -1;
        }
    }

    fclose(fd);
    gzclose(gz_fd);
    os_free(buf);
    return 0;
}


int w_uncompress_gzfile(const char *gzfilesrc, const char *gzfiledst) {
    FILE *fd;
    gzFile gz_fd;
    char *buf;
    int len;
    int err;
    struct stat statbuf;

#ifdef WIN32
    /* Win32 does not have lstat */
    if (stat(gzfilesrc, &statbuf) < 0)
#else
    if (lstat(gzfilesrc, &statbuf) < 0)
#endif
    {
        return -1;
    }
    /* Set umask */
    umask(0027);

    /* Read file */
    fd = fopen(gzfiledst, "wb");
    if (!fd) {
        merror("in w_uncompress_gzfile(): fopen error %s (%d):'%s'",
                gzfiledst,
                errno,
                strerror(errno));
        return -1;
    }

    /* Open compressed file */
    gz_fd = gzopen(gzfilesrc, "rb");
    if (!gz_fd) {
        merror("in w_uncompress_gzfile(): gzopen error %s (%d):'%s'",
                gzfilesrc,
                errno,
                strerror(errno));
        fclose(fd);
        return -1;
    }

    os_calloc(OS_SIZE_8192, sizeof(char), buf);
    do {
        len = gzread(gz_fd, buf, OS_SIZE_8192);

        if (len > 0) {
            fwrite(buf, 1, len, fd);
            buf[0] = '\0';
        }
    } while (len == OS_SIZE_8192);

    if (!gzeof(gz_fd)) {
        const char * gzerr = gzerror(gz_fd, &err);
        if (err) {
            merror("in w_uncompress_gzfile(): gzread error: '%s'", gzerr);
            fclose(fd);
            gzclose(gz_fd);
            os_free(buf);
            return -1;
        }
    }

    os_free(buf);
    fclose(fd);
    gzclose(gz_fd);

    return 0;
}


int is_ascii_utf8(const char * file, unsigned int max_lines_ascii, unsigned int max_chars_utf8) {
    int is_ascii = 1;
    int retval = 0;
    char *buffer = NULL;
    unsigned int lines_read_ascii = 0;
    unsigned int chars_read_utf8 = 0;
    fpos_t begin;
    FILE *fp;

    fp = fopen(file, "r");

    if (!fp) {
        mdebug1(OPEN_UNABLE, file);
        retval = 1;
        goto end;
    }

    fgetpos(fp, &begin);

    os_calloc(OS_MAXSTR + 1, sizeof(char), buffer);

    /* ASCII */
    while (fgets(buffer, OS_MAXSTR, fp)) {
        int i;
        unsigned char *c = (unsigned char *)buffer;

        if (lines_read_ascii >= max_lines_ascii) {
            break;
        }

        lines_read_ascii++;

        for (i = 0; i < OS_MAXSTR; i++) {
            if( c[i] >= 0x80 ) {
                is_ascii = 0;
                break;
            }
        }

        if (!is_ascii) {
            break;
        }
    }

    if (is_ascii) {
        goto end;
    }

    /* UTF-8 */
    fsetpos(fp, &begin);
    unsigned char b[4] = {0};
    size_t nbytes = 0;

    while (nbytes = fread(b, sizeof(char), 4, fp), nbytes) {

        if (chars_read_utf8 >= max_chars_utf8) {
            break;
        }

        chars_read_utf8++;

        /* Check for UTF-8 BOM */
        if (b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) {
            if (fseek(fp, -1, SEEK_CUR) < 0) {
                merror(FSEEK_ERROR, file, errno, strerror(errno));
            }
            goto next;
        }

        /* Valid ASCII */
        if (b[0] == 0x09 || b[0] == 0x0A || b[0] == 0x0D || (0x20 <= b[0] && b[0] <= 0x7E)) {
            if (fseek(fp, -nbytes + 1, SEEK_CUR) < 0) {
                merror(FSEEK_ERROR, file, errno, strerror(errno));
            }
            goto next;
        }

        /* Two bytes UTF-8 */
        if (b[0] >= 0xC2 && b[0] <= 0xDF) {
            if (b[1] >= 0x80 && b[1] <= 0xBF) {
                if (fseek(fp, -2, SEEK_CUR) < 0) {
                    merror(FSEEK_ERROR, file, errno, strerror(errno));
                }
                goto next;
            }
        }

        /* Exclude overlongs */
        if ( b[0] == 0xE0 ) {
            if ( b[1] >= 0xA0 && b[1] <= 0xBF) {
                if ( b[2] >= 0x80 && b[2] <= 0xBF ) {
                    if (fseek(fp, -1, SEEK_CUR) < 0 ) {
                        merror(FSEEK_ERROR, file, errno, strerror(errno));
                    }
                    goto next;
                }
            }
        }

        /* Three bytes UTF-8 */
        if ((b[0] >= 0xE1 && b[0] <= 0xEC) || b[0] == 0xEE || b[0] == 0xEF) {
            if (b[1] >= 0x80 && b[1] <= 0xBF) {
                if (b[2] >= 0x80 && b[2] <= 0xBF) {
                    if (fseek(fp, -1, SEEK_CUR) < 0 ) {
                        merror(FSEEK_ERROR, file, errno, strerror(errno));
                    }
                    goto next;
                }
            }
        }

        /* Exclude surrogates */
        if (b[0] == 0xED) {
            if ( b[1] >= 0x80 && b[1] <= 0x9F) {
                if ( b[2] >= 0x80 && b[2] <= 0xBF) {
                    if (fseek(fp, -1, SEEK_CUR) < 0 ) {
                        merror(FSEEK_ERROR, file, errno, strerror(errno));
                    }
                    goto next;
                }
            }
        }

        /* Four bytes UTF-8 plane 1-3 */
        if (b[0] == 0xF0) {
            if (b[1] >= 0x90 && b[1] <= 0xBF) {
                if (b[2] >= 0x80 && b[2] <= 0xBF) {
                    if (b[3] >= 0x80 && b[3] <= 0xBF) {
                        goto next;
                    }
                }
            }
        }

        /* Four bytes UTF-8 plane 4-15*/
        if (b[0] >= 0xF1 && b[0] <= 0xF3) {
            if (b[1] >= 0x80 && b[1] <= 0xBF) {
                if (b[2] >= 0x80 && b[2] <= 0xBF) {
                    if (b[3] >= 0x80 && b[3] <= 0xBF) {
                        goto next;
                    }
                }
            }
        }

        /* Four bytes UTF-8 plane 16 */
        if (b[0] == 0xF4) {
            if (b[1] >= 0x80 && b[1] <= 0x8F) {
                if (b[2] >= 0x80 && b[2] <= 0xBF) {
                    if (b[3] >= 0x80 && b[3] <= 0xBF) {
                        goto next;
                    }
                }
            }
        }

        retval = 1;
        goto end;

next:
        memset(b, 0, 4);
        continue;
    }

end:
    if (fp) {
        fclose(fp);
    }
    os_free(buffer);

    return retval;
}


int is_usc2(const char * file) {
    int retval = 0;
    FILE *fp;

    fp = fopen(file, "r");

    if (!fp) {
        mdebug1(OPEN_UNABLE, file);
        retval = 1;
        goto end;
    }

    /* UCS-2 */
    unsigned char b[2] = {0};
    size_t nbytes = 0;

    while (nbytes = fread(b, sizeof(char), 2, fp), nbytes) {

        /* Check for UCS-2 LE BOM */
        if (b[0] == 0xFF && b[1] == 0xFE) {
            retval = UCS2_LE;
            goto end;
        }

        /* Check for UCS-2 BE BOM */
        if (b[0] == 0xFE && b[1] == 0xFF) {
            retval = UCS2_BE;
            goto end;
        }

        retval = 0;
        goto end;
    }

end:
    if (fp) {
        fclose(fp);
    }

    return retval;
}

#ifdef WIN32
DWORD FileSizeWin(const char * file) {
    HANDLE h1;
    BY_HANDLE_FILE_INFORMATION lpFileInfo;

    h1 = CreateFile(file, GENERIC_READ,
                    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h1 == INVALID_HANDLE_VALUE) {
        merror(FILE_ERROR, file);
    } else if (GetFileInformationByHandle(h1, &lpFileInfo) == 0) {
        CloseHandle(h1);
        merror(FILE_ERROR, file);
    } else {
        CloseHandle(h1);
        return lpFileInfo.nFileSizeHigh + lpFileInfo.nFileSizeLow;
    }

    return -1;
}

float DirSize(const char *path) {
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;
    float folder_size = 0.0;
    float file_size = 0.0;

    char sPath[2048];

    // Specify a file mask. *.* = We want everything!
    sprintf(sPath, "%s\\*.*", path);

    if ((hFind = FindFirstFile(sPath, &fdFile)) == INVALID_HANDLE_VALUE) {
        merror(FILE_ERROR, path);
        return 0;
    }

    do {
        if (strcmp(fdFile.cFileName, ".") != 0 && strcmp(fdFile.cFileName, "..") != 0) {
            // Build up our file path using the passed in
            //  [path] and the file/foldername we just found:
            sprintf(sPath, "%s\\%s", path, fdFile.cFileName);

            if (fdFile.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY) {
                folder_size += DirSize(sPath);
            }
            else {
                if (file_size = FileSizeWin(sPath), file_size != -1) {
                    folder_size += file_size;
                }
            }
        }
    } while (FindNextFile(hFind, &fdFile));

    FindClose(hFind);

    return folder_size;
}

#endif


int64_t w_ftell (FILE *x) {

#ifndef WIN32
    int64_t z = ftell(x);
#else
    int64_t z = _ftelli64(x);
#endif

    if (z < 0)  {
        merror("Ftell function failed due to [(%d)-(%s)]", errno, strerror(errno));
        return -1;
    } else {
        return z;
    }
}

/* Prevent children processes from inheriting a file pointer */
void w_file_cloexec(__attribute__((unused)) FILE * fp) {
#ifndef WIN32
    w_descriptor_cloexec(fileno(fp));
#endif
}

/* Prevent children processes from inheriting a file descriptor */
void w_descriptor_cloexec(__attribute__((unused)) int fd){
#ifndef WIN32
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        mwarn("Cannot set close-on-exec flag to the descriptor: %s (%d)", strerror(errno), errno);
    }
#endif
}

// Add a trailing separator to a path string
int trail_path_separator(char * dest, const char * src, size_t n) {
    const char STR_SEPARATOR[] = { PATH_SEP, '\0' };
    if (strlen(src) == 0) return 0;
    return snprintf(dest, n, "%s%s", src, src[strlen(src) - 1] == PATH_SEP ? "" : STR_SEPARATOR);
}

// Check if a path is absolute
bool isabspath(const char * path) {
#ifdef WIN32
    return strlen(path) >= 3 && isalpha(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/');
#else
    return path[0] == '/';
#endif
}

// Unify path separators (slashes) for Windows paths

void win_path_backslash(char * path) {
    for (char * c = strchr(path, '/'); c != NULL; c = strchr(c + 1, '/')) {
        *c = '\\';
    }
}

// Get an absolute path
char * abspath(const char * path, char * buffer, size_t size) {
    // If the path is already absolute, copy and return
    if (isabspath(path)) {
        strncpy(buffer, path, size);
        buffer[size - 1] = '\0';
#ifdef WIN32
        buffer[0] = tolower(buffer[0]);
#endif
        return buffer;
    }

    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        return NULL;
    }

#ifdef WIN32
    size_t len;

    switch (path[0]) {
    case '/':
    case '\\':
        // Starts with \: current drive's root
        if (snprintf(buffer, size, "%c:%s", cwd[0], path) >= (int)size) {
            return NULL;
        }

        break;

    default:
        // Remove root's backslash: "C:\" must be "C:"
        len = strlen(cwd);
        cwd[len - 1] = cwd[len - 1] == '\\' ? '\0' : cwd[len - 1];

        if (snprintf(buffer, size, "%s\\%s", cwd, path) >= (int)size) {
            return NULL;
        }
    }

    win_path_backslash(buffer);
#else
    if (snprintf(buffer, size, "%s/%s", strcmp(cwd, "/") == 0 ? "" : cwd, path) >= (int)size) {
        return NULL;
    }
#endif

    return buffer;
}

/* Return the content of a file from a given path */
char * w_get_file_content(const char * path, int max_size) {
    FILE * fp = NULL;
    char * buffer = NULL;
    long size;
    size_t read;

    // Check if path is NULL
    if (path == NULL) {
        mdebug1("Cannot open NULL path");
        goto end;
    }

    // Load file
    if (fp = fopen(path, "r"), !fp) {
        mdebug1(FOPEN_ERROR, path, errno, strerror(errno));
        goto end;
    }

    // Get file size
    if (size = get_fp_size(fp), size < 0) {
        mdebug1(FSEEK_ERROR, path, errno, strerror(errno));
        goto end;
    }

    // Check file size limit
    if (size > max_size) {
        mdebug1("Cannot load file '%s': it exceeds %i MiB", path, (max_size / (1024 * 1024)));
        goto end;
    }

    // Allocate memory
    os_malloc(size + 1, buffer);

    // Get file content
    if (read = fread(buffer, 1, size, fp), read != (size_t)size && !feof(fp)) {
        mdebug1(FREAD_ERROR, path, errno, strerror(errno));
        os_free(buffer);
        goto end;
    }

    buffer[size] = '\0';

end:
    if (fp) {
        fclose(fp);
    }

    return buffer;
}

/* Check if a file is gzip compressed. */
int w_is_compressed_gz_file(const char * path) {
    unsigned char buf[2];
    int retval = 0;
    FILE *fp;

    fp = fopen(path, "rb");

    /* Magic number: 1f 8b */
    if (fp && fread(buf, 1, 2, fp) == 2) {
        if (buf[0] == 0x1f && buf[1] == 0x8b) {
            retval = 1;
        }
    }

    if (fp) {
        fclose(fp);
    }

    return retval;
}

/* Check if a file is bzip2 compressed. */
int w_is_compressed_bz2_file(const char * path) {
    unsigned char buf[3];
    int retval = 0;
    FILE *fp;

    fp = fopen(path, "rb");

    /* Magic number: 42 5a 68 */
    if (fp && fread(buf, 1, 3, fp) == 3) {
        if (buf[0] == 0x42 && buf[1] == 0x5a && buf[2] == 0x68) {
            retval = 1;
        }
    }

    if (fp) {
        fclose(fp);
    }

    return retval;
}

#ifndef CLIENT

int w_uncompress_bz2_gz_file(const char * path, const char * dest) {
    int result = 1;

    if (w_is_compressed_bz2_file(path)) {
        result = bzip2_uncompress(path, dest);
    }

    if (w_is_compressed_gz_file(path)) {
        result = w_uncompress_gzfile(path, dest);
    }

    if (!result) {
        mdebug1("The file '%s' was successfully uncompressed into '%s'", path, dest);
    }

    return result;
}
#endif
