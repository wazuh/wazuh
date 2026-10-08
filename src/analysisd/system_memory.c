/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "system_memory.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

#define CGROUP_V1_MEMORY_CONTROLLER "memory"
#define CGROUP_V1_MEMORY_LIMIT      "memory.limit_in_bytes"
#define CGROUP_V2_MEMORY_LIMIT      "memory.max"

STATIC uint64_t w_read_cgroup_limit(const char *path);
STATIC uint64_t w_lowest_cgroup_limit(const char *base, const char *cgroup_path, const char *limit_file);
STATIC bool w_cgroup_has_controller(const char *controllers, const char *controller);
STATIC bool w_find_cgroup_mount(const char *proc_mountinfo, bool v1, const char *cgroup_path, char *mount_point,
                                size_t mount_point_size, const char **relative_path);
STATIC void w_unescape_mountinfo(char *field);

uint64_t w_get_memory_size(bool *cgroup_limited) {

    uint64_t physical = w_get_physical_memory();
    uint64_t cgroup = w_get_cgroup_memory_limit(W_PROC_SELF_CGROUP, W_PROC_SELF_MOUNTINFO, "");

    if (cgroup_limited != NULL) {
        *cgroup_limited = false;
    }

    if (cgroup > 0 && (physical == 0 || cgroup < physical)) {
        if (cgroup_limited != NULL) {
            *cgroup_limited = true;
        }
        return cgroup;
    }

    return physical;
}

uint64_t w_get_physical_memory(void) {

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);

    if (pages <= 0 || page_size <= 0) {
        return 0;
    }

    return (uint64_t)pages * (uint64_t)page_size;
}

uint64_t w_get_cgroup_memory_limit(const char *proc_cgroup, const char *proc_mountinfo, const char *fs_root) {

    char line[PATH_MAX + OS_SIZE_256];
    char v1_path[PATH_MAX] = "";
    char v2_path[PATH_MAX] = "";
    char mount_point[PATH_MAX];
    char base[PATH_MAX * 2];
    const char *relative_path;
    bool v1 = false;
    bool v2 = false;
    FILE *fp;

    if (fp = wfopen(proc_cgroup, "r"), fp == NULL) {
        return 0;
    }

    /* Each line is "hierarchy-ID:controller-list:cgroup-path". cgroup v2 has an empty controller list */
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *controllers;
        char *path;

        line[strcspn(line, "\n")] = '\0';

        if (controllers = strchr(line, ':'), controllers == NULL) {
            continue;
        }
        controllers++;

        if (path = strchr(controllers, ':'), path == NULL) {
            continue;
        }
        *path++ = '\0';

        if (*controllers == '\0') {
            snprintf(v2_path, sizeof(v2_path), "%s", path);
            v2 = true;
        } else if (w_cgroup_has_controller(controllers, CGROUP_V1_MEMORY_CONTROLLER)) {
            snprintf(v1_path, sizeof(v1_path), "%s", path);
            v1 = true;
        }
    }

    fclose(fp);

    /* On hybrid systems, the memory controller is still in cgroup v1 */
    if (v1 && w_find_cgroup_mount(proc_mountinfo, true, v1_path, mount_point, sizeof(mount_point), &relative_path)) {
        snprintf(base, sizeof(base), "%s%s", fs_root, mount_point);
        return w_lowest_cgroup_limit(base, relative_path, CGROUP_V1_MEMORY_LIMIT);
    }

    if (v2 && w_find_cgroup_mount(proc_mountinfo, false, v2_path, mount_point, sizeof(mount_point), &relative_path)) {
        snprintf(base, sizeof(base), "%s%s", fs_root, mount_point);
        return w_lowest_cgroup_limit(base, relative_path, CGROUP_V2_MEMORY_LIMIT);
    }

    return 0;
}

/* Find the mount of the cgroup v1 memory controller or of the cgroup v2 hierarchy that contains cgroup_path.
 * A mount can expose a subtree of the hierarchy: relative_path is set to the part of cgroup_path below the root
 * of the mount. Each line of mountinfo is
 * "ID parent major:minor root mount-point options [optional fields] - type source super-options".
 */
STATIC bool w_find_cgroup_mount(const char *proc_mountinfo, bool v1, const char *cgroup_path, char *mount_point,
                                size_t mount_point_size, const char **relative_path) {

    char line[PATH_MAX * 2 + OS_SIZE_1024];
    bool found = false;
    FILE *fp;

    if (fp = wfopen(proc_mountinfo, "r"), fp == NULL) {
        return false;
    }

    while (!found && fgets(line, sizeof(line), fp) != NULL) {
        char *fields[5];
        char *separator;
        char *save = NULL;
        char *type;
        char *options;
        size_t root_length;
        int i;

        line[strcspn(line, "\n")] = '\0';

        if (separator = strstr(line, " - "), separator == NULL) {
            continue;
        }
        *separator = '\0';

        /* Filesystem type, source and super options follow the separator */
        if (type = strtok_r(separator + 3, " ", &save), type == NULL || strtok_r(NULL, " ", &save) == NULL
            || (options = strtok_r(NULL, " ", &save), options == NULL)) {
            continue;
        }

        if (v1 ? strcmp(type, "cgroup") != 0 || !w_cgroup_has_controller(options, CGROUP_V1_MEMORY_CONTROLLER)
               : strcmp(type, "cgroup2") != 0) {
            continue;
        }

        /* ID, parent, major:minor, root and mount point */
        save = NULL;
        for (i = 0; i < 5; i++) {
            if (fields[i] = strtok_r(i == 0 ? line : NULL, " ", &save), fields[i] == NULL) {
                break;
            }
        }
        if (i < 5) {
            continue;
        }

        w_unescape_mountinfo(fields[3]);
        w_unescape_mountinfo(fields[4]);

        /* The cgroup must be inside the mounted subtree */
        root_length = strcmp(fields[3], "/") == 0 ? 0 : strlen(fields[3]);
        if (strncmp(cgroup_path, fields[3], root_length) != 0
            || (cgroup_path[root_length] != '/' && cgroup_path[root_length] != '\0')) {
            continue;
        }

        snprintf(mount_point, mount_point_size, "%s", fields[4]);
        *relative_path = cgroup_path[root_length] == '\0' ? "/" : cgroup_path + root_length;
        found = true;
    }

    fclose(fp);
    return found;
}

/* mountinfo escapes spaces, tabs, newlines and backslashes as octal sequences such as \040 */
STATIC void w_unescape_mountinfo(char *field) {

    char *read = field;
    char *write = field;

    while (*read != '\0') {
        if (read[0] == '\\' && read[1] >= '0' && read[1] <= '7' && read[2] >= '0' && read[2] <= '7'
            && read[3] >= '0' && read[3] <= '7') {
            *write++ = (char)((read[1] - '0') * 64 + (read[2] - '0') * 8 + (read[3] - '0'));
            read += 4;
        } else {
            *write++ = *read++;
        }
    }

    *write = '\0';
}

/* Check the lowest limit from the cgroup of the process up to the root of the mount. base is the mount point and
 * cgroup_path is relative to it.
 */
STATIC uint64_t w_lowest_cgroup_limit(const char *base, const char *cgroup_path, const char *limit_file) {

    char dir[PATH_MAX];
    char file[PATH_MAX * 2];
    uint64_t lowest = 0;

    snprintf(dir, sizeof(dir), "%s", cgroup_path);

    while (true) {
        uint64_t limit;
        char *slash;

        /* The root is "/": avoid a double slash */
        snprintf(file, sizeof(file), "%s%s/%s", base, strcmp(dir, "/") == 0 ? "" : dir, limit_file);

        limit = w_read_cgroup_limit(file);
        if (limit > 0 && (lowest == 0 || limit < lowest)) {
            lowest = limit;
        }

        if (slash = strrchr(dir, '/'), slash == NULL || strcmp(dir, "/") == 0) {
            break;
        }

        if (slash == dir) {
            dir[1] = '\0';
        } else {
            *slash = '\0';
        }
    }

    return lowest;
}

/* Read a memory limit file. "max" (cgroup v2), a missing file or an invalid value mean no limit */
STATIC uint64_t w_read_cgroup_limit(const char *path) {

    char buffer[OS_SIZE_128];
    unsigned long long limit;
    char *end;
    FILE *fp;

    if (fp = wfopen(path, "r"), fp == NULL) {
        return 0;
    }

    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    buffer[strcspn(buffer, "\n")] = '\0';

    if (!isdigit((unsigned char)buffer[0])) {
        return 0;
    }

    errno = 0;
    limit = strtoull(buffer, &end, 10);
    if (errno == ERANGE || *end != '\0') {
        return 0;
    }

    return (uint64_t)limit;
}

STATIC bool w_cgroup_has_controller(const char *controllers, const char *controller) {

    size_t length = strlen(controller);
    const char *item = controllers;

    while (item != NULL && *item != '\0') {
        if (strncmp(item, controller, length) == 0 && (item[length] == ',' || item[length] == '\0')) {
            return true;
        }

        if (item = strchr(item, ','), item != NULL) {
            item++;
        }
    }

    return false;
}
