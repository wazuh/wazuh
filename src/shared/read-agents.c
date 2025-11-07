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
#include "read-agents.h"
#include "os_net/os_net.h"
#include "wazuhdb_op.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"

/* Delete diff folders */
void delete_diff(const char *name)
{
    if (NULL == name || *name == '\0') {
        return;
    }

    char tmp_folder[513] = {0};
    snprintf(tmp_folder, 512, "%s/%s",
             DIFF_DIR,
             name);

    rmdir_ex(tmp_folder);
}

#ifndef WIN32
/* Non-windows functions from now on */

char *agent_file_perm(mode_t mode)
{
    /* rwxrwxrwx0 -> 10 */
    char *permissions;

    os_calloc(10, sizeof(char), permissions);
    permissions[0] = (mode & S_IRUSR) ? 'r' : '-';
    permissions[1] = (mode & S_IWUSR) ? 'w' : '-';
    permissions[2] = (mode & S_ISUID) ? 's' : (mode & S_IXUSR) ? 'x' : '-';
    permissions[3] = (mode & S_IRGRP) ? 'r' : '-';
    permissions[4] = (mode & S_IWGRP) ? 'w' : '-';
    permissions[5] = (mode & S_ISGID) ? 's' : (mode & S_IXGRP) ? 'x' : '-';
    permissions[6] = (mode & S_IROTH) ? 'r' : '-';
    permissions[7] = (mode & S_IWOTH) ? 'w' : '-';
    permissions[8] = (mode & S_ISVTX) ? 't' : (mode & S_IXOTH) ? 'x' : '-';
    permissions[9] = '\0';

    return permissions;
}

#endif
