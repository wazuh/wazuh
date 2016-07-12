/*
 * Copyright (C) 2016 Wazuh Inc.
 * July 07, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

const char* get_user(int uid) {
    struct passwd *user = getpwuid(uid);
    return user ? user->pw_name : "";
}

const char* get_group(int gid) {
    struct group *group = getgrgid(gid);
    return group ? group->gr_name : "";
}

#else

const char *get_user(__attribute__((unused)) int uid) {
    return "";
}

const char *get_group(__attribute__((unused)) int gid) {
    return "";
}

#endif
