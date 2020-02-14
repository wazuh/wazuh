/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck-config.h"
#include "config.h"

void dump_syscheck_entry(syscheck_config *syscheck, char *entry, int vals, int reg,
        const char *restrictfile, int recursion_limit, const char *tag, const char *link)
{
    unsigned int pl = 0;
    int overwrite = -1;
    int j;

    for (j = 0; syscheck->dir && syscheck->dir[j]; j++) {
        /* Duplicate entry */
        if (strcmp(syscheck->dir[j], entry) == 0) {
            mdebug2("Overwriting the file entry %s", entry);
            overwrite = j;
        }
    }

    /* If overwrite < 0, syscheck entry is added at the end */
    if(overwrite != -1) {
        pl = overwrite;
    }

    if (reg == 1) {
#ifdef WIN32
        if (syscheck->registry == NULL) {
            os_calloc(2, sizeof(registry), syscheck->registry);
            syscheck->registry[pl + 1].entry = NULL;
            syscheck->registry[pl].tag = NULL;
            syscheck->registry[pl + 1].tag = NULL;
            syscheck->registry[pl].arch = vals;
            os_strdup(entry, syscheck->registry[pl].entry);
        } else if (overwrite < 0) {
            while (syscheck->registry[pl].entry != NULL) {
                pl++;
            }
            os_realloc(syscheck->registry, (pl + 2) * sizeof(registry),
                       syscheck->registry);
            syscheck->registry[pl + 1].entry = NULL;
            syscheck->registry[pl].tag = NULL;
            syscheck->registry[pl + 1].tag = NULL;
            syscheck->registry[pl].arch = vals;
            os_strdup(entry, syscheck->registry[pl].entry);
        } else {
            os_free(syscheck->registry[pl].tag);
            syscheck->registry[pl].arch = vals;
        }

        if (tag) {
            os_strdup(tag, syscheck->registry[pl].tag);
        }

#endif
    }
    else {
        if (syscheck->dir == NULL) {
            os_calloc(2, sizeof(char *), syscheck->dir);
            os_calloc(strlen(entry) + 2, sizeof(char), syscheck->dir[0]);
            snprintf(syscheck->dir[0], strlen(entry) + 1, "%s", entry);
            syscheck->dir[1] = NULL;

#ifdef WIN32
            os_calloc(2, sizeof(whodata_dir_status), syscheck->wdata.dirs_status);
#endif
            os_calloc(2, sizeof(char *), syscheck->symbolic_links);
            syscheck->symbolic_links[0] = NULL;
            syscheck->symbolic_links[1] = NULL;
            if (link) {
                os_strdup(link, syscheck->symbolic_links[0]);
            }

            os_calloc(2, sizeof(int), syscheck->opts);
            syscheck->opts[0] = vals;

            os_calloc(2, sizeof(OSMatch *), syscheck->filerestrict);

            os_calloc(2, sizeof(int), syscheck->recursion_level);
            syscheck->recursion_level[0] = recursion_limit;

            os_calloc(2, sizeof(char *), syscheck->tag);
        } else if (overwrite < 0) {
            while (syscheck->dir[pl] != NULL) {
                pl++;
            }
            os_realloc(syscheck->dir, (pl + 2) * sizeof(char *), syscheck->dir);
            syscheck->dir[pl + 1] = NULL;
            os_calloc(strlen(entry) + 2, sizeof(char), syscheck->dir[pl]);
            snprintf(syscheck->dir[pl], strlen(entry) + 1, "%s", entry);

#ifdef WIN32
            os_realloc(syscheck->wdata.dirs_status, (pl + 2) * sizeof(whodata_dir_status),
                    syscheck->wdata.dirs_status);
            memset(syscheck->wdata.dirs_status + pl, 0, 2 * sizeof(whodata_dir_status));
#endif

            os_realloc(syscheck->symbolic_links, (pl + 2) * sizeof(char *), syscheck->symbolic_links);
            syscheck->symbolic_links[pl] = NULL;
            syscheck->symbolic_links[pl + 1] = NULL;
            if (link) {
                os_strdup(link, syscheck->symbolic_links[pl]);
            }

            os_realloc(syscheck->opts, (pl + 2) * sizeof(int),
                       syscheck->opts);
            syscheck->opts[pl] = vals;
            syscheck->opts[pl + 1] = 0;

            os_realloc(syscheck->filerestrict, (pl + 2) * sizeof(OSMatch *),
                    syscheck->filerestrict);
            syscheck->filerestrict[pl] = NULL;
            syscheck->filerestrict[pl + 1] = NULL;

            os_realloc(syscheck->recursion_level, (pl + 2) * sizeof(int),
                       syscheck->recursion_level);
            syscheck->recursion_level[pl] = recursion_limit;
            syscheck->recursion_level[pl + 1] = 0;

            os_realloc(syscheck->tag, (pl + 2) * sizeof(char *),
                       syscheck->tag);
            syscheck->tag[pl] = NULL;
            syscheck->tag[pl + 1] = NULL;
        } else {
            if (link) {
                os_free(syscheck->symbolic_links[pl]);
                os_strdup(link, syscheck->symbolic_links[pl]);
            }
            syscheck->opts[pl] = vals;
            os_free(syscheck->filerestrict[pl]);
            syscheck->recursion_level[pl] = recursion_limit;
            os_free(syscheck->tag[pl]);
        }

        if (restrictfile) {
            os_calloc(1, sizeof(OSMatch), syscheck->filerestrict[pl]);
            if (!OSMatch_Compile(restrictfile, syscheck->filerestrict[pl], 0)) {
                OSMatch *ptm;

                ptm = syscheck->filerestrict[pl];

                merror(REGEX_COMPILE, restrictfile, ptm->error);
                free(syscheck->filerestrict[pl]);
                syscheck->filerestrict[pl] = NULL;
            }
        }
        if (tag) {
            os_strdup(tag, syscheck->tag[pl]);
        }

        if (vals & WHODATA_ACTIVE) {
            syscheck->enable_whodata = 1;
        }
    }
}

#ifdef WIN32

void dump_registry_ignore(syscheck_config *syscheck, char *entry, int arch) {
    int ign_size = 0;

    if (syscheck->registry_ignore) {
        /* We do not add duplicated entries */
        for (ign_size = 0; syscheck->registry_ignore[ign_size].entry; ign_size++)
            if (syscheck->registry_ignore[ign_size].arch == arch &&
                    strcmp(syscheck->registry_ignore[ign_size].entry, entry) == 0)
                return;

        os_realloc(syscheck->registry_ignore, sizeof(registry) * (ign_size + 2),
                   syscheck->registry_ignore);

        syscheck->registry_ignore[ign_size + 1].entry = NULL;
    } else {
        ign_size = 0;
        os_calloc(2, sizeof(registry), syscheck->registry_ignore);
        syscheck->registry_ignore[0].entry = NULL;
        syscheck->registry_ignore[1].entry = NULL;
    }

    os_strdup(entry, syscheck->registry_ignore[ign_size].entry);
    syscheck->registry_ignore[ign_size].arch = arch;
}

int dump_registry_ignore_regex(syscheck_config *syscheck, char *regex, int arch) {
    OSMatch *mt_pt;
    int ign_size = 0;

    if (!syscheck->registry_ignore_regex) {
        os_calloc(2, sizeof(registry_regex), syscheck->registry_ignore_regex);
        syscheck->registry_ignore_regex[0].regex = NULL;
        syscheck->registry_ignore_regex[1].regex = NULL;
    } else {
        while (syscheck->registry_ignore_regex[ign_size].regex != NULL) {
            ign_size++;
        }

        os_realloc(syscheck->registry_ignore_regex, sizeof(registry_regex) * (ign_size + 2),
                syscheck->registry_ignore_regex);
        syscheck->registry_ignore_regex[ign_size + 1].regex = NULL;
    }

    os_calloc(1, sizeof(OSMatch),
            syscheck->registry_ignore_regex[ign_size].regex);

    if (!OSMatch_Compile(regex, syscheck->registry_ignore_regex[ign_size].regex, 0)) {
        mt_pt = syscheck->registry_ignore_regex[ign_size].regex;
        merror(REGEX_COMPILE, regex, mt_pt->error);
        return (0);
    }

    syscheck->registry_ignore_regex[ign_size].arch = arch;
    return 1;
}

/* Read Windows registry configuration */
int read_reg(syscheck_config *syscheck, char *entries, int arch, char *tag)
{
    int i;
    int j;
    char **entry;
    char *tmp_str;

    /* Get each entry separately */
    entry = OS_StrBreak(',', entries, MAX_DIR_SIZE); /* Max number */

    if (entry == NULL) {
        return (0);
    }

    for (j = 0; entry[j]; j++) {
        char *tmp_entry;
        char * clean_tag = NULL;

        tmp_entry = entry[j];

        /* Remove spaces at the beginning */
        while (*tmp_entry == ' ') {
            tmp_entry++;
        }

        /* Remove spaces at the end */
        tmp_str = strchr(tmp_entry, ' ');
        if (tmp_str) {
            tmp_str++;

            /* Check if it is really at the end */
            if ((*tmp_str == '\0') || (*tmp_str == ' ')) {
                tmp_str--;
                *tmp_str = '\0';
            }
        }

        /* Add entries - look for the last available */
        i = 0;
        while (syscheck->registry && syscheck->registry[i].entry) {
            int str_len_i;
            int str_len_dir;

            str_len_dir = strlen(tmp_entry);
            str_len_i = strlen(syscheck->registry[i].entry);

            if (str_len_dir > str_len_i) {
                str_len_dir = str_len_i;
            }

            /* Duplicated entry */
            if (syscheck->registry[i].arch == arch && strcmp(syscheck->registry[i].entry, tmp_entry) == 0) {
                mdebug2("Overwriting the registration entry: %s", syscheck->registry[i].entry);
                dump_syscheck_entry(syscheck, tmp_entry, arch, 1, NULL, 0, clean_tag, NULL);
                free_strarray(entry);
                return (1);
            }
            i++;
        }

        /* Remove spaces from tag */

        if (tag) {
            if (clean_tag = os_strip_char(tag, ' '), !clean_tag)
                merror("Processing tag '%s' for registry entry '%s'.", tag, tmp_entry);
        }

        /* Add new entry */
        dump_syscheck_entry(syscheck, tmp_entry, arch, 1, NULL, 0, clean_tag, NULL);

        if (clean_tag)
            free(clean_tag);

        /* Next entry */
        free(entry[j]);
    }
    free(entry);

    return (1);
}
#endif /* WIN32 */

/* Read directories attributes */
static int read_attr(syscheck_config *syscheck, const char *dirs, char **g_attrs, char **g_values)
{
    const char *xml_check_all = "check_all";
    const char *xml_check_sum = "check_sum";
    const char *xml_check_sha1sum = "check_sha1sum";
    const char *xml_check_md5sum = "check_md5sum";
    const char *xml_check_size = "check_size";
    const char *xml_check_owner = "check_owner";
    const char *xml_check_group = "check_group";
    const char *xml_check_perm = "check_perm";
    const char *xml_check_mtime = "check_mtime";
    const char *xml_check_inode = "check_inode";
    const char *xml_check_attrs = "check_attrs";
    const char *xml_follow_symbolic_link = "follow_symbolic_link";
    const char *xml_real_time = "realtime";
    const char *xml_report_changes = "report_changes";
    const char *xml_restrict = "restrict";
    const char *xml_check_sha256sum = "check_sha256sum";
    const char *xml_whodata = "whodata";
    const char *xml_recursion_level = "recursion_level";
    const char *xml_tag = "tags";

    char *restrictfile = NULL;
    int recursion_limit = syscheck->max_depth;
    char *tag = NULL;
    char *clean_tag = NULL;
    char **dir;
    char *tmp_str;
    dir = OS_StrBreak(',', dirs, MAX_DIR_SIZE); /* Max number */
    char **dir_org = dir;

    int i;

    /* Dir can not be null */
    if (dir == NULL) {
        return (0);
    }

    while (*dir) {
        int opts = 0;
        char *tmp_dir;

        char **attrs = NULL;
        char **values = NULL;

        tmp_dir = *dir;
        restrictfile = NULL;
        tag = NULL;

        /* Remove spaces at the beginning */
        while (*tmp_dir == ' ') {
            tmp_dir++;
        }

        /* Remove spaces at the end */
        tmp_str = tmp_dir + strlen(tmp_dir) - 1;
        while(*tmp_str == ' ') {
            *tmp_str = '\0';
            tmp_str--;
        }
#ifdef WIN32
        /* Change forward slashes to backslashes on entry */
        tmp_str = strchr(tmp_dir, '/');
        while (tmp_str) {
            *tmp_str = '\\';

            tmp_str++;
            tmp_str = strchr(tmp_str, '/');
        }
#endif

        if (!strcmp(tmp_dir,"")) {
            mdebug2(FIM_EMPTY_DIRECTORIES_CONFIG);
            dir++;
            continue;
        }

        attrs = g_attrs;
        values = g_values;

        /* Default values */
        opts &= ~ CHECK_FOLLOW;
        opts |= SCHEDULED_ACTIVE;
        opts |= CHECK_SIZE;
        opts |= CHECK_PERM;
        opts |= CHECK_OWNER;
        opts |= CHECK_GROUP;
        opts |= CHECK_SHA256SUM;
        opts |= CHECK_MD5SUM;
        opts |= CHECK_SHA1SUM;
        opts |= CHECK_MTIME;
        opts |= CHECK_INODE;
#ifdef WIN32
        opts |= CHECK_ATTRS;
#endif

        while (attrs && values && *attrs && *values) {
            /* Check all */
            if (strcmp(*attrs, xml_check_all) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_MD5SUM;
                    opts |= CHECK_SHA1SUM;
                    opts |= CHECK_SHA256SUM;
                    opts |= CHECK_PERM;
                    opts |= CHECK_SIZE;
                    opts |= CHECK_OWNER;
                    opts |= CHECK_GROUP;
                    opts |= CHECK_MTIME;
                    opts |= CHECK_INODE;
#ifdef WIN32
                    opts |= CHECK_ATTRS;
#endif
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ ( CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_PERM | CHECK_SHA256SUM | CHECK_SIZE
                            | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE);
#ifdef WIN32
                    opts &= ~ CHECK_ATTRS;
#endif
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check sum */
            else if (strcmp(*attrs, xml_check_sum) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_MD5SUM;
                    opts |= CHECK_SHA1SUM;
                    opts |= CHECK_SHA256SUM;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM);
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check md5sum */
            else if (strcmp(*attrs, xml_check_md5sum) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_MD5SUM;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_MD5SUM;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check sha1sum */
            else if (strcmp(*attrs, xml_check_sha1sum) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_SHA1SUM;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_SHA1SUM;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check sha256sum */
            else if (strcmp(*attrs, xml_check_sha256sum) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_SHA256SUM;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_SHA256SUM;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check whodata */
            else if (strcmp(*attrs, xml_whodata) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts &= ~ REALTIME_ACTIVE;
                    opts &= ~ SCHEDULED_ACTIVE;
                    opts |= WHODATA_ACTIVE;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ WHODATA_ACTIVE;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check permission */
            else if (strcmp(*attrs, xml_check_perm) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_PERM;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_PERM;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check size */
            else if (strcmp(*attrs, xml_check_size) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_SIZE;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_SIZE;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check owner */
            else if (strcmp(*attrs, xml_check_owner) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_OWNER;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_OWNER;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check group */
            else if (strcmp(*attrs, xml_check_group) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_GROUP;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_GROUP;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check modification time */
            else if (strcmp(*attrs, xml_check_mtime) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_MTIME;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_MTIME;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check inode */
            else if (strcmp(*attrs, xml_check_inode) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_INODE;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_INODE;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check attributes */
            else if (strcmp(*attrs, xml_check_attrs) == 0) {
#ifdef WIN32
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_ATTRS;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_ATTRS;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
#else
                mdebug1("Option '%s' is only available on Windows systems.", xml_check_attrs);
#endif
            }
            /* Check real time */
            else if (strcmp(*attrs, xml_real_time) == 0) {
                if (strcmp(*values, "yes") == 0 && !(opts & WHODATA_ACTIVE)) {
                    opts &= ~ SCHEDULED_ACTIVE;
                    opts |= REALTIME_ACTIVE;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ REALTIME_ACTIVE;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check report changes */
            else if (strcmp(*attrs, xml_report_changes) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_SEECHANGES;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_SEECHANGES;
                } else {
                    mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                    goto out_free;
                }
            }
            /* Check file restriction */
            else if (strcmp(*attrs, xml_restrict) == 0) {
                if (restrictfile) {
                    free(restrictfile);
                    restrictfile = NULL;
                }
                os_strdup(*values, restrictfile);
#ifdef WIN32
                str_lowercase(restrictfile);
#endif
            }
            /* Check recursion limit */
            else if (strcmp(*attrs, xml_recursion_level) == 0) {
                if (!OS_StrIsNum(*values)) {
                    merror(XML_VALUEERR, xml_recursion_level, *values);
                    goto out_free;
                }
                recursion_limit = (unsigned int) atoi(*values);
                if (recursion_limit < 0) {
                    mwarn("Invalid recursion level value: %d. Setting default (%d).", recursion_limit, syscheck->max_depth);
                    recursion_limit = syscheck->max_depth;
                } else if (recursion_limit > MAX_DEPTH_ALLOWED) {
                    mwarn("Recursion level '%d' exceeding limit. Setting %d.", recursion_limit, MAX_DEPTH_ALLOWED);
                    recursion_limit = syscheck->max_depth;
                }
            }

            /* Check tag */
            else if (strcmp(*attrs, xml_tag) == 0) {
                if (tag) {
                    free(tag);
                    tag = NULL;
                }
                os_strdup(*values, tag);
            }
            /* Check follow symbolic links */
            else if (strcmp(*attrs, xml_follow_symbolic_link) == 0) {
               if (strcmp(*values, "yes") == 0) {
                   opts |= CHECK_FOLLOW;
               } else if (strcmp(*values, "no") == 0) {
                   opts &= ~ CHECK_FOLLOW;
               } else {
                   mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                   goto out_free;
               }
            } else {
                mwarn(FIM_UNKNOWN_ATTRIBUTE, *attrs);
            }
            attrs++;
            values++;
        }

        /* You must have something set */
        if (opts == 0) {
            mwarn(FIM_NO_OPTIONS, dirs);
            goto out_free;
        }

        /* Remove spaces from tag */

        if (tag) {
            if (clean_tag = os_strip_char(tag, ' '), !clean_tag) {
                merror("Processing tag '%s'.", tag);
                goto out_free;
            } else {
                free(tag);
                tag = NULL;
                os_strdup(clean_tag, tag);
                free(clean_tag);
            }
            if (clean_tag = os_strip_char(tag, '!'), !clean_tag) {
                merror("Processing tag '%s'.", tag);
                goto out_free;
            } else {
                free(tag);
                tag = NULL;
                os_strdup(clean_tag, tag);
                free(clean_tag);
            }
            if (clean_tag = os_strip_char(tag, ':'), !clean_tag) {
                merror("Processing tag '%s'.", tag);
                goto out_free;
            }
        }

        char real_path[PATH_MAX + 1] = "";
#ifdef WIN32
        char expandedpath[PATH_MAX + 1];

        if(!ExpandEnvironmentStrings(tmp_dir, expandedpath, PATH_MAX + 1)){
            merror("Could not expand the environment variable %s (%ld)", expandedpath, GetLastError());
            os_free(restrictfile);
            os_free(tag);
            dir++;
            continue;
        }

        // Get absolute path
        int retval = GetFullPathName(expandedpath, PATH_MAX, real_path, NULL);

        if (retval == 0) {
            int error = GetLastError();
            mwarn("Couldn't get full path name '%s' (%d):'%s'\n", expandedpath, error, win_strerror(error));
            os_free(restrictfile);
            os_free(tag);
            dir++;
            continue;
        }

        str_lowercase(real_path);
#else
        strncpy(real_path, tmp_dir, PATH_MAX);
#endif
        /* Check for glob */
        /* The mingw32 builder used by travis.ci can't find glob.h
         * Yet glob must work on actual win32.
         */
#ifndef __MINGW32__
        if (strchr(real_path, '*') ||
                strchr(real_path, '?') ||
                strchr(real_path, '[')) {
            int gindex = 0;
            glob_t g;

            if (glob(tmp_dir, 0, NULL, &g) != 0) {
                merror(GLOB_ERROR, real_path);
                dir++;
                continue;
            }

            if (g.gl_pathv[0] == NULL) {
                merror(GLOB_NFOUND, real_path);
                dir++;
                continue;
            }

            while (g.gl_pathv[gindex]) {
                char *resolved_path = NULL;

                if (resolved_path = realpath(g.gl_pathv[gindex], NULL), resolved_path) {
                    if (!strcmp(resolved_path, g.gl_pathv[gindex])) {
                        dump_syscheck_entry(syscheck, g.gl_pathv[gindex], opts, 0, restrictfile, recursion_limit, clean_tag, NULL);
                    } else {
                        dump_syscheck_entry(syscheck, resolved_path, opts, 0, restrictfile, recursion_limit, clean_tag, g.gl_pathv[gindex]);
                    }
                    os_free(resolved_path);
                } else {
                    mdebug1("Could not check the real path of '%s' due to [(%d)-(%s)].", g.gl_pathv[gindex], errno, strerror(errno));
                }

                gindex++;
            }

            globfree(&g);
        }
        else {
            char *resolved_path = NULL;

            if (resolved_path = realpath(real_path, NULL), resolved_path) {
                if (!strcmp(resolved_path, real_path)) {
                    dump_syscheck_entry(syscheck, real_path, opts, 0, restrictfile, recursion_limit, clean_tag, NULL);
                } else {
                    dump_syscheck_entry(syscheck, resolved_path, opts, 0, restrictfile, recursion_limit, clean_tag, real_path);
                }
            } else {
                dump_syscheck_entry(syscheck, real_path, opts, 0, restrictfile, recursion_limit, clean_tag, NULL);
            }
            os_free(resolved_path);
        }
#else
        dump_syscheck_entry(syscheck, real_path, opts, 0, restrictfile, recursion_limit, clean_tag, NULL);
#endif

        if (restrictfile) {
            free(restrictfile);
            restrictfile = NULL;
        }

        if (tag) {
            free(tag);
            if (clean_tag)
                free(clean_tag);
            tag = NULL;
            clean_tag = NULL;
        }

        /* Next entry */
        dir++;
    }

out_free:

    i = 0;
    while (dir_org[i]) {
        free(dir_org[i++]);
    }

    free(dir_org);
    free(restrictfile);
    if (tag) {
        free(tag);
    }
    if (clean_tag) {
        free(clean_tag);
    }

    return 1;
}

static void parse_synchronization(syscheck_config * syscheck, XML_NODE node) {
    const char *xml_enabled = "enabled";
    const char *xml_sync_interval = "interval";
    const char *xml_max_sync_interval = "max_interval";
    const char *xml_response_timeout = "response_timeout";
    const char *xml_sync_queue_size = "queue_size";

    for (int i = 0; node[i]; i++) {
        if (strcmp(node[i]->element, xml_enabled) == 0) {
            int r = w_parse_bool(node[i]->content);

            if (r < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->enable_synchronization = r;
            }
        } else if (strcmp(node[i]->element, xml_sync_interval) == 0) {
            long t = w_parse_time(node[i]->content);

            if (t <= 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_interval = t;
            }
        } else if (strcmp(node[i]->element, xml_max_sync_interval) == 0) {
            long t = w_parse_time(node[i]->content);

            if (t <= 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->max_sync_interval = t;
            }
        } else if (strcmp(node[i]->element, xml_response_timeout) == 0) {
            long t = w_parse_time(node[i]->content);

            if (t == -1) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_response_timeout = t;
            }
        } else if (strcmp(node[i]->element, xml_sync_queue_size) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 2 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_queue_size = value;
            }
        } else {
            mwarn(XML_INVELEM, node[i]->element);
        }
    }
}

int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *configp, __attribute__((unused)) void *mailp, int modules)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;

    /* XML Definitions */
    const char *xml_directories = "directories";
    const char *xml_registry = "windows_registry";
    const char *xml_time = "frequency";
    const char *xml_scanday = "scan_day";
    const char *xml_scantime = "scan_time";
    const char *xml_ignore = "ignore";
    const char *xml_registry_ignore = "registry_ignore";
    const char *xml_auto_ignore = "auto_ignore"; // TODO: Deprecated since 3.11.0
    const char *xml_alert_new_files = "alert_new_files"; // TODO: Deprecated since 3.11.0
    const char *xml_remove_old_diff = "remove_old_diff"; // Deprecated since 3.8.0
    const char *xml_disabled = "disabled";
    const char *xml_scan_on_start = "scan_on_start";
    const char *xml_prefilter_cmd = "prefilter_cmd";
    const char *xml_skip_nfs = "skip_nfs";
    const char *xml_skip_dev = "skip_dev";
    const char *xml_skip_sys = "skip_sys";
    const char *xml_skip_proc = "skip_proc";
    const char *xml_nodiff = "nodiff";
    const char *xml_restart_audit = "restart_audit";
    const char *xml_windows_audit_interval = "windows_audit_interval";
#ifdef WIN32
    const char *xml_arch = "arch";
    const char *xml_32bit = "32bit";
    const char *xml_64bit = "64bit";
    const char *xml_both = "both";
    const char *xml_tag = "tags";
#endif
    const char *xml_whodata_options = "whodata";
    const char *xml_audit_key = "audit_key";
    const char *xml_audit_hc = "startup_healthcheck";
    const char *xml_process_priority = "process_priority";
    const char *xml_synchronization = "synchronization";
    const char *xml_max_eps = "max_eps";
    const char *xml_allow_remote_prefilter_cmd = "allow_remote_prefilter_cmd";

    /* Configuration example
    <directories check_all="yes">/etc,/usr/bin</directories>
    <directories check_owner="yes" check_group="yes" check_perm="yes"
    check_sum="yes">/var/log</directories>
    */

    syscheck_config *syscheck;
    syscheck = (syscheck_config *)configp;
    unsigned int nodiff_size = 0;
    char prefilter_cmd[OS_MAXSTR] = "";

    if (syscheck->disabled == SK_CONF_UNPARSED) {
        syscheck->disabled = SK_CONF_UNDEFINED;
    }

    if(!syscheck->audit_key) {
        os_calloc(1, sizeof(char *), syscheck->audit_key);
    }
    for (i = 0; node && node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }

        /* Get directories */
        else if (strcmp(node[i]->element, xml_directories) == 0) {
            char dirs[OS_MAXSTR];
            char *ptfile;

#ifdef WIN32
            str_lowercase(node[i]->content);
            /* Change backslashes to forwardslashes on entry */
            ptfile = strchr(node[i]->content, '/');
            while (ptfile) {
                *ptfile = '\\';
                ptfile++;

                ptfile = strchr(ptfile, '/');
            }
#endif
            int path_lenght = strlen(node[i]->content);
            ptfile = node[i]->content + path_lenght - 1;
            if (*ptfile == '/' && path_lenght != 1) {
                *ptfile = '\0';
            }

#ifdef WIN32
            if(!ExpandEnvironmentStrings(node[i]->content, dirs, sizeof(dirs) - 1)){
                merror("Could not expand the environment variable %s (%ld)", node[i]->content, GetLastError());
                continue;
            }
            str_lowercase(dirs);
#else
            strncpy(dirs, node[i]->content, sizeof(dirs) - 1);
#endif

            if (!read_attr(syscheck,
                           dirs,
                           node[i]->attributes,
                           node[i]->values)) {
                return (OS_INVALID);
            }
        }
        /* Get Windows registry */
        else if (strcmp(node[i]->element, xml_registry) == 0) {
#ifdef WIN32
            char * tag = NULL;
            char arch[6] = "32bit";

            if (node[i]->attributes) {
                int j = 0;

                while(node[i]->attributes[j]) {
                    if (strcmp(node[i]->attributes[j], xml_tag) == 0) {
                        os_free(tag);
                        os_strdup(node[i]->values[j], tag);
                    } else if (strcmp(node[i]->attributes[j], xml_arch) == 0) {
                        if (strcmp(node[i]->values[j], xml_32bit) == 0) {
                        } else if (strcmp(node[i]->values[j], xml_64bit) == 0) {
                            snprintf(arch, 6, "%s", "64bit");
                        } else if (strcmp(node[i]->values[j], xml_both) == 0) {
                            snprintf(arch, 6, "%s", "both");
                        } else {
                            merror(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                            os_free(tag);
                            return OS_INVALID;
                        }
                    } else {
                        merror(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                        os_free(tag);
                        return OS_INVALID;
                    }
                    j++;
                }
            }

            if (strcmp(arch, "both") == 0) {
                if (!(read_reg(syscheck, node[i]->content, ARCH_32BIT, tag) &&
                read_reg(syscheck, node[i]->content, ARCH_64BIT, tag))) {
                    free(tag);
                    return (OS_INVALID);
                }

            } else if (strcmp(arch, "64bit") == 0) {
                if (!read_reg(syscheck, node[i]->content, ARCH_64BIT, tag)) {
                    free(tag);
                    return (OS_INVALID);
                }

            } else {
                if (!read_reg(syscheck, node[i]->content, ARCH_32BIT, tag)) {
                    free(tag);
                    return (OS_INVALID);
                }

            }

            if (tag)
                free(tag);
#endif
        }
        /* Get windows audit interval */
        else if (strcmp(node[i]->element, xml_windows_audit_interval) == 0) {
#ifdef WIN32
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            syscheck->wdata.interval_scan = atoi(node[i]->content);
#endif
        }
        /* Get frequency */
        else if (strcmp(node[i]->element, xml_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            syscheck->time = atoi(node[i]->content);
        }
        /* Get scan time */
        else if (strcmp(node[i]->element, xml_scantime) == 0) {
            syscheck->scan_time = OS_IsValidUniqueTime(node[i]->content);
            if (!syscheck->scan_time) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Get scan day */
        else if (strcmp(node[i]->element, xml_scanday) == 0) {
            syscheck->scan_day = OS_IsValidDay(node[i]->content);
            if (!syscheck->scan_day) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Get if xml_scan_on_start */
        else if (strcmp(node[i]->element, xml_scan_on_start) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                syscheck->scan_on_start = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                syscheck->scan_on_start = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Get if disabled */
        else if (strcmp(node[i]->element, xml_disabled) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                syscheck->disabled = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                syscheck->disabled = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Getting if skip_nfs. */
        else if (strcmp(node[i]->element,xml_skip_nfs) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.nfs = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.nfs = 0;
            else
            {
                merror(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting if skip_dev. */
        else if (strcmp(node[i]->element,xml_skip_dev) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.dev = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.dev = 0;
            else
            {
                merror(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting if skip_sys */
        else if (strcmp(node[i]->element,xml_skip_sys) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.sys = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.sys = 0;
            else
            {
                merror(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting if skip_proc. */
        else if (strcmp(node[i]->element,xml_skip_proc) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.proc = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.proc = 0;
            else
            {
                merror(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting file/dir ignore */
        else if (strcmp(node[i]->element,xml_ignore) == 0)
        {
            unsigned int ign_size = 0;

#ifdef WIN32
            /* For Windows, we attempt to expand environment variables */
            char *new_ig = NULL;
            os_calloc(2048, sizeof(char), new_ig);

            if(!ExpandEnvironmentStrings(node[i]->content, new_ig, 2047)){
                merror("Could not expand the environment variable %s (%ld)", node[i]->content, GetLastError());
                free(new_ig);
                continue;
            }

            free(node[i]->content);
            str_lowercase(new_ig);
            node[i]->content = new_ig;
#endif
            /* Add if regex */
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0] && node[i]->values[0]) {
                if (!strcmp(node[i]->attributes[0], "type") &&
                    !strcmp(node[i]->values[0], "sregex")) {
                    OSMatch *mt_pt;

                    if (!syscheck->ignore_regex) {
                        os_calloc(2, sizeof(OSMatch *), syscheck->ignore_regex);
                        syscheck->ignore_regex[0] = NULL;
                        syscheck->ignore_regex[1] = NULL;
                    } else {
                        while (syscheck->ignore_regex[ign_size] != NULL) {
                            ign_size++;
                        }

                        os_realloc(syscheck->ignore_regex,
                                   sizeof(OSMatch *) * (ign_size + 2),
                                   syscheck->ignore_regex);
                        syscheck->ignore_regex[ign_size + 1] = NULL;
                    }
                    os_calloc(1, sizeof(OSMatch),
                              syscheck->ignore_regex[ign_size]);

                    if (!OSMatch_Compile(node[i]->content,
                                         syscheck->ignore_regex[ign_size], 0)) {
                        mt_pt = (OSMatch *)syscheck->ignore_regex[ign_size];
                        merror(REGEX_COMPILE, node[i]->content,
                               mt_pt->error);
                        return (0);
                    }
                } else {
                    merror(FIM_INVALID_OPTION, node[i]->attributes[0] ? node[i]->attributes[0] : "", node[i]->element);
                    return (OS_INVALID);
                }
            }

            /* Add if simple entry -- check for duplicates */
            else if (!os_IsStrOnArray(node[i]->content, syscheck->ignore)) {
                if (!syscheck->ignore) {
                    os_calloc(2, sizeof(char *), syscheck->ignore);
                    syscheck->ignore[0] = NULL;
                    syscheck->ignore[1] = NULL;
                } else {
                    while (syscheck->ignore[ign_size] != NULL) {
                        ign_size++;
                    }

                    os_realloc(syscheck->ignore,
                               sizeof(char *) * (ign_size + 2),
                               syscheck->ignore);
                    syscheck->ignore[ign_size + 1] = NULL;
                }
                os_strdup(node[i]->content, syscheck->ignore[ign_size]);
            }
        }

        /* Get registry ignore list */
        else if (strcmp(node[i]->element, xml_registry_ignore) == 0) {
#ifdef WIN32
            int sregex = 0;
            int arch = ARCH_32BIT;

            /* Add if regex */
            if (node[i]->attributes && node[i]->values) {
                int j;

                for (j = 0; node[i]->attributes[j]; j++) {
                    if (strcmp(node[i]->attributes[j], "type") == 0 &&
                    strcmp(node[i]->values[j], "sregex") == 0) {
                        sregex = 1;
                    } else if (strcmp(node[i]->attributes[j], xml_arch) == 0) {
                        if (strcmp(node[i]->values[j], xml_32bit) == 0)
                            arch = ARCH_32BIT;
                        else if  (strcmp(node[i]->values[j], xml_64bit) == 0)
                            arch = ARCH_64BIT;
                        else if (strcmp(node[i]->values[j], xml_both) == 0)
                            arch = ARCH_BOTH;
                        else {
                            merror(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                            return OS_INVALID;
                        }
                    } else {
                        merror(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                        return OS_INVALID;
                    }
                }
            }


            if (sregex) {
                if (arch != ARCH_BOTH)
                    dump_registry_ignore_regex(syscheck, node[i]->content, arch);
                else {
                    dump_registry_ignore_regex(syscheck, node[i]->content, ARCH_32BIT);
                    dump_registry_ignore_regex(syscheck, node[i]->content, ARCH_64BIT);
                }
            } else {
                if (arch != ARCH_BOTH)
                    dump_registry_ignore(syscheck, node[i]->content, arch);
                else {
                    dump_registry_ignore(syscheck, node[i]->content, ARCH_32BIT);
                    dump_registry_ignore(syscheck, node[i]->content, ARCH_64BIT);
                }
            }

#endif
        /* Getting file/dir nodiff */
        } else if (strcmp(node[i]->element,xml_nodiff) == 0) {
#ifdef WIN32
            /* For Windows, we attempt to expand environment variables */
            char *new_nodiff = NULL;
            os_calloc(2048, sizeof(char), new_nodiff);

            if(!ExpandEnvironmentStrings(node[i]->content, new_nodiff, 2047)){
                merror("Could not expand the environment variable %s (%ld)", node[i]->content, GetLastError());
                free(new_nodiff);
                continue;
            }

            free(node[i]->content);
            str_lowercase(new_nodiff);
            node[i]->content = new_nodiff;
#endif
            /* Add if regex */
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0] && node[i]->values[0]) {
                if (!strcmp(node[i]->attributes[0], "type") &&
                    !strcmp(node[i]->values[0], "sregex")) {
                    OSMatch *mt_pt;
                    if (!syscheck->nodiff_regex) {
                        os_calloc(2, sizeof(OSMatch *), syscheck->nodiff_regex);
                        syscheck->nodiff_regex[0] = NULL;
                        syscheck->nodiff_regex[1] = NULL;
                    } else {
                        while (syscheck->nodiff_regex[nodiff_size] != NULL) {
                            nodiff_size++;
                        }

                        os_realloc(syscheck->nodiff_regex,
                                   sizeof(OSMatch *) * (nodiff_size + 2),
                                   syscheck->nodiff_regex);
                        syscheck->nodiff_regex[nodiff_size + 1] = NULL;
                    }
                    os_calloc(1, sizeof(OSMatch),
                              syscheck->nodiff_regex[nodiff_size]);
                    mdebug1("Found nodiff regex node %s", node[i]->content);
                    if (!OSMatch_Compile(node[i]->content,
                                         syscheck->nodiff_regex[nodiff_size], 0)) {
                        mt_pt = (OSMatch *)syscheck->nodiff_regex[nodiff_size];
                        merror(REGEX_COMPILE, node[i]->content,
                               mt_pt->error);
                        return (0);
                    }
                    mdebug1("Found nodiff regex node %s OK?", node[i]->content);
                    mdebug1("Found nodiff regex size %d", nodiff_size);
                } else {
                    merror(FIM_INVALID_ATTRIBUTE, node[i]->attributes[0], node[i]->element);
                    return (OS_INVALID);
                }
            }

            /* Add if simple entry -- check for duplicates */
            else if (!os_IsStrOnArray(node[i]->content, syscheck->nodiff)) {
                if (!syscheck->nodiff) {
                    os_calloc(2, sizeof(char *), syscheck->nodiff);
                    syscheck->nodiff[0] = NULL;
                    syscheck->nodiff[1] = NULL;
                } else {
                    while (syscheck->nodiff[nodiff_size] != NULL) {
                        nodiff_size++;
                    }

                    os_realloc(syscheck->nodiff,
                               sizeof(char *) * (nodiff_size + 2),
                               syscheck->nodiff);
                    syscheck->nodiff[nodiff_size + 1] = NULL;
                }
                os_strdup(node[i]->content, syscheck->nodiff[nodiff_size]);
            }
        } else if (strcmp(node[i]->element, xml_auto_ignore) == 0) {
            /* auto_ignore is not read here */
        } else if (strcmp(node[i]->element, xml_alert_new_files) == 0) {
            /* alert_new_files option is not read here */
        } else if (strcmp(node[i]->element, xml_prefilter_cmd) == 0) {
            struct stat statbuf;

#ifdef WIN32
            if(!ExpandEnvironmentStrings(node[i]->content, prefilter_cmd, sizeof(prefilter_cmd) - 1)){
                merror("Could not expand the environment variable %s (%ld)", node[i]->content, GetLastError());
                continue;
            }
            str_lowercase(prefilter_cmd);
#else
            strncpy(prefilter_cmd, node[i]->content, sizeof(prefilter_cmd) - 1);
            prefilter_cmd[sizeof(prefilter_cmd) - 1] = '\0';
#endif

            if (strlen(prefilter_cmd) > 0) {
                char statcmd[OS_MAXSTR];
                char *ix;
                strncpy(statcmd, prefilter_cmd, sizeof(statcmd) - 1);
                statcmd[sizeof(statcmd) - 1] = '\0';
                if (NULL != (ix = strchr(statcmd, ' '))) {
                    *ix = '\0';
                }
                if (stat(statcmd, &statbuf) != 0) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            }
        } else if (strcmp(node[i]->element, xml_remove_old_diff) == 0) {
            // Deprecated since 3.8.0, aplied by default...
        } else if (strcmp(node[i]->element, xml_restart_audit) == 0) {
            // To be deprecated. This field is now read inside the <whodata> block.
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->restart_audit = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->restart_audit = 0;
            else
            {
                merror(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        /* Whodata options */
        else if (strcmp(node[i]->element, xml_whodata_options) == 0) {

            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }

            for (j = 0; children[j]; j++) {
                /* Listen another audit keys */
                if (strcmp(children[j]->element, xml_audit_key) == 0) {
                    int keyit = 0;
                    char *delim = ",";
                    char *key;
                    char *saveptr;
                    key = strtok_r(children[j]->content, delim, &saveptr);

                    while (key) {
                        if (*key) {
                            syscheck->audit_key[keyit] = check_ascci_hex(key);
                            os_realloc(syscheck->audit_key, (keyit + 2) * sizeof(char *), syscheck->audit_key);
                            syscheck->audit_key[keyit + 1] = NULL;
                            key = strtok_r(NULL, delim, &saveptr);
                            keyit++;
                        }
                    }
                } else if (strcmp(children[j]->element, xml_audit_hc) == 0) {
                    if(strcmp(children[j]->content, "yes") == 0)
                        syscheck->audit_healthcheck = 1;
                    else if(strcmp(children[j]->content, "no") == 0)
                        syscheck->audit_healthcheck = 0;
                    else
                    {
                        merror(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                } else if (strcmp(children[j]->element, xml_restart_audit) == 0) {
                    if(strcmp(children[j]->content, "yes") == 0)
                        syscheck->restart_audit = 1;
                    else if(strcmp(children[j]->content, "no") == 0)
                        syscheck->restart_audit = 0;
                    else
                    {
                        merror(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        /* Set priority process this value should be between -20 and 19 */
        } else if (strcmp(node[i]->element, xml_process_priority) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < -20 || value > 19 || *end) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                syscheck->process_priority = value;
            }
        } else if (strcmp(node[i]->element, xml_synchronization) == 0) {
            children = OS_GetElementsbyNode(xml, node[i]);

            if (children == NULL) {
                continue;
            }

            parse_synchronization(syscheck, children);
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_max_eps) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 1 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                if (value > 1000000) {
                    mdebug1("<%s> exceeds the maximum allowed value (1000000). EPS limitation is disabled.", node[i]->element);
                }

                syscheck->max_eps = value;
            }
        } /* Allow prefilter cmd */
        else if (strcmp(node[i]->element, xml_allow_remote_prefilter_cmd) == 0) {
            if (modules & CAGENT_CONFIG) {
                mwarn("'%s' option can't be changed using centralized configuration (agent.conf).", xml_allow_remote_prefilter_cmd);
                i++;
                continue;
            }
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->allow_remote_prefilter_cmd = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->allow_remote_prefilter_cmd = 0;
            else {
                merror(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        } else {
            mwarn(XML_INVELEM, node[i]->element);
        }
    }

    // Set prefilter only if it's expressly allowed (ossec.conf in agent side).

    if (prefilter_cmd[0]) {
        if (!(modules & CAGENT_CONFIG) || syscheck->allow_remote_prefilter_cmd) {
            free(syscheck->prefilter_cmd);
            os_strdup(prefilter_cmd, syscheck->prefilter_cmd);
        } else if (!syscheck->allow_remote_prefilter_cmd) {
            mwarn(FIM_WARN_ALLOW_PREFILTER, prefilter_cmd, xml_allow_remote_prefilter_cmd);
        }
    }

    return (0);
}

char *syscheck_opts2str(char *buf, int buflen, int opts) {
    int left = buflen;
    int i;
    int check_bits[] = {
        CHECK_SIZE,
        CHECK_PERM,
        CHECK_OWNER,
        CHECK_GROUP,
        CHECK_MTIME,
        CHECK_INODE,
        CHECK_MD5SUM,
        CHECK_SHA1SUM,
        CHECK_SHA256SUM,
        CHECK_ATTRS,
        CHECK_SEECHANGES,
        CHECK_FOLLOW,
        REALTIME_ACTIVE,
        WHODATA_ACTIVE,
        SCHEDULED_ACTIVE,
	    0
	};
    char *check_strings[] = {
        "size",
        "permissions",
        "owner",
        "group",
    	"mtime",
        "inode",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "attributes",
        "report_changes",
        "follow_symbolic_links",
        "realtime",
        "whodata",
        "scheduled",
	    NULL
	};

    buf[0] = '\0';
    for ( i = 0; check_bits[ i ]; i++ ) {
	if ( opts & check_bits[ i ] ) {
	    if ( left < buflen )  {
		strncat( buf, " | ", left );
		left -= 3;
		}
	    strncat( buf, check_strings[ i ], left );
	    left = buflen - strlen( buf );
	    }
	}

    return buf;
    }

int Test_Syscheck(const char * path){
    int fail = 0;
    syscheck_config test_syscheck = { .rootcheck = 0 };

    if (ReadConfig(CAGENT_CONFIG | CSYSCHECK, path, &test_syscheck, NULL) < 0) {
		merror(RCONFIG_ERROR,"Syscheck", path);
		fail = 1;
	}

    Free_Syscheck(&test_syscheck);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void Free_Syscheck(syscheck_config * config) {
    if (config) {
        int i;
        free(config->opts);
        free(config->scan_day);
        free(config->scan_time);
        if (config->ignore) {
            for (i=0; config->ignore[i] != NULL; i++) {
                free(config->ignore[i]);
            }
            free(config->ignore);
        }
        if (config->ignore_regex) {
            for (i=0; config->ignore_regex[i] != NULL; i++) {
                OSMatch_FreePattern(config->ignore_regex[i]);
            }
            free(config->ignore_regex);
        }
        if (config->nodiff) {
            for (i=0; config->nodiff[i] != NULL; i++) {
                free(config->nodiff[i]);
            }
            free(config->nodiff);
        }
        if (config->nodiff_regex) {
            for (i=0; config->nodiff_regex[i] != NULL; i++) {
                OSMatch_FreePattern(config->nodiff_regex[i]);
            }
        }
        if (config->dir) {
            for (i=0; config->dir[i] != NULL; i++) {
                free(config->dir[i]);
                if(config->filerestrict[i]) {
                    OSMatch_FreePattern(config->filerestrict[i]);
                    free(config->filerestrict[i]);
                }
                if(config->tag[i]) {
                    free(config->tag[i]);
                }
            }
            free(config->dir);
            free(config->filerestrict);
            free(config->tag);
        }

    #ifdef WIN32
        if (config->registry_ignore) {
            for (i=0; config->registry_ignore[i].entry != NULL; i++) {
                free(config->registry_ignore[i].entry);
            }
            free(config->registry_ignore);
        }
        if (config->registry_ignore_regex) {
            for (i=0; config->registry_ignore_regex[i].regex != NULL; i++) {
                OSMatch_FreePattern(config->registry_ignore_regex[i].regex);
            }
            free(config->registry_ignore_regex);
        }
        if (config->registry) {
            for (i=0; config->registry[i].entry != NULL; i++) {
                free(config->registry[i].entry);
                if (config->registry[i].tag) {
                    free(config->registry[i].tag);
                }
            }
            free(config->registry);
        }
    #endif

        if (config->realtime) {
            OSHash_Free(config->realtime->dirtb);
#ifdef WIN32
            CloseEventLog(config->realtime->evt);
#endif
            free(config->realtime);
        }
        free(config->prefilter_cmd);

        free_strarray(config->audit_key);
    }
}

char* check_ascci_hex (char *input) {
    unsigned int j = 0;
    int hex = 0;
    char outhex[OS_SIZE_256];

    for (j = 0; j < strlen(input); j++) {
        snprintf(outhex + j*2, OS_SIZE_256 - j * 2, "%hhX", input[j]);
        if ((unsigned int)input[j] > 126 ||
                (unsigned int)input[j] == 32 ||
                (unsigned int)input[j] == 34) {
            hex = 1;
        }
    }

    char *output;
    if (hex) {
        os_strdup(outhex, output);
    } else {
        os_strdup(input, output);
    }
    return output;
}
