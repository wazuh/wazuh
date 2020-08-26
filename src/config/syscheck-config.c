/* Copyright (C) 2015-2020, Wazuh Inc.
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

/* Extract the value (one or multiples paths) from environment variable */
static char **get_paths_from_env_variable (char *environment_variable);
/* Used for options nodiff_regex and ignore_regex */
static int process_option_regex(char *option, OSMatch ***syscheck_option, xml_node *node);
/* Used for options ignore and nodiff */
static void process_option(char ***syscheck_option, xml_node *node);
/* Set check_all options in a directory/file */
static void fim_set_check_all(int *opt);


void organize_syscheck_dirs(syscheck_config *syscheck)
{
    if (syscheck->dir && syscheck->dir[0]) {
        char **dir;
        char **symbolic_links;
        char **tag;
        OSMatch **filerestrict;
        int *opts;
        int *recursion_level;

        int i;
        int j;
        int dirs = 0;

        while (syscheck->dir[dirs] != NULL) {
            dirs++;
        }

        os_calloc(dirs + 1, sizeof(char *), dir);
        os_calloc(dirs + 1, sizeof(char *), symbolic_links);
        os_calloc(dirs + 1, sizeof(char *), tag);
        os_calloc(dirs + 1, sizeof(OSMatch *), filerestrict);
        os_calloc(dirs + 1, sizeof(int), opts);
        os_calloc(dirs + 1, sizeof(int), recursion_level);

        for (i = 0; i < dirs; ++i) {

            char *current = NULL;
            int pos = -1;

            for (j = 0; j < dirs; ++j) {

                if (syscheck->dir[j] == NULL) {
                    continue;
                }

                if (current == NULL) {
                    current = syscheck->dir[j];
                    pos = j;
                    continue;
                }

                if (strcmp(current, syscheck->dir[j]) > 0) {
                    current = syscheck->dir[j];
                    pos = j;
                }
            }

            dir[i] = current;
            dir[i + 1] = NULL;

            symbolic_links[i] = (syscheck->symbolic_links[pos]) ? syscheck->symbolic_links[pos] : NULL;
            symbolic_links[i + 1] = NULL;

            tag[i] = (syscheck->tag[pos]) ? syscheck->tag[pos] : NULL;
            tag[i + 1] = NULL;

            filerestrict[i] = (syscheck->filerestrict[pos]) ? syscheck->filerestrict[pos] : NULL;
            filerestrict[i + 1] = NULL;

            opts[i] = syscheck->opts[pos];
            opts[i + 1] = 0;

            recursion_level[i] = syscheck->recursion_level[pos];
            recursion_level[i + 1] = 0;

            syscheck->dir[pos] = NULL;
        }

        free(syscheck->dir);
        syscheck->dir = dir;

        free(syscheck->symbolic_links);
        syscheck->symbolic_links = symbolic_links;

        free(syscheck->tag);
        syscheck->tag = tag;

        free(syscheck->filerestrict);
        syscheck->filerestrict = filerestrict;

        free(syscheck->opts);
        syscheck->opts = opts;

        free(syscheck->recursion_level);
        syscheck->recursion_level = recursion_level;
    }
    else {
        mdebug2("No directory entries to organize in syscheck configuration.");
    }
}


void dump_syscheck_entry(syscheck_config *syscheck, char *entry, int vals, int reg,
        const char *restrictfile, int recursion_limit, const char *tag, const char *link)
{
    unsigned int pl = 0;
    int overwrite = -1;
    int j;

    if (!reg) {
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

        if (syscheck->dir == NULL) {
            os_calloc(2, sizeof(char *), syscheck->dir);
            os_calloc(strlen(entry) + 2, sizeof(char), syscheck->dir[0]);
            if (link && !(CHECK_FOLLOW & vals)) {
                // Taking the link itself if follow_symbolic_link is not enabled
                snprintf(syscheck->dir[0], strlen(link) + 1, "%s", link);
            }
            else {
                snprintf(syscheck->dir[0], strlen(entry) + 1, "%s", entry);
            }
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
            if (link && !(CHECK_FOLLOW & vals)) {
                // Taking the link itself if follow_symbolic_link is not enabled
                snprintf(syscheck->dir[pl], strlen(link) + 1, "%s", link);
            }
            else {
                snprintf(syscheck->dir[pl], strlen(entry) + 1, "%s", entry);
            }

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
    }
#ifdef WIN32
    else {
        if (syscheck->registry == NULL) {
            os_calloc(2, sizeof(registry), syscheck->registry);
            syscheck->registry[pl + 1].entry = NULL;
            syscheck->registry[pl].tag = NULL;
            syscheck->registry[pl + 1].tag = NULL;
            syscheck->registry[pl].arch = vals;
            os_strdup(entry, syscheck->registry[pl].entry);
        } else {
            while (syscheck->registry[pl].entry != NULL) {
                /* Duplicated entry */
                if (strcmp(syscheck->registry[pl].entry, entry) == 0 && vals == syscheck->registry[pl].arch) {
                    overwrite = pl;
                    mdebug2("Duplicated registration entry: %s", syscheck->registry[pl].entry);
                    break;
                }
                pl++;
            }
            if (overwrite < 0) {
                os_realloc(syscheck->registry, (pl + 2) * sizeof(registry),
                        syscheck->registry);
                syscheck->registry[pl + 1].entry = NULL;
                syscheck->registry[pl].tag = NULL;
                syscheck->registry[pl + 1].tag = NULL;
                syscheck->registry[pl].arch = vals;
                os_strdup(entry, syscheck->registry[pl].entry);
            } else {
                os_free(syscheck->registry[pl].tag);
            }
        }

        if (tag) {
            os_strdup(tag, syscheck->registry[pl].tag);
        }
    }
#endif
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
    int j;
    char **entry;
    char *tmp_str;

    /* Get each entry separately */
    entry = OS_StrBreak(',', entries, MAX_DIR_SIZE + 1); /* Max number */

    if (entry == NULL) {
        return (0);
    }

    for (j = 0; entry[j]; j++) {
        char *tmp_entry;
        char * clean_tag = NULL;

        tmp_entry = entry[j];


        /* When the maximum number of registries monitored in the same tag is reached,
           the excess is discarded and warned */
        if (j >= MAX_DIR_SIZE){
            mwarn(FIM_WARN_MAX_REG_REACH, MAX_DIR_SIZE, tmp_entry);
            free(entry[j]);
            continue;
        }

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

    /* Variables for extract options */
    char *restrictfile = NULL;
    int recursion_limit = syscheck->max_depth;
    char *tag = NULL;
    char *clean_tag = NULL;
    char **attrs = g_attrs;
    char **values = g_values;
    int opts = 0;

    /* Variables for extract directories and free memory after that */
    char **dir;
    dir = OS_StrBreak(',', dirs, MAX_DIR_SIZE + 1); /* Max number */
    char **dir_org = dir;
    int i;
    int j = 0;

    /* Dir can not be null */
    if (dir == NULL) {
        return (0);
    }

    /* Default values */
    opts &= ~ CHECK_FOLLOW;
    opts |= SCHEDULED_ACTIVE;
    fim_set_check_all(&opts);

    /* Extract all options */
    while (attrs && values && *attrs && *values) {
        /* Check all */
        if (strcmp(*attrs, xml_check_all) == 0) {
            if (strcmp(*values, "yes") == 0) {
                fim_set_check_all(&opts);
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
            if (strcmp(*values, "yes") == 0) {
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
            os_free(restrictfile);
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
            os_free(tag);
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

    /* Whodata prevails over Realtime */
    if ((opts & WHODATA_ACTIVE) && (opts & REALTIME_ACTIVE)) {
        opts &= ~ REALTIME_ACTIVE;
    }

    /* Remove spaces from tag */
    if (tag) {
        if (clean_tag = os_strip_char(tag, ' '), !clean_tag) {
            merror("Processing tag '%s'", tag);
            goto out_free;
        } else {
            os_free(tag);
            os_strdup(clean_tag, tag);
            os_free(clean_tag);
        }
        if (clean_tag = os_strip_char(tag, '!'), !clean_tag) {
            merror("Processing tag '%s'", tag);
            goto out_free;
        } else {
            os_free(tag);
            os_strdup(clean_tag, tag);
            os_free(clean_tag);
        }
        if (clean_tag = os_strip_char(tag, ':'), !clean_tag) {
            merror("Processing tag '%s'", tag);
            goto out_free;
        }
    }

    /* Extract all directories */
    char real_path[PATH_MAX + 1] = "";
    char *tmp_str;
    char *tmp_dir;
    char **env_variable;
#ifdef WIN32
    int retvalF;
#endif

    while (*dir) {
        tmp_dir = *dir;

        /* When the maximum number of directories monitored in the same tag is reached,
           the excess are discarded and warned */
        if (j++ >= MAX_DIR_SIZE){
            mwarn(FIM_WARN_MAX_DIR_REACH, MAX_DIR_SIZE, tmp_dir);
            dir++;
            continue;
        }

        /* Remove spaces at the beginning and the end */
        while (*tmp_dir == ' ') {
            tmp_dir++;
        }

        tmp_str = tmp_dir + strlen(tmp_dir) - 1;
        while(*tmp_str == ' ') {
            *tmp_str = '\0';
            tmp_str--;
        }

        if (!strcmp(tmp_dir,"")) {
            mdebug2(FIM_EMPTY_DIRECTORIES_CONFIG);
            dir++;
            continue;
        }

#ifdef WIN32

        /* If it's an environment variable, expand it */
        if(env_variable = get_paths_from_env_variable(tmp_dir), env_variable){

            for(int i = 0; env_variable[i]; i++) {
                if(strcmp(env_variable[i], "")) {
                    // Get absolute path cheking if the path is a drive without the backslash.
                    if (strlen(env_variable[i]) == 2) {
                        strcat(env_variable[i], "\\");
                    }

                    if (retvalF = GetFullPathName(env_variable[i], PATH_MAX, real_path, NULL), retvalF == 0) {
                        retvalF = GetLastError();
                        mwarn("Couldn't get full path name '%s' (%d):'%s'\n", env_variable[i], retvalF, win_strerror(retvalF));
                        os_free(env_variable[i]);
                        continue;
                    }

                    // Remove any trailling path separators
                    int path_length = strlen(real_path);
                    if (path_length != 3) { // Drives need :\ attached in order to work properly
                        tmp_str = real_path + path_length - 1;
                        if (*tmp_str == PATH_SEP) {
                            *tmp_str = '\0';
                        }
                    }

                    str_lowercase(real_path);
                    dump_syscheck_entry(syscheck, real_path, opts, 0, restrictfile, recursion_limit, clean_tag, NULL);
                }
                os_free(env_variable[i]);
            }

            os_free(env_variable);
            dir++;
            continue;
        }

        /* Else, treat as a path */
        /* Change forward slashes to backslashes on entry */
        tmp_str = strchr(tmp_dir, '/');
        while (tmp_str) {
            *tmp_str = '\\';
            tmp_str++;
            tmp_str = strchr(tmp_str, '/');
        }

        // Get absolute path cheking if the path is a drive without the backslash.
        if (strlen(tmp_dir) == 2) {
            strcat(tmp_dir, "\\");
        }

        /* Get absolute path and monitor it */
        retvalF = GetFullPathName(tmp_dir, PATH_MAX, real_path, NULL);
        if (retvalF == 0) {
            retvalF = GetLastError();
            mwarn("Couldn't get full path name '%s' (%d):'%s'\n", tmp_dir, retvalF, win_strerror(retvalF));
            os_free(restrictfile);
            os_free(tag);
            dir++;
            continue;
        }

        // Remove any trailling path separators
        int path_length = strlen(real_path);
        if (path_length != 3) { // Drives need :\ attached in order to work properly
            tmp_str = real_path + path_length - 1;
            if (*tmp_str == PATH_SEP) {
                *tmp_str = '\0';
            }
        }

        str_lowercase(real_path);
        dump_syscheck_entry(syscheck, real_path, opts, 0, restrictfile, recursion_limit, clean_tag, NULL);

#else
        /* If it's an environment variable, expand it */
        if (*tmp_dir == '$') {
            if(env_variable = get_paths_from_env_variable(tmp_dir), env_variable) {

                for(int i = 0; env_variable[i]; i++) {
                    if(strcmp(env_variable[i], "")) {
                        // Remove any trailling path separators
                        int path_length = strlen(env_variable[i]);
                        if (path_length != 1) {
                            tmp_str = env_variable[i] + path_length - 1;
                            if (*tmp_str == PATH_SEP) {
                                *tmp_str = '\0';
                            }
                        }

                        dump_syscheck_entry(syscheck, env_variable[i], opts, 0, restrictfile, recursion_limit, clean_tag, NULL);
                    }
                    os_free(env_variable[i]);
                }

                os_free(env_variable);
                dir++;
                continue;
            }
        }

        /* Else, check if it's a wildcard, hard/symbolic link or path of file/directory */
        strncpy(real_path, tmp_dir, PATH_MAX);

        // Remove any trailling path separators
        int path_length = strlen(real_path);
        if (path_length != 1) {
            tmp_str = real_path + path_length - 1;
            if (*tmp_str == PATH_SEP) {
                *tmp_str = '\0';
            }
        }

        /* Check for glob */
        /* The mingw32 builder used by travis.ci can't find glob.h
         * Yet glob must work on actual win32.
         */
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
            char *resolved_path = realpath(real_path, NULL);

            if (resolved_path && strcmp(resolved_path, real_path)) {
                dump_syscheck_entry(syscheck, resolved_path, opts, 0, restrictfile, recursion_limit, clean_tag, real_path);
            } else {
                dump_syscheck_entry(syscheck, real_path, opts, 0, restrictfile, recursion_limit, clean_tag, NULL);
            }

            os_free(resolved_path);
        }
#endif

        /* Next entry */
        dir++;
    }

out_free:

    i = 0;
    while (dir_org[i]) {
        free(dir_org[i++]);
    }

    free(dir_org);
    os_free(restrictfile);
    os_free(tag);
    os_free(clean_tag);

    return 1;
}

static void parse_synchronization(syscheck_config * syscheck, XML_NODE node) {
    const char *xml_enabled = "enabled";
    const char *xml_sync_interval = "interval";
    const char *xml_max_sync_interval = "max_interval";
    const char *xml_response_timeout = "response_timeout";
    const char *xml_sync_queue_size = "queue_size";
    const char *xml_max_eps = "max_eps";

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
        } else if (strcmp(node[i]->element, xml_max_eps) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_max_eps = value;
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
    const char *xml_database = "database";
    const char *xml_scantime = "scan_time";
    const char *xml_file_limit = "file_limit";
    const char *xml_file_limit_enabled = "enabled";
    const char *xml_file_limit_entries = "entries";
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
#ifdef WIN32
            char *ptfile;

            /* Change backslashes to forwardslashes on entry */
            ptfile = strchr(node[i]->content, '/');
            while (ptfile) {
                *ptfile = '\\';
                ptfile++;

                ptfile = strchr(ptfile, '/');
            }
#endif
            strncpy(dirs, node[i]->content, sizeof(dirs) - 1);

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

        /*  Store database in memory or in disk.
        *   By default disk.
        */
        else if (strcmp(node[i]->element, xml_database) == 0) {
            if (strcmp(node[i]->content, "memory") == 0) {
                syscheck->database_store = FIM_DB_MEMORY;
            }
            else if (strcmp(node[i]->content, "disk") == 0){
                syscheck->database_store = FIM_DB_DISK;
            }
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

        /* Get file limit */
        else if (strcmp(node[i]->element, xml_file_limit) == 0) {
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }

            for(j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_file_limit_enabled) == 0) {
                    if (strcmp(children[j]->content, "yes") == 0) {
                        syscheck->file_limit_enabled = true;
                    }
                    else if (strcmp(children[j]->content, "no") == 0) {
                        syscheck->file_limit_enabled = false;
                    }
                    else {
                        merror(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return (OS_INVALID);
                    }
                }
                else if (strcmp(children[j]->element, xml_file_limit_entries) == 0) {
                    if (!OS_StrIsNum(children[j]->content)) {
                        merror(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return (OS_INVALID);
                    }

                    syscheck->file_limit = atoi(children[j]->content);

                    if (syscheck->file_limit > MAX_FILE_LIMIT) {
                        mdebug2("Maximum value allowed for file_limit is '%d'", MAX_FILE_LIMIT);
                        syscheck->file_limit = MAX_FILE_LIMIT;
                    }
                }
            }

            if (!syscheck->file_limit_enabled) {
                syscheck->file_limit = 0;
            }

            OS_ClearNode(children);
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
        else if (strcmp(node[i]->element,xml_ignore) == 0) {
            /* If it is a regex, add it */
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0] && node[i]->values[0]) {
                if (!strcmp(node[i]->attributes[0], "type") && !strcmp(node[i]->values[0], "sregex")) {
                    int result = process_option_regex("ignore", &syscheck->ignore_regex, node[i]);
                    if (result < 1) {
                        return result;
                    }
                } else {
                    merror(FIM_INVALID_ATTRIBUTE, node[i]->attributes[0], node[i]->element);
                    return (OS_INVALID);
                }
            } else {
                process_option(&syscheck->ignore, node[i]);
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
            /* Add if regex */
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0] && node[i]->values[0]) {
                if (!strcmp(node[i]->attributes[0], "type") && !strcmp(node[i]->values[0], "sregex")) {
                    int result = process_option_regex("nodiff", &syscheck->nodiff_regex, node[i]);
                    if (result < 1) {
                        return result;
                    }
                } else {
                    merror(FIM_INVALID_ATTRIBUTE, node[i]->attributes[0], node[i]->element);
                    return (OS_INVALID);
                }
            } else {
                process_option(&syscheck->nodiff, node[i]);
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

            if (value < 0 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
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

    organize_syscheck_dirs(syscheck);

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
        "follow_symbolic_link",
        "realtime",
        "whodata",
        "scheduled",
	    NULL
	};

    buf[0] = '\0';
    for (i = 0; check_bits[i]; i++) {
	    if (opts & check_bits[i]) {
            if (left < buflen) {
                strncat(buf, " | ", left);
                left -= 3;
            }
            strncat(buf, check_strings[i], left);
            left = buflen - strlen(buf);
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
        if (config->opts) {
            free(config->opts);
        }
        if (config->scan_day) {
            free(config->scan_day);
        }
        if (config->scan_time) {
            free(config->scan_time);
        }
        if (config->ignore) {
            for (i=0; config->ignore[i] != NULL; i++) {
                free(config->ignore[i]);
            }
            free(config->ignore);
        }
        if (config->ignore_regex) {
            for (i=0; config->ignore_regex[i] != NULL; i++) {
                OSMatch_FreePattern(config->ignore_regex[i]);
                free(config->ignore_regex[i]);
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
                free(config->nodiff_regex[i]);
            }
            free(config->nodiff_regex);
        }
        if (config->dir) {
            for (i=0; config->dir[i] != NULL; i++) {
                free(config->dir[i]);
                if(config->filerestrict && config->filerestrict[i]) {
                    OSMatch_FreePattern(config->filerestrict[i]);
                    free(config->filerestrict[i]);
                }
                if(config->tag && config->tag[i]) {
                    free(config->tag[i]);
                }
            }
            free(config->dir);
            if (config->filerestrict) {
                free(config->filerestrict);
            }
            if (config->tag) {
                free(config->tag);
            }
        }
        if (config->symbolic_links) {
            for (i=0; config->symbolic_links[i] != NULL; i++) {
                free(config->symbolic_links[i]);
            }
            free(config->symbolic_links);
        }
        if (config->recursion_level) {
            free(config->recursion_level);
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
            if (config->realtime->dirtb) {
                OSHash_Free(config->realtime->dirtb);
            }
#ifdef WIN32
            CloseEventLog(config->realtime->evt);
#endif
            free(config->realtime);
        }
        if (config->prefilter_cmd) {
            free(config->prefilter_cmd);
        }

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

static char **get_paths_from_env_variable (char *environment_variable) {

    char **paths =NULL;

#ifdef WIN32
    char expandedpath[PATH_MAX + 1];

    if(!ExpandEnvironmentStrings(environment_variable, expandedpath, PATH_MAX + 1)){
        merror("Could not expand the environment variable %s (%ld)", expandedpath, GetLastError());
    }

    /* The env. variable may have multiples paths split by ; */
    paths = OS_StrBreak(';', expandedpath, MAX_DIR_SIZE);

    for (int i = 0; paths[i]; i++) {
        str_lowercase(paths[i]);
    }

#else
    char *expandedpath = NULL;

    if(environment_variable[0] == '$') {
        environment_variable++;
    }

    if(expandedpath = getenv(environment_variable), expandedpath) {
        /* The env. variable may have multiples paths split by : */
        paths = OS_StrBreak(':', expandedpath, MAX_DIR_SIZE);
    }

#endif

    return paths;
}

static int process_option_regex(char *option, OSMatch ***syscheck_option, xml_node *node) {

    unsigned int counter_opt = 0;
    OSMatch *mt_pt;

    if (!syscheck_option[0]) {
        os_calloc(2, sizeof(OSMatch *), syscheck_option[0]);
        syscheck_option[0][0] = NULL;
        syscheck_option[0][1] = NULL;
    } else {
        while (syscheck_option[0][counter_opt] != NULL) {
            counter_opt++;
        }
        os_realloc(syscheck_option[0], sizeof(OSMatch *) * (counter_opt + 2),
                    syscheck_option[0]);
        syscheck_option[0][counter_opt + 1] = NULL;
    }

    os_calloc(1, sizeof(OSMatch), syscheck_option[0][counter_opt]);
    mdebug1("Found %s regex node %s", option, node->content);

    if (!OSMatch_Compile(node->content, syscheck_option[0][counter_opt], 0)) {
        mt_pt = (OSMatch *)syscheck_option[0][counter_opt];
        merror(REGEX_COMPILE, node->content, mt_pt->error);
        return (0);
    }
    mdebug1("Found %s regex node %s OK?", option, node->content);
    mdebug1("Found %s regex size %d", option, counter_opt);

    return 1;
}

static void process_option(char ***syscheck_option, xml_node *node) {

    unsigned int counter_opt = 0;
    char **new_opt = NULL;

    /* We attempt to expand environment variables */
    if (new_opt = get_paths_from_env_variable(node->content), !new_opt) {
        os_calloc(2, sizeof(char *), new_opt);
        os_strdup(node->content, new_opt[0]);
        new_opt[1] = NULL;
    }

    if (syscheck_option[0]) {
        while (syscheck_option[0][counter_opt] != NULL) {
            counter_opt++;
        }
    }

    for (int i = 0; new_opt[i]; i++) {
        if (!os_IsStrOnArray(node->content, syscheck_option[0])) {
            os_realloc(syscheck_option[0], sizeof(char *) * (counter_opt + 2),
                        syscheck_option[0]);
            os_strdup(new_opt[i], syscheck_option[0][counter_opt]);
            syscheck_option[0][counter_opt + 1] = NULL;
            counter_opt++;
        }
        os_free(new_opt[i]);
    }
    os_free(new_opt);
}

static void fim_set_check_all(int *opt) {
    *opt |= CHECK_MD5SUM;
    *opt |= CHECK_SHA1SUM;
    *opt |= CHECK_SHA256SUM;
    *opt |= CHECK_PERM;
    *opt |= CHECK_SIZE;
    *opt |= CHECK_OWNER;
    *opt |= CHECK_GROUP;
    *opt |= CHECK_MTIME;
    *opt |= CHECK_INODE;
#ifdef WIN32
    *opt |= CHECK_ATTRS;
#endif
}
