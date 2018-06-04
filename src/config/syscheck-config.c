/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck-config.h"
#include "config.h"


int dump_syscheck_entry(syscheck_config *syscheck, const char *entry, int vals, int reg, const char *restrictfile)
{
    unsigned int pl = 0;

    if (reg == 1) {
#ifdef WIN32
        if (syscheck->registry == NULL) {
            os_calloc(2, sizeof(registry), syscheck->registry);
            syscheck->registry[pl + 1].entry = NULL;
            syscheck->registry[pl].arch = vals;
            os_strdup(entry, syscheck->registry[pl].entry);
        } else {
            while (syscheck->registry[pl].entry != NULL) {
                pl++;
            }
            os_realloc(syscheck->registry, (pl + 2) * sizeof(registry),
                       syscheck->registry);
            syscheck->registry[pl + 1].entry = NULL;
            syscheck->registry[pl].arch = vals;
            os_strdup(entry, syscheck->registry[pl].entry);
        }

#endif
    }

    else {
        if (syscheck->dir == NULL) {
            os_calloc(2, sizeof(char *), syscheck->dir);
            syscheck->dir[pl + 1] = NULL;
            os_strdup(entry, syscheck->dir[pl]);

            os_calloc(2, sizeof(int), syscheck->opts);
            syscheck->opts[pl + 1] = 0;
            syscheck->opts[pl] = vals;

            os_calloc(2, sizeof(OSMatch *), syscheck->filerestrict);
            syscheck->filerestrict[pl] = NULL;
            syscheck->filerestrict[pl + 1] = NULL;
        } else {
            while (syscheck->dir[pl] != NULL) {
                pl++;
            }
            os_realloc(syscheck->dir, (pl + 2) * sizeof(char *),
                       syscheck->dir);
            syscheck->dir[pl + 1] = NULL;
            os_strdup(entry, syscheck->dir[pl]);

            os_realloc(syscheck->opts, (pl + 2) * sizeof(int),
                       syscheck->opts);
            syscheck->opts[pl + 1] = 0;
            syscheck->opts[pl] = vals;

            os_realloc(syscheck->filerestrict, (pl + 2) * sizeof(OSMatch *),
                       syscheck->filerestrict);
            syscheck->filerestrict[pl] = NULL;
            syscheck->filerestrict[pl + 1] = NULL;
        }
        if (restrictfile) {
            os_calloc(1, sizeof(OSMatch), syscheck->filerestrict[pl]);
            if (!OSMatch_Compile(restrictfile, syscheck->filerestrict[pl], 0)) {
                OSMatch *ptm;

                ptm = syscheck->filerestrict[pl];

                merror(REGEX_COMPILE, restrictfile,
                       ptm->error);
                free(syscheck->filerestrict[pl]);
                syscheck->filerestrict[pl] = NULL;
            }
        }
    }

    return (1);
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

        os_realloc(syscheck->registry_ignore,
                   sizeof(registry) * (ign_size + 2),
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
        os_calloc(2, sizeof(registry_regex),
                  syscheck->registry_ignore_regex);
        syscheck->registry_ignore_regex[0].regex = NULL;
        syscheck->registry_ignore_regex[1].regex = NULL;
    } else {
        while (syscheck->registry_ignore_regex[ign_size].regex != NULL) {
            ign_size++;
        }

        os_realloc(syscheck->registry_ignore_regex,
                   sizeof(registry_regex) * (ign_size + 2),
                   syscheck->registry_ignore_regex);
        syscheck->registry_ignore_regex[ign_size + 1].regex = NULL;
    }

    os_calloc(1, sizeof(OSMatch),
              syscheck->registry_ignore_regex[ign_size].regex);

    if (!OSMatch_Compile(regex,
                         syscheck->registry_ignore_regex[ign_size].regex, 0)) {
        mt_pt = syscheck->registry_ignore_regex[ign_size].regex;
        merror(REGEX_COMPILE, regex, mt_pt->error);
        return (0);
    }

    syscheck->registry_ignore_regex[ign_size].arch = arch;
    return 1;
}

/* Read Windows registry configuration */
int read_reg(syscheck_config *syscheck, char *entries, int arch)
{
    int i;
    char **entry;
    char *tmp_str;

    /* Get each entry separately */
    entry = OS_StrBreak(',', entries, MAX_DIR_SIZE); /* Max number */

    if (entry == NULL) {
        return (0);
    }

    while (*entry) {
        char *tmp_entry;

        tmp_entry = *entry;

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
                merror(SK_DUP, tmp_entry);
                return (1);
            }
            i++;
        }

        /* Add new entry */
        dump_syscheck_entry(syscheck, tmp_entry, arch, 1, NULL);

        /* Next entry */
        entry++;
    }

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
    const char *xml_real_time = "realtime";
    const char *xml_report_changes = "report_changes";
    const char *xml_restrict = "restrict";
    const char *xml_check_sha256sum = "check_sha256sum";
    const char *xml_check_whodata = "check_whodata";

    char *restrictfile = NULL;
    char **dir;
    char *tmp_str;
    dir = OS_StrBreak(',', dirs, MAX_DIR_SIZE); /* Max number */
    char **dir_org = dir;

    int ret = 0, i;

    /* Dir can not be null */
    if (dir == NULL) {
        return (0);
    }

    while (*dir) {
        int j = 0;
        int opts = 0;
        char *tmp_dir;

        char **attrs = NULL;
        char **values = NULL;

        tmp_dir = *dir;
        restrictfile = NULL;

        /* Remove spaces at the beginning */
        while (*tmp_dir == ' ') {
            tmp_dir++;
        }

        /* Remove spaces at the end */
        tmp_str = strchr(tmp_dir, ' ');
        if (tmp_str) {
            tmp_str++;

            /* Check if it is really at the end */
            if ((*tmp_str == '\0') || (*tmp_str == ' ')) {
                tmp_str--;
                *tmp_str = '\0';
            }
        }

        /* Get the options */
        if (!g_attrs || !g_values) {
            mwarn(SYSCHECK_NO_OPT, dirs);
            ret = 0;
            goto out_free;
        }

        attrs = g_attrs;
        values = g_values;

        while (*attrs && *values) {
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
                    opts |= CHECK_WHODATA;
                } else if (strcmp(*values, "no") == 0) {
		    opts &= ~ ( CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_PERM | CHECK_SHA256SUM
		       | CHECK_SIZE | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE | CHECK_WHODATA );
                } else {
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
		    opts &= ~ ( CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM);
                } else {
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
                    goto out_free;
                }
            }
            /* Check whodata */
            else if (strcmp(*attrs, xml_check_whodata) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_WHODATA;
                } else if (strcmp(*values, "no") == 0) {
                    opts &= ~ CHECK_WHODATA;
                } else {
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
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
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
                    goto out_free;
                }
            }
            else if (strcmp(*attrs, xml_real_time) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_REALTIME;
                } else if (strcmp(*values, "no") == 0) {
		    opts &= ~ CHECK_REALTIME;
                } else {
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
                    goto out_free;
                }
            } else if (strcmp(*attrs, xml_report_changes) == 0) {
                if (strcmp(*values, "yes") == 0) {
                    opts |= CHECK_SEECHANGES;
                } else if (strcmp(*values, "no") == 0) {
		    opts &= ~ CHECK_SEECHANGES;
                } else {
                    merror(SK_INV_OPT, *values, *attrs);
                    ret = 0;
                    goto out_free;
                }
            } else if (strcmp(*attrs, xml_restrict) == 0) {
                if (restrictfile) {
                    free(restrictfile);
                    restrictfile = NULL;
                }
                os_strdup(*values, restrictfile);
            } else {
                merror(SK_INV_ATTR, *attrs);
                ret = 0;
                goto out_free;
            }
            attrs++;
            values++;
        }

        /* You must have something set */
        if (opts == 0) {
            mwarn(SYSCHECK_NO_OPT, dirs);
            ret = 0;
            goto out_free;
        }

        /* Add directory - look for the last available */
        j = 0;
        while (syscheck->dir && syscheck->dir[j]) {
            /* Duplicate entry */
            if (strcmp(syscheck->dir[j], tmp_dir) == 0) {
                merror(SK_DUP, tmp_dir);
                ret = 1;
                goto out_free;
            }

            j++;
        }

        /* Check for glob */
	/* The mingw32 builder used by travis.ci can't find glob.h
	 * Yet glob must work on actual win32.
	 */
#ifndef __MINGW32__
        if (strchr(tmp_dir, '*') ||
                strchr(tmp_dir, '?') ||
                strchr(tmp_dir, '[')) {
            int gindex = 0;
            glob_t g;

            if (glob(tmp_dir, 0, NULL, &g) != 0) {
                merror(GLOB_ERROR, tmp_dir);
                ret = 1;
                goto out_free;
            }

            if (g.gl_pathv[0] == NULL) {
                merror(GLOB_NFOUND, tmp_dir);
                ret = 1;
                goto out_free;
            }

            while (g.gl_pathv[gindex]) {
                dump_syscheck_entry(syscheck, g.gl_pathv[gindex], opts, 0, restrictfile);
                gindex++;
            }

            globfree(&g);
        }

        else {
            dump_syscheck_entry(syscheck, tmp_dir, opts, 0, restrictfile);
        }
#else
	dump_syscheck_entry(syscheck, tmp_dir, opts, 0, restrictfile);
#endif

        if (restrictfile) {
            free(restrictfile);
            restrictfile = NULL;
        }

        /* Next entry */
        dir++;
    }

    ret = 1;

out_free:

    i = 0;
    while (dir_org[i]) {
        free(dir_org[i++]);
    }

    free(dir_org);
    free(restrictfile);

    return ret;
}

int Read_Syscheck(XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;

    /* XML Definitions */
    const char *xml_directories = "directories";
    const char *xml_registry = "windows_registry";
    const char *xml_time = "frequency";
    const char *xml_scanday = "scan_day";
    const char *xml_scantime = "scan_time";
    const char *xml_ignore = "ignore";
    const char *xml_registry_ignore = "registry_ignore";
    const char *xml_auto_ignore = "auto_ignore";
    const char *xml_alert_new_files = "alert_new_files";
    const char *xml_disabled = "disabled";
    const char *xml_scan_on_start = "scan_on_start";
    const char *xml_prefilter_cmd = "prefilter_cmd";
    const char *xml_skip_nfs = "skip_nfs";
    const char *xml_nodiff = "nodiff";

#ifdef WIN32
    const char *xml_arch = "arch";
    const char *xml_32bit = "32bit";
    const char *xml_64bit = "64bit";
    const char *xml_both = "both";
#endif

    /* Configuration example
    <directories check_all="yes">/etc,/usr/bin</directories>
    <directories check_owner="yes" check_group="yes" check_perm="yes"
    check_sum="yes">/var/log</directories>
    */

    syscheck_config *syscheck;
    syscheck = (syscheck_config *)configp;
    unsigned int nodiff_size = 0;

    while (node[i]) {
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
            ExpandEnvironmentStrings(node[i]->content, dirs, sizeof(dirs) - 1);
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
            if (node[i]->attributes) {
                if (strcmp(node[i]->attributes[0], xml_arch) == 0) {
                    if (strcmp(node[i]->values[0], xml_32bit) == 0) {
                        if (!read_reg(syscheck, node[i]->content, ARCH_32BIT))
                            return (OS_INVALID);
                    } else if (strcmp(node[i]->values[0], xml_64bit) == 0) {
                        if (!read_reg(syscheck, node[i]->content, ARCH_64BIT))
                            return (OS_INVALID);
                    } else if (strcmp(node[i]->values[0], xml_both) == 0) {
                        if (!(read_reg(syscheck, node[i]->content, ARCH_32BIT) &&
                            read_reg(syscheck, node[i]->content, ARCH_64BIT)))
                            return (OS_INVALID);
                    } else {
                        merror(XML_INVATTR, node[i]->attributes[0], node[i]->content);
                        return OS_INVALID;
                    }
                } else {
                    merror(XML_INVATTR, node[i]->attributes[0], node[i]->content);
                    return OS_INVALID;
                }

            } else if (!read_reg(syscheck, node[i]->content, ARCH_32BIT)) {
                return (OS_INVALID);
            }
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
                syscheck->skip_nfs = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_nfs = 0;
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

            ExpandEnvironmentStrings(node[i]->content, new_ig, 2047);

            free(node[i]->content);
            node[i]->content = new_ig;
#endif
            /* Add if regex */
            if (node[i]->attributes && node[i]->values) {
                if (node[i]->attributes[0] && node[i]->values[0] &&
                        (strcmp(node[i]->attributes[0], "type") == 0) &&
                        (strcmp(node[i]->values[0], "sregex") == 0)) {
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
                    merror(SK_INV_ATTR, node[i]->attributes[0]);
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

            ExpandEnvironmentStrings(node[i]->content, new_nodiff, 2047);

            free(node[i]->content);
            node[i]->content = new_nodiff;
#endif
            /* Add if regex */
            if (node[i]->attributes && node[i]->values) {
                if (node[i]->attributes[0] && node[i]->values[0] &&
                        (strcmp(node[i]->attributes[0], "type") == 0) &&
                        (strcmp(node[i]->values[0], "sregex") == 0)) {
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
                    merror(SK_INV_ATTR, node[i]->attributes[0]);
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
            char cmd[OS_MAXSTR];
            struct stat statbuf;

#ifdef WIN32
            ExpandEnvironmentStrings(node[i]->content, cmd, sizeof(cmd) - 1);
#else
            strncpy(cmd, node[i]->content, sizeof(cmd) - 1);
#endif

            if (strlen(cmd) > 0) {
                char statcmd[OS_MAXSTR];
                char *ix;
                strncpy(statcmd, cmd, sizeof(statcmd) - 1);
                if (NULL != (ix = strchr(statcmd, ' '))) {
                    *ix = '\0';
                }
                if (stat(statcmd, &statbuf) == 0) {
                    /* More checks needed (perms, owner, etc.) */
                    os_calloc(1, strlen(cmd) + 1, syscheck->prefilter_cmd);
                    strncpy(syscheck->prefilter_cmd, cmd, strlen(cmd));
                } else {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    return (0);
}


/* return a text version of the directory check option bits,
 * in a provided string buffer
 */
char *syscheck_opts2str(char *buf, int buflen, int opts) {
    int left = buflen;
    int i;
    int check_bits[] = {
        CHECK_PERM,
        CHECK_SIZE,
        CHECK_OWNER,
        CHECK_GROUP,
        CHECK_MD5SUM,
        CHECK_SHA1SUM,
        CHECK_SHA256SUM,
        CHECK_REALTIME,
        CHECK_SEECHANGES,
        CHECK_MTIME,
        CHECK_INODE,
        CHECK_WHODATA,
	0
	};
    char *check_strings[] = {
        "perm",
        "size",
        "owner",
        "group",
    	"md5sum",
        "sha1sum",
        "sha256sum",
        "realtime",
        "report_changes",
        "mtime",
        "inode",
        "whodata",
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
    syscheck_config test_syscheck = { .tsleep = 0 };

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
        free(config->remote_db);
        free(config->db);
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
            }
            free(config->dir);
            free(config->filerestrict);
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
            }
            free(config->registry);
        }
        if (config->reg_fp) {
            fclose(config->reg_fp);
        }
    #endif
        if (config->fp) {
            OSHash_Free(config->fp);
        }

        if (config->realtime) {
            OSHash_Free(config->realtime->dirtb);
#ifdef WIN32
            CloseEventLog(config->realtime->evt);
#endif
            free(config->realtime);
        }
        free(config->prefilter_cmd);
    }
}
