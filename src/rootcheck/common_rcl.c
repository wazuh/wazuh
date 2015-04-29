/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"

/* Prototypes */
static char *_rkcl_getfp(FILE *fp, char *buf);
static int   _rkcl_is_name(const char *buf);
static int   _rkcl_get_vars(OSStore *vars, char *nbuf);
static char *_rkcl_get_name(char *buf, char *ref, int *condition);
static char *_rkcl_get_pattern(char *value);
static char *_rkcl_get_value(char *buf, int *type);

/* Types of values */
#define RKCL_TYPE_FILE      1
#define RKCL_TYPE_REGISTRY  2
#define RKCL_TYPE_PROCESS   3
#define RKCL_TYPE_DIR       4

#define RKCL_COND_ALL       0x001
#define RKCL_COND_ANY       0x002
#define RKCL_COND_REQ       0x004
#define RKCL_COND_INV       0x010


#ifdef WIN32
char *_rkcl_getrootdir(char *root_dir, int dir_size)
{
    char final_file[2048 + 1];
    char *tmp;

    final_file[0] = '\0';
    final_file[2048] = '\0';

    ExpandEnvironmentStrings("%WINDIR%", final_file, 2047);

    tmp = strchr(final_file, '\\');
    if (tmp) {
        *tmp = '\0';
        strncpy(root_dir, final_file, dir_size);
        return (root_dir);
    }

    return (NULL);
}
#endif

/* Get next available buffer in file */
static char *_rkcl_getfp(FILE *fp, char *buf)
{
    while (fgets(buf, OS_SIZE_1024, fp) != NULL) {
        char *nbuf;

        /* Remove end of line */
        nbuf = strchr(buf, '\n');
        if (nbuf) {
            *nbuf = '\0';
        }

        /* Assign buf to be used */
        nbuf = buf;

        /* Exclude commented lines or blanked ones */
        while (*nbuf != '\0') {
            if (*nbuf == ' ' || *nbuf == '\t') {
                nbuf++;
                continue;
            } else if (*nbuf == '#') {
                *nbuf = '\0';
                continue;
            } else {
                break;
            }
        }

        /* Go to next line if empty */
        if (*nbuf == '\0') {
            continue;
        }

        return (nbuf);
    }

    return (NULL);
}

static int _rkcl_is_name(const char *buf)
{
    if (*buf == '[' && buf[strlen(buf) - 1] == ']') {
        return (1);
    }
    return (0);
}

static int _rkcl_get_vars(OSStore *vars, char *nbuf)
{
    char *var_value;
    char *tmp;

    /* If not a variable, return 0 */
    if (*nbuf != '$') {
        return (0);
    }

    /* Remove semicolon from the end */
    tmp = strchr(nbuf, ';');
    if (tmp) {
        *tmp = '\0';
    } else {
        return (-1);
    }

    /* Get value */
    tmp = strchr(nbuf, '=');
    if (tmp) {
        *tmp = '\0';
        tmp++;
    } else {
        return (-1);
    }

    /* Dump the variable options */
    os_strdup(tmp, var_value);

    /* Add entry to the storage */
    OSStore_Put(vars, nbuf, var_value);
    return (1);
}

static char *_rkcl_get_name(char *buf, char *ref, int *condition)
{
    char *tmp_location;
    char *tmp_location2;
    *condition = 0;

    /* Check if name is valid */
    if (!_rkcl_is_name(buf)) {
        return (NULL);
    }

    /* Set name */
    buf++;
    tmp_location = strchr(buf, ']');
    if (!tmp_location) {
        return (NULL);
    }
    *tmp_location = '\0';

    /* Get condition */
    tmp_location++;
    if (*tmp_location != ' ' && tmp_location[1] != '[') {
        return (NULL);
    }
    tmp_location += 2;

    tmp_location2 = strchr(tmp_location, ']');
    if (!tmp_location2) {
        return (NULL);
    }
    *tmp_location2 = '\0';
    tmp_location2++;

    /* Get condition */
    if (strcmp(tmp_location, "all") == 0) {
        *condition |= RKCL_COND_ALL;
    } else if (strcmp(tmp_location, "any") == 0) {
        *condition |= RKCL_COND_ANY;
    } else if (strcmp(tmp_location, "any required") == 0) {
        *condition |= RKCL_COND_ANY;
        *condition |= RKCL_COND_REQ;
    } else if (strcmp(tmp_location, "all required") == 0) {
        *condition |= RKCL_COND_ALL;
        *condition |= RKCL_COND_REQ;
    } else {
        *condition = RKCL_COND_INV;
        return (NULL);
    }

    /* Get reference */
    if (*tmp_location2 != ' ' && tmp_location2[1] != '[') {
        return (NULL);
    }

    tmp_location2 += 2;
    tmp_location = strchr(tmp_location2, ']');
    if (!tmp_location) {
        return (NULL);
    }
    *tmp_location = '\0';

    /* Copy reference */
    strncpy(ref, tmp_location2, 255);

    return (strdup(buf));
}

static char *_rkcl_get_pattern(char *value)
{
    while (*value != '\0') {
        if ((*value == ' ') && (value[1] == '-') &&
                (value[2] == '>') && (value[3] == ' ')) {
            *value = '\0';
            value += 4;

            return (value);
        }
        value++;
    }

    return (NULL);
}

static char *_rkcl_get_value(char *buf, int *type)
{
    char *tmp_str;
    char *value;

    /* Zero type before using it to make sure return is valid
     * in case of error.
     */
    *type = 0;

    value = strchr(buf, ':');
    if (value == NULL) {
        return (NULL);
    }

    *value = '\0';
    value++;

    tmp_str = strchr(value, ';');
    if (tmp_str == NULL) {
        return (NULL);
    }
    *tmp_str = '\0';

    /* Get types - removing negate flag (using later) */
    if (*buf == '!') {
        buf++;
    }

    if (strcmp(buf, "f") == 0) {
        *type = RKCL_TYPE_FILE;
    } else if (strcmp(buf, "r") == 0) {
        *type = RKCL_TYPE_REGISTRY;
    } else if (strcmp(buf, "p") == 0) {
        *type = RKCL_TYPE_PROCESS;
    } else if (strcmp(buf, "d") == 0) {
        *type = RKCL_TYPE_DIR;
    } else {
        return (NULL);
    }

    return (value);
}

int rkcl_get_entry(FILE *fp, const char *msg, OSList *p_list)
{
    int type = 0, condition = 0;
    char *nbuf;
    char buf[OS_SIZE_1024 + 2];
    char root_dir[OS_SIZE_1024 + 2];
    char final_file[2048 + 1];
    char ref[255 + 1];
    char *value;
    char *name = NULL;
    OSStore *vars;

    /* Initialize variables */
    memset(buf, '\0', sizeof(buf));
    memset(root_dir, '\0', sizeof(root_dir));
    memset(final_file, '\0', sizeof(final_file));
    memset(ref, '\0', sizeof(ref));

#ifdef WIN32
    /* Get Windows rootdir */
    _rkcl_getrootdir(root_dir, sizeof(root_dir) - 1);
    if (root_dir[0] == '\0') {
        merror(INVALID_ROOTDIR, ARGV0);
    }
#endif
    /* Get variables */
    vars = OSStore_Create();

    /* We first read all variables -- they must be defined at the top */
    while (1) {
        int rc_code = 0;
        nbuf = _rkcl_getfp(fp, buf);
        if (nbuf == NULL) {
            goto clean_return;
        }

        rc_code = _rkcl_get_vars(vars, nbuf);
        if (rc_code == 0) {
            break;
        } else if (rc_code == -1) {
            merror(INVALID_RKCL_VAR, ARGV0, nbuf);
            goto clean_return;
        }
    }

    /* Get first name */
    name = _rkcl_get_name(nbuf, ref, &condition);
    if (name == NULL || condition == RKCL_COND_INV) {
        merror(INVALID_RKCL_NAME, ARGV0, nbuf);
        goto clean_return;
    }

    /* Get the real entries */
    do {
        int g_found = 0;

        debug2("%s: DEBUG: Checking entry: '%s'.", ARGV0, name);

        /* Get each value */
        do {
            int negate = 0;
            int found = 0;
            value = NULL;

            nbuf = _rkcl_getfp(fp, buf);
            if (nbuf == NULL) {
                break;
            }

            /* First try to get the name, looking for new entries */
            if (_rkcl_is_name(nbuf)) {
                break;
            }

            /* Get value to look for */
            value = _rkcl_get_value(nbuf, &type);
            if (value == NULL) {
                merror(INVALID_RKCL_VALUE, ARGV0, nbuf);
                goto clean_return;
            }

            /* Get negate value */
            if (*value == '!') {
                negate = 1;
                value++;
            }

            /* Check for a file */
            if (type == RKCL_TYPE_FILE) {
                char *pattern = NULL;
                char *f_value = NULL;

                pattern = _rkcl_get_pattern(value);
                f_value = value;

                /* Get any variable */
                if (value[0] == '$') {
                    f_value = (char *) OSStore_Get(vars, value);
                    if (!f_value) {
                        merror(INVALID_RKCL_VAR, ARGV0, value);
                        continue;
                    }
                }

#ifdef WIN32
                else if (value[0] == '\\') {
                    final_file[0] = '\0';
                    final_file[sizeof(final_file) - 1] = '\0';

                    snprintf(final_file, sizeof(final_file) - 2, "%s%s",
                             root_dir, value);
                    f_value = final_file;
                } else {
                    final_file[0] = '\0';
                    final_file[sizeof(final_file) - 1] = '\0';

                    ExpandEnvironmentStrings(value, final_file,
                                             sizeof(final_file) - 2);
                    f_value = final_file;
                }
#endif

                debug2("%s: DEBUG: Checking file: '%s'.", ARGV0, f_value);
                if (rk_check_file(f_value, pattern)) {
                    debug1("%s: DEBUG: found file.", ARGV0);
                    found = 1;
                }
            }

#ifdef WIN32
            /* Check for a registry entry */
            else if (type == RKCL_TYPE_REGISTRY) {
                char *entry = NULL;
                char *pattern = NULL;

                /* Look for additional entries in the registry
                 * and a pattern to match.
                 */
                entry = _rkcl_get_pattern(value);
                if (entry) {
                    pattern = _rkcl_get_pattern(entry);
                }

                debug2("%s: DEBUG: Checking registry: '%s'.", ARGV0, value);
                if (is_registry(value, entry, pattern)) {
                    debug2("%s: DEBUG: found registry.", ARGV0);
                    found = 1;
                }

            }
#endif
            /* Check for a directory */
            else if (type == RKCL_TYPE_DIR) {
                char *file = NULL;
                char *pattern = NULL;
                char *f_value = NULL;
                char *dir = NULL;

                file = _rkcl_get_pattern(value);
                if (!file) {
                    merror(INVALID_RKCL_VAR, ARGV0, value);
                    continue;
                }

                pattern = _rkcl_get_pattern(file);

                /* Get any variable */
                if (value[0] == '$') {
                    f_value = (char *) OSStore_Get(vars, value);
                    if (!f_value) {
                        merror(INVALID_RKCL_VAR, ARGV0, value);
                        continue;
                    }
                } else {
                    f_value = value;
                }

                /* Check for multiple comma separated directories */
                dir = f_value;
                f_value = strchr(dir, ',');
                if (f_value) {
                    *f_value = '\0';
                }

                while (dir) {

                    debug2("%s: Checking dir: %s", ARGV0, dir);

                    short is_nfs = IsNFS(dir);
                    if( is_nfs == 1 && rootcheck.skip_nfs ) {
                        debug1("%s: DEBUG: rootcheck.skip_nfs enabled and %s is flagged as NFS.", ARGV0, dir);
                    }
                    else {
                        debug2("%s: DEBUG: %s => is_nfs=%d, skip_nfs=%d", ARGV0, dir, is_nfs, rootcheck.skip_nfs);

                        if (rk_check_dir(dir, file, pattern)) {
                            debug2("%s: DEBUG: Found dir.", ARGV0);
                            found = 1;
                        }
                    }

                    if (f_value) {
                        *f_value = ',';
                        f_value++;

                        dir = f_value;

                        f_value = strchr(dir, ',');
                        if (f_value) {
                            *f_value = '\0';
                        }
                    } else {
                        dir = NULL;
                    }
                }
            }

            /* Check for a process */
            else if (type == RKCL_TYPE_PROCESS) {
                debug2("%s: DEBUG: Checking process: '%s'.", ARGV0, value);
                if (is_process(value, p_list)) {
                    debug2("%s: DEBUG: found process.", ARGV0);
                    found = 1;
                }
            }

            /* Switch the values if ! is present */
            if (negate) {
                if (found) {
                    found = 0;
                } else {
                    found = 1;
                }
            }

            /* Check the conditions */
            if (condition & RKCL_COND_ANY) {
                debug2("%s: DEBUG: Condition ANY.", ARGV0);
                if (found) {
                    g_found = 1;
                }
            } else {
                /* Condition for ALL */
                debug2("%s: DEBUG: Condition ALL.", ARGV0);
                if (found && (g_found != -1)) {
                    g_found = 1;
                } else {
                    g_found = -1;
                }
            }
        } while (value != NULL);

        /* Alert if necessary */
        if (g_found == 1) {
            int j = 0;
            char op_msg[OS_SIZE_1024 + 1];
            char **p_alert_msg = rootcheck.alert_msg;

            while (1) {
                if (ref[0] != '\0') {
                    snprintf(op_msg, OS_SIZE_1024, "%s %s.%s"
                             " Reference: %s .", msg, name,
                             p_alert_msg[j] ? p_alert_msg[j] : "\0",
                             ref);
                } else {
                    snprintf(op_msg, OS_SIZE_1024, "%s %s.%s", msg,
                             name, p_alert_msg[j] ? p_alert_msg[j] : "\0");
                }

                if ((type == RKCL_TYPE_DIR) || (j == 0)) {
                    notify_rk(ALERT_POLICY_VIOLATION, op_msg);
                }

                if (p_alert_msg[j]) {
                    free(p_alert_msg[j]);
                    p_alert_msg[j] = NULL;
                    j++;

                    if (!p_alert_msg[j]) {
                        break;
                    }
                } else {
                    break;
                }
            }
        } else {
            int j = 0;
            while (rootcheck.alert_msg[j]) {
                free(rootcheck.alert_msg[j]);
                rootcheck.alert_msg[j] = NULL;
                j++;
            }

            /* Check if this entry is required for the rest of the file */
            if (condition & RKCL_COND_REQ) {
                goto clean_return;
            }
        }

        /* End if we don't have anything else */
        if (!nbuf) {
            goto clean_return;
        }

        /* Clean up name */
        if (name) {
            free(name);
            name = NULL;
        }

        /* Get name already read */
        name = _rkcl_get_name(nbuf, ref, &condition);
        if (!name) {
            merror(INVALID_RKCL_NAME, ARGV0, nbuf);
            goto clean_return;
        }
    } while (nbuf != NULL);

    /* Clean up memory */
clean_return:
    if (name) {
        free(name);
        name = NULL;
    }
    OSStore_Free(vars);

    return (1);
}

