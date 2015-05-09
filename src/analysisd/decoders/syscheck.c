/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Syscheck decoder */

#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "config.h"
#include "alerts/alerts.h"
#include "decoder.h"

typedef struct __sdb {
    char buf[OS_MAXSTR + 1];
    char comment[OS_MAXSTR + 1];

    char size[OS_FLSIZE + 1];
    char perm[OS_FLSIZE + 1];
    char owner[OS_FLSIZE + 1];
    char gowner[OS_FLSIZE + 1];
    char md5[OS_FLSIZE + 1];
    char sha1[OS_FLSIZE + 1];

    char agent_cp[MAX_AGENTS + 1][1];
    char *agent_ips[MAX_AGENTS + 1];
    FILE *agent_fps[MAX_AGENTS + 1];

    int db_err;

    /* Ids for decoder */
    int id1;
    int id2;
    int id3;
    int idn;
    int idd;

    /* Syscheck rule */
    OSDecoderInfo  *syscheck_dec;

    /* File search variables */
    fpos_t init_pos;

} _sdb; /* syscheck db information */

/* Local variables */
static _sdb sdb;


/* Initialize the necessary information to process the syscheck information */
void SyscheckInit()
{
    int i = 0;

    sdb.db_err = 0;

    for (; i <= MAX_AGENTS; i++) {
        sdb.agent_ips[i] = NULL;
        sdb.agent_fps[i] = NULL;
        sdb.agent_cp[i][0] = '0';
    }

    /* Clear db memory */
    memset(sdb.buf, '\0', OS_MAXSTR + 1);
    memset(sdb.comment, '\0', OS_MAXSTR + 1);

    memset(sdb.size, '\0', OS_FLSIZE + 1);
    memset(sdb.perm, '\0', OS_FLSIZE + 1);
    memset(sdb.owner, '\0', OS_FLSIZE + 1);
    memset(sdb.gowner, '\0', OS_FLSIZE + 1);
    memset(sdb.md5, '\0', OS_FLSIZE + 1);
    memset(sdb.sha1, '\0', OS_FLSIZE + 1);

    /* Create decoder */
    os_calloc(1, sizeof(OSDecoderInfo), sdb.syscheck_dec);
    sdb.syscheck_dec->id = getDecoderfromlist(SYSCHECK_MOD);
    sdb.syscheck_dec->name = SYSCHECK_MOD;
    sdb.syscheck_dec->type = OSSEC_RL;
    sdb.syscheck_dec->fts = 0;

    sdb.id1 = getDecoderfromlist(SYSCHECK_MOD);
    sdb.id2 = getDecoderfromlist(SYSCHECK_MOD2);
    sdb.id3 = getDecoderfromlist(SYSCHECK_MOD3);
    sdb.idn = getDecoderfromlist(SYSCHECK_NEW);
    sdb.idd = getDecoderfromlist(SYSCHECK_DEL);

    debug1("%s: SyscheckInit completed.", ARGV0);
    return;
}

/* Check if the db is completed for that specific agent */
#define DB_IsCompleted(x) (sdb.agent_cp[x][0] == '1')?1:0

static void __setcompleted(const char *agent)
{
    FILE *fp;

    /* Get agent file */
    snprintf(sdb.buf, OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(sdb.buf, "w");
    if (fp) {
        fprintf(fp, "#!X");
        fclose(fp);
    }
}

static int __iscompleted(const char *agent)
{
    FILE *fp;

    /* Get agent file */
    snprintf(sdb.buf, OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(sdb.buf, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Set the database of a specific agent as completed */
static void DB_SetCompleted(const Eventinfo *lf)
{
    int i = 0;

    /* Find file pointer */
    while (sdb.agent_ips[i] != NULL &&  i < MAX_AGENTS) {
        if (strcmp(sdb.agent_ips[i], lf->location) == 0) {
            /* Return if already set as completed */
            if (DB_IsCompleted(i)) {
                return;
            }

            __setcompleted(lf->location);

            /* Set as completed in memory */
            sdb.agent_cp[i][0] = '1';
            return;
        }

        i++;
    }
}


/* Return the file pointer to be used to verify the integrity */
static FILE *DB_File(const char *agent, int *agent_id)
{
    int i = 0;

    /* Find file pointer */
    while (sdb.agent_ips[i] != NULL  &&  i < MAX_AGENTS) {
        if (strcmp(sdb.agent_ips[i], agent) == 0) {
            /* Point to the beginning of the file */
            fseek(sdb.agent_fps[i], 0, SEEK_SET);
            *agent_id = i;
            return (sdb.agent_fps[i]);
        }

        i++;
    }

    /* If here, our agent wasn't found */
    if (i == MAX_AGENTS) {
        merror("%s: Unable to open integrity file. Increase MAX_AGENTS.", ARGV0);
        return (NULL);
    }

    os_strdup(agent, sdb.agent_ips[i]);

    /* Get agent file */
    snprintf(sdb.buf, OS_FLSIZE , "%s/%s", SYSCHECK_DIR, agent);

    /* r+ to read and write. Do not truncate */
    sdb.agent_fps[i] = fopen(sdb.buf, "r+");
    if (!sdb.agent_fps[i]) {
        /* Try opening with a w flag, file probably does not exist */
        sdb.agent_fps[i] = fopen(sdb.buf, "w");
        if (sdb.agent_fps[i]) {
            fclose(sdb.agent_fps[i]);
            sdb.agent_fps[i] = fopen(sdb.buf, "r+");
        }
    }

    /* Check again */
    if (!sdb.agent_fps[i]) {
        merror("%s: Unable to open '%s'", ARGV0, sdb.buf);

        free(sdb.agent_ips[i]);
        sdb.agent_ips[i] = NULL;
        return (NULL);
    }

    /* Return the opened pointer (the beginning of it) */
    fseek(sdb.agent_fps[i], 0, SEEK_SET);
    *agent_id = i;

    /* Check if the agent was completed */
    if (__iscompleted(agent)) {
        sdb.agent_cp[i][0] = '1';
    }

    return (sdb.agent_fps[i]);
}

/* Search the DB for any entry related to the file being received */
static int DB_Search(const char *f_name, const char *c_sum, Eventinfo *lf)
{
    int p = 0;
    size_t sn_size;
    int agent_id;

    char *saved_sum;
    char *saved_name;

    FILE *fp;

    /* Get db pointer */
    fp = DB_File(lf->location, &agent_id);
    if (!fp) {
        merror("%s: Error handling integrity database.", ARGV0);
        sdb.db_err++;
        lf->data = NULL;
        return (0);
    }

    /* Read the integrity file and search for a possible entry */
    if (fgetpos(fp, &sdb.init_pos) == -1) {
        merror("%s: Error handling integrity database (fgetpos).", ARGV0);
        return (0);
    }

    /* Loop over the file */
    while (fgets(sdb.buf, OS_MAXSTR, fp) != NULL) {
        /* Ignore blank lines and lines with a comment */
        if (sdb.buf[0] == '\n' || sdb.buf[0] == '#') {
            fgetpos(fp, &sdb.init_pos); /* Get next location */
            continue;
        }

        /* Get name */
        saved_name = strchr(sdb.buf, ' ');
        if (saved_name == NULL) {
            merror("%s: Invalid integrity message in the database.", ARGV0);
            fgetpos(fp, &sdb.init_pos); /* Get next location */
            continue;
        }
        *saved_name = '\0';
        saved_name++;

        /* New format - with a timestamp */
        if (*saved_name == '!') {
            saved_name = strchr(saved_name, ' ');
            if (saved_name == NULL) {
                merror("%s: Invalid integrity message in the database", ARGV0);
                fgetpos(fp, &sdb.init_pos); /* Get next location */
                continue;
            }
            saved_name++;
        }

        /* Remove newline from saved_name */
        sn_size = strlen(saved_name);
        sn_size -= 1;
        if (saved_name[sn_size] == '\n') {
            saved_name[sn_size] = '\0';
        }

        /* If name is different, go to next one */
        if (strcmp(f_name, saved_name) != 0) {
            /* Save current location */
            fgetpos(fp, &sdb.init_pos);
            continue;
        }

        saved_sum = sdb.buf;

        /* First three bytes are for frequency check */
        saved_sum += 3;

        /* Checksum match, we can just return and keep going */
        if (strcmp(saved_sum, c_sum) == 0) {
            lf->data = NULL;
            return (0);
        }

        /* If we reached here, the checksum of the file has changed */
        if (saved_sum[-3] == '!') {
            p++;
            if (saved_sum[-2] == '!') {
                p++;
                if (saved_sum[-1] == '!') {
                    p++;
                } else if (saved_sum[-1] == '?') {
                    p += 2;
                }
            }
        }

        /* Check the number of changes */
        if (!Config.syscheck_auto_ignore) {
            sdb.syscheck_dec->id = sdb.id1;
        } else {
            switch (p) {
                case 0:
                    sdb.syscheck_dec->id = sdb.id1;
                    break;

                case 1:
                    sdb.syscheck_dec->id = sdb.id2;
                    break;

                case 2:
                    sdb.syscheck_dec->id = sdb.id3;
                    break;

                default:
                    lf->data = NULL;
                    return (0);
                    break;
            }
        }

        /* Add new checksum to the database */
        /* Commenting the file entry and adding a new one later */
        if (fsetpos(fp, &sdb.init_pos)) {
            merror("%s: Error handling integrity database (fsetpos).", ARGV0);
            return (0);
        }
        fputc('#', fp);

        /* Add the new entry at the end of the file */
        fseek(fp, 0, SEEK_END);
        fprintf(fp, "%c%c%c%s !%ld %s\n",
                '!',
                p >= 1 ? '!' : '+',
                p == 2 ? '!' : (p > 2) ? '?' : '+',
                c_sum,
                (long int)lf->time,
                f_name);
        fflush(fp);

        /* File deleted */
        if (c_sum[0] == '-' && c_sum[1] == '1') {
            sdb.syscheck_dec->id = sdb.idd;
            snprintf(sdb.comment, OS_MAXSTR,
                     "File '%.756s' was deleted. Unable to retrieve "
                     "checksum.", f_name);
        }

        /* If file was re-added, do not compare changes */
        else if (saved_sum[0] == '-' && saved_sum[1] == '1') {
            sdb.syscheck_dec->id = sdb.idn;
            snprintf(sdb.comment, OS_MAXSTR,
                     "File '%.756s' was re-added.", f_name);
        }

        else {
            int oldperm = 0, newperm = 0;

            /* Provide more info about the file change */
            const char *oldsize = NULL, *newsize = NULL;
            char *olduid = NULL, *newuid = NULL;
            char *c_oldperm = NULL, *c_newperm = NULL;
            char *oldgid = NULL, *newgid = NULL;
            char *oldmd5 = NULL, *newmd5 = NULL;
            char *oldsha1 = NULL, *newsha1 = NULL;

            oldsize = saved_sum;
            newsize = c_sum;

            c_oldperm = strchr(saved_sum, ':');
            c_newperm = strchr(c_sum, ':');

            /* Get old/new permissions */
            if (c_oldperm && c_newperm) {
                *c_oldperm = '\0';
                c_oldperm++;

                *c_newperm = '\0';
                c_newperm++;

                /* Get old/new uid/gid */
                olduid = strchr(c_oldperm, ':');
                newuid = strchr(c_newperm, ':');

                if (olduid && newuid) {
                    *olduid = '\0';
                    *newuid = '\0';
                    olduid++;
                    newuid++;

                    oldgid = strchr(olduid, ':');
                    newgid = strchr(newuid, ':');

                    if (oldgid && newgid) {
                        *oldgid = '\0';
                        *newgid = '\0';
                        oldgid++;
                        newgid++;

                        /* Get MD5 */
                        oldmd5 = strchr(oldgid, ':');
                        newmd5 = strchr(newgid, ':');

                        if (oldmd5 && newmd5) {
                            *oldmd5 = '\0';
                            *newmd5 = '\0';
                            oldmd5++;
                            newmd5++;

                            /* Get SHA-1 */
                            oldsha1 = strchr(oldmd5, ':');
                            newsha1 = strchr(newmd5, ':');

                            if (oldsha1 && newsha1) {
                                *oldsha1 = '\0';
                                *newsha1 = '\0';
                                oldsha1++;
                                newsha1++;
                            }
                        }
                    }
                }
            }

            /* Get integer values */
            if (c_newperm && c_oldperm) {
                newperm = atoi(c_newperm);
                oldperm = atoi(c_oldperm);
            }

            /* Generate size message */
            if (!oldsize || !newsize || strcmp(oldsize, newsize) == 0) {
                sdb.size[0] = '\0';
            } else {
                snprintf(sdb.size, OS_FLSIZE,
                         "Size changed from '%s' to '%s'\n",
                         oldsize, newsize);

                os_strdup(oldsize, lf->size_before);
                os_strdup(newsize, lf->size_after);
            }

            /* Permission message */
            if (oldperm == newperm) {
                sdb.perm[0] = '\0';
            } else if (oldperm > 0 && newperm > 0) {

                snprintf(sdb.perm, OS_FLSIZE, "Permissions changed from "
                         "'%c%c%c%c%c%c%c%c%c' "
                         "to '%c%c%c%c%c%c%c%c%c'\n",
                         (oldperm & S_IRUSR) ? 'r' : '-',
                         (oldperm & S_IWUSR) ? 'w' : '-',

                         (oldperm & S_ISUID) ? 's' :
                         (oldperm & S_IXUSR) ? 'x' : '-',

                         (oldperm & S_IRGRP) ? 'r' : '-',
                         (oldperm & S_IWGRP) ? 'w' : '-',

                         (oldperm & S_ISGID) ? 's' :
                         (oldperm & S_IXGRP) ? 'x' : '-',

                         (oldperm & S_IROTH) ? 'r' : '-',
                         (oldperm & S_IWOTH) ? 'w' : '-',

                         (oldperm & S_ISVTX) ? 't' :
                         (oldperm & S_IXOTH) ? 'x' : '-',



                         (newperm & S_IRUSR) ? 'r' : '-',
                         (newperm & S_IWUSR) ? 'w' : '-',

                         (newperm & S_ISUID) ? 's' :
                         (newperm & S_IXUSR) ? 'x' : '-',


                         (newperm & S_IRGRP) ? 'r' : '-',
                         (newperm & S_IWGRP) ? 'w' : '-',

                         (newperm & S_ISGID) ? 's' :
                         (newperm & S_IXGRP) ? 'x' : '-',

                         (newperm & S_IROTH) ? 'r' : '-',
                         (newperm & S_IWOTH) ? 'w' : '-',

                         (newperm & S_ISVTX) ? 't' :
                         (newperm & S_IXOTH) ? 'x' : '-');

                lf->perm_before = oldperm;
                lf->perm_after = newperm;
            }

            /* Ownership message */
            if (!newuid || !olduid || strcmp(newuid, olduid) == 0) {
                sdb.owner[0] = '\0';
            } else {
                snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s', "
                         "now it is '%s'\n",
                         olduid, newuid);


                os_strdup(olduid, lf->owner_before);
                os_strdup(newuid, lf->owner_after);
            }

            /* Group ownership message */
            if (!newgid || !oldgid || strcmp(newgid, oldgid) == 0) {
                sdb.gowner[0] = '\0';
            } else {
                snprintf(sdb.gowner, OS_FLSIZE, "Group ownership was '%s', "
                         "now it is '%s'\n",
                         oldgid, newgid);
                os_strdup(oldgid, lf->gowner_before);
                os_strdup(newgid, lf->gowner_after);
            }

            /* MD5 message */
            if (!newmd5 || !oldmd5 || strcmp(newmd5, oldmd5) == 0) {
                sdb.md5[0] = '\0';
            } else {
                snprintf(sdb.md5, OS_FLSIZE, "Old md5sum was: '%s'\n"
                         "New md5sum is : '%s'\n",
                         oldmd5, newmd5);
                os_strdup(oldmd5, lf->md5_before);
                os_strdup(newmd5, lf->md5_after);
            }

            /* SHA-1 message */
            if (!newsha1 || !oldsha1 || strcmp(newsha1, oldsha1) == 0) {
                sdb.sha1[0] = '\0';
            } else {
                snprintf(sdb.sha1, OS_FLSIZE, "Old sha1sum was: '%s'\n"
                         "New sha1sum is : '%s'\n",
                         oldsha1, newsha1);
                os_strdup(oldsha1, lf->sha1_before);
                os_strdup(newsha1, lf->sha1_after);
            }
            os_strdup(f_name, lf->filename);

            /* Provide information about the file */
            snprintf(sdb.comment, OS_MAXSTR, "Integrity checksum changed for: "
                     "'%.756s'\n"
                     "%s"
                     "%s"
                     "%s"
                     "%s"
                     "%s"
                     "%s"
                     "%s%s",
                     f_name,
                     sdb.size,
                     sdb.perm,
                     sdb.owner,
                     sdb.gowner,
                     sdb.md5,
                     sdb.sha1,
                     lf->data == NULL ? "" : "What changed:\n",
                     lf->data == NULL ? "" : lf->data
                    );
        }

        /* Create a new log message */
        free(lf->full_log);
        os_strdup(sdb.comment, lf->full_log);
        lf->log = lf->full_log;
        lf->data = NULL;

        /* Set decoder */
        lf->decoder_info = sdb.syscheck_dec;

        return (1);

    } /* Continue */

    /* If we reach here, this file is not present in our database */
    fseek(fp, 0, SEEK_END);
    fprintf(fp, "+++%s !%ld %s\n", c_sum, (long int)lf->time, f_name);
    fflush(fp);

    /* Alert if configured to notify on new files */
    if ((Config.syscheck_alert_new == 1) && (DB_IsCompleted(agent_id))) {
        sdb.syscheck_dec->id = sdb.idn;

        /* New file message */
        snprintf(sdb.comment, OS_MAXSTR,
                 "New file '%.756s' "
                 "added to the file system.", f_name);

        /* Create a new log message */
        free(lf->full_log);
        os_strdup(sdb.comment, lf->full_log);
        lf->log = lf->full_log;

        /* Set decoder */
        lf->decoder_info = sdb.syscheck_dec;
        lf->data = NULL;

        return (1);
    }

    lf->data = NULL;
    return (0);
}

/* Special decoder for syscheck
 * Not using the default decoding lib for simplicity
 * and to be less resource intensive
 */
int DecodeSyscheck(Eventinfo *lf)
{
    const char *c_sum;
    char *f_name;

    /* Every syscheck message must be in the following format:
     * checksum filename
     */
    f_name = strchr(lf->log, ' ');
    if (f_name == NULL) {
        /* If we don't have a valid syscheck message, it may be
         * a database completed message
         */
        if (strcmp(lf->log, HC_SK_DB_COMPLETED) == 0) {
            DB_SetCompleted(lf);
            return (0);
        }

        merror(SK_INV_MSG, ARGV0);
        return (0);
    }

    /* Zero to get the check sum */
    *f_name = '\0';
    f_name++;

    /* Get diff */
    lf->data = strchr(f_name, '\n');
    if (lf->data) {
        *lf->data = '\0';
        lf->data++;
    } else {
        lf->data = NULL;
    }

    /* Check if file is supposed to be ignored */
    if (Config.syscheck_ignore) {
        char **ff_ig = Config.syscheck_ignore;

        while (*ff_ig) {
            if (strncasecmp(*ff_ig, f_name, strlen(*ff_ig)) == 0) {
                lf->data = NULL;
                return (0);
            }

            ff_ig++;
        }
    }

    /* Checksum is at the beginning of the log */
    c_sum = lf->log;

    /* Search for file changes */
    return (DB_Search(f_name, c_sum, lf));
}

