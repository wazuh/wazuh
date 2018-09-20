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
#include "syscheck_op.h"
#include "wazuh_modules/wmodules.h"

/* Compare the first common fields between sum strings */
static int SumCompare(const char *s1, const char *s2);

static void InsertWhodata(const sk_sum_t * sum,char * user_name,char * effective_name, char * audit_name,char * group_name,char * process_id,char * process_name);

/* Initialize the necessary information to process the syscheck information */
void SyscheckInit()
{
    int i = 0;

    sdb.db_err = 0;

    for (; i <= MAX_AGENTS; i++) {
        sdb.agent_ips[i] = NULL;
        sdb.agent_fps[i] = NULL;
        sdb.agent_cp[i][0] = '0';
        sdb.syscheck_mutex[i] = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
        memset(sdb.buf[i], '\0', OS_MAXSTR + 1);
    }

    /* Clear db memory */
    memset(sdb.comment, '\0', OS_MAXSTR + 1);

    memset(sdb.size, '\0', OS_FLSIZE + 1);
    memset(sdb.perm, '\0', OS_FLSIZE + 1);
    memset(sdb.owner, '\0', OS_FLSIZE + 1);
    memset(sdb.gowner, '\0', OS_FLSIZE + 1);
    memset(sdb.md5, '\0', OS_FLSIZE + 1);
    memset(sdb.sha1, '\0', OS_FLSIZE + 1);
    memset(sdb.sha256, '\0', OS_FLSIZE + 1);
    memset(sdb.mtime, '\0', OS_FLSIZE + 1);
    memset(sdb.inode, '\0', OS_FLSIZE + 1);

    /* Create decoder */
    os_calloc(1, sizeof(OSDecoderInfo), sdb.syscheck_dec);
    sdb.syscheck_dec->id = getDecoderfromlist(SYSCHECK_MOD);
    sdb.syscheck_dec->name = SYSCHECK_MOD;
    sdb.syscheck_dec->type = OSSEC_RL;
    sdb.syscheck_dec->fts = 0;

    os_calloc(Config.decoder_order_size, sizeof(char *), sdb.syscheck_dec->fields);
    sdb.syscheck_dec->fields[SK_FILE] = "file";
    sdb.syscheck_dec->fields[SK_SIZE] = "size";
    sdb.syscheck_dec->fields[SK_PERM] = "perm";
    sdb.syscheck_dec->fields[SK_UID] = "uid";
    sdb.syscheck_dec->fields[SK_GID] = "gid";
    sdb.syscheck_dec->fields[SK_MD5] = "md5";
    sdb.syscheck_dec->fields[SK_SHA1] = "sha1";
    sdb.syscheck_dec->fields[SK_SHA256] = "sha256";
    sdb.syscheck_dec->fields[SK_UNAME] = "uname";
    sdb.syscheck_dec->fields[SK_GNAME] = "gname";
    sdb.syscheck_dec->fields[SK_INODE] = "inode";
    sdb.syscheck_dec->fields[SK_MTIME] = "mtime";
    sdb.syscheck_dec->fields[SK_CHFIELDS] = "changed_fields";

    sdb.syscheck_dec->fields[SK_USER_ID] = "user_id";
    sdb.syscheck_dec->fields[SK_USER_NAME] = "user_name";
    sdb.syscheck_dec->fields[SK_GROUP_ID] = "group_id";
    sdb.syscheck_dec->fields[SK_GROUP_NAME] = "group_name";
    sdb.syscheck_dec->fields[SK_PROC_NAME] = "process_name";
    sdb.syscheck_dec->fields[SK_AUDIT_ID] = "audit_uid";
    sdb.syscheck_dec->fields[SK_AUDIT_NAME] = "audit_name";
    sdb.syscheck_dec->fields[SK_EFFECTIVE_UID] = "effective_uid";
    sdb.syscheck_dec->fields[SK_EFFECTIVE_NAME] = "effective_name";
    sdb.syscheck_dec->fields[SK_PPID] = "ppid";
    sdb.syscheck_dec->fields[SK_PROC_ID] = "process_id";
    sdb.syscheck_dec->fields[SK_TAG] = "tag";

    sdb.id1 = getDecoderfromlist(SYSCHECK_MOD);
    sdb.idn = getDecoderfromlist(SYSCHECK_NEW);
    sdb.idd = getDecoderfromlist(SYSCHECK_DEL);

    mdebug1("SyscheckInit completed.");
}

/* Check if the db is completed for that specific agent */
#define DB_IsCompleted(x) (sdb.agent_cp[x][0] == '1')?1:0

static void __setcompleted(const char *agent,int id)
{
    FILE *fp;

    /* Get agent file */
    snprintf(sdb.buf[id], OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(sdb.buf[id], "w");
    if (fp) {
        fprintf(fp, "#!X");
        fclose(fp);
    }
}

static int __iscompleted(const char *agent,int id)
{
    FILE *fp;

    /* Get agent file */
    snprintf(sdb.buf[id], OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(sdb.buf[id], "r");
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

            w_mutex_lock(&sdb.syscheck_mutex[i]);
            __setcompleted(lf->location,i);

            /* Set as completed in memory */
            sdb.agent_cp[i][0] = '1';
            w_mutex_unlock(&sdb.syscheck_mutex[i]);
            return;
        }

        i++;
    }
}


/* Return the file pointer to be used to verify the integrity */
static FILE *DB_File(const char *agent, int *agent_id)
{
    int i;

    /* Find file pointer */
    for (i = 0; sdb.agent_ips[i] && i < MAX_AGENTS; i++) {
        if (strcmp(sdb.agent_ips[i], agent) == 0) {
            char buf[OS_MAXSTR + 1];

            snprintf(buf, OS_FLSIZE , "%s/%s", SYSCHECK_DIR, agent);

            if (!IsFile(buf)) {
                /* Point to the beginning of the file */
                w_mutex_lock(&sdb.syscheck_mutex[i]);
                snprintf(sdb.buf[i], OS_FLSIZE , "%s/%s", SYSCHECK_DIR, agent);
                fseek(sdb.agent_fps[i], 0, SEEK_SET);
                *agent_id = i;
                w_mutex_unlock(&sdb.syscheck_mutex[i]);
                return (sdb.agent_fps[i]);
            } else {
                // File was deleted. Close and let reopen.
                mwarn("Syscheck database '%s' has been deleted. Recreating.", agent);
                w_mutex_lock(&sdb.syscheck_mutex[i]);
                snprintf(sdb.buf[i], OS_FLSIZE , "%s/%s", SYSCHECK_DIR, agent);
                fclose(sdb.agent_fps[i]);
                free(sdb.agent_ips[i]);
                sdb.agent_ips[i] = NULL;
                w_mutex_unlock(&sdb.syscheck_mutex[i]);
                break;
            }
        }
    }

    /* If here, our agent wasn't found */
    if (i == MAX_AGENTS) {
        merror("Unable to open integrity file. Increase MAX_AGENTS.");
        return (NULL);
    }

    w_mutex_lock(&sdb.syscheck_mutex[i]);
    os_strdup(agent, sdb.agent_ips[i]);

    /* Get agent file */
    snprintf(sdb.buf[i], OS_FLSIZE , "%s/%s", SYSCHECK_DIR, agent);

    /* r+ to read and write. Do not truncate */
    sdb.agent_fps[i] = fopen(sdb.buf[i], "r+");
    if (!sdb.agent_fps[i]) {
        /* Try opening with a w flag, file probably does not exist */
        sdb.agent_fps[i] = fopen(sdb.buf[i], "w");
        if (sdb.agent_fps[i]) {
            fclose(sdb.agent_fps[i]);
            sdb.agent_fps[i] = fopen(sdb.buf[i], "r+");
        }
    }

    /* Check again */
    if (!sdb.agent_fps[i]) {
        merror("Unable to open '%s'", sdb.buf[i]);

        free(sdb.agent_ips[i]);
        sdb.agent_ips[i] = NULL;
        w_mutex_unlock(&sdb.syscheck_mutex[i]);
        return (NULL);
    }

    /* Return the opened pointer (the beginning of it) */
    fseek(sdb.agent_fps[i], 0, SEEK_SET);
    *agent_id = i;

    /* Check if the agent was completed */
    if (__iscompleted(agent,i)) {
        sdb.agent_cp[i][0] = '1';
    }

    w_mutex_unlock(&sdb.syscheck_mutex[i]);

    return (sdb.agent_fps[i]);
}

/* Search the DB for any entry related to the file being received */
static int DB_Search(const char *f_name, char *c_sum, char *w_sum, Eventinfo *lf)
{
    size_t sn_size;
    int agent_id;
    int result;

    int changes = 0;
    int st = 0;
    int sf = 0;
    int comment_buf = 0;

    char *saved_sum = NULL;
    char *saved_name = NULL;
    char *saved_time = NULL;
    char *saved_frec = NULL;

    FILE *fp;

    sk_sum_t oldsum = { .size = NULL };
    sk_sum_t newsum = { .size = NULL };

    char comment[OS_MAXSTR + 1] = {0};
    char perm[257] = {0};
    char size[257] = {0};
    char owner[257] = {0};
    char gowner[257] = {0};
    char md5[257] = {0};
    char sha1[257] = {0};
    char sha256[257] = {0};
    char mtime[257] = {0};
    char inode[257] = {0};
    char buf[OS_MAXSTR + 1] = {0};
    char user_name[OS_FLSIZE + 1] = {0};
    char audit_name[OS_FLSIZE + 1] = {0};
    char effective_name[OS_FLSIZE + 1] = {0};
    char group_name[OS_FLSIZE + 1] = {0};
    char process_id[OS_FLSIZE + 1] = {0};
    char process_name[OS_FLSIZE + 1] = {0};
    u_int16_t syscheck_decoder_id = 0;

    /* Get db pointer */
    fp = DB_File(lf->location, &agent_id);

    if (!fp) {
        merror("Error handling integrity database.");
        sdb.db_err++;
        lf->data = NULL;
        return (0);
    }

    w_mutex_lock(&sdb.syscheck_mutex[agent_id]);

    /* Read the integrity file and search for a possible entry */
    if (fgetpos(fp, &sdb.init_pos[agent_id]) == -1) {
        merror("Error handling integrity database (fgetpos).");
        w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
        return (0);
    }

    /* Loop over the file */
    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        /* Ignore blank lines and lines with a comment */
        if (buf[0] == '\n' || buf[0] == '#') {
            fgetpos(fp, &sdb.init_pos[agent_id]); /* Get next location */
            continue;
        }

        /* Get name */
        saved_name = strchr(buf, ' ');
        if (saved_name == NULL) {
            merror("Invalid integrity message in the database.");
            fgetpos(fp, &sdb.init_pos[agent_id]); /* Get next location */
            continue;
        }
        *saved_name = '\0';
        saved_name++;

        /* New format - with a timestamp */
        if (*saved_name == '!') {
            /* Get time */
            saved_time = saved_name;
            saved_time++;

            saved_name = strchr(saved_name, ' ');
            if (saved_name == NULL) {
                merror("Invalid integrity message in the database");
                fgetpos(fp, &sdb.init_pos[agent_id]); /* Get next location */
                continue;
            }
            *saved_name = '\0';
            saved_name++;
            st = atoi(saved_time);
        }

        if (saved_time == NULL) {
            merror("Invalid integrity message in the database");
            fgetpos(fp, &sdb.init_pos[agent_id]); /* Get next location */
            continue;
        }

        /* Remove newline from saved_name */
        sn_size = strlen(saved_name);
        sn_size -= 1;
        if (saved_name[sn_size] == '\n') {
            saved_name[sn_size] = '\0';
        }

        //Change in Windows paths all slashes for backslashes for compatibility agent<3.4 with manager>=3.4
        normalize_path(saved_name);

        /* If name is different, go to next one */
        if (strcmp(f_name, saved_name) != 0) {
            /* Save current location */
            fgetpos(fp, &sdb.init_pos[agent_id]);
            continue;
        }

        saved_sum = buf;

        /* First three bytes are for frequency check */
        saved_sum += 3;

        /* Checksum match, we can just return and keep going */
        if (SumCompare(saved_sum, c_sum) == 0) {
            lf->data = NULL;
            w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
            return (0);
        }
        /* Get frec */
        saved_frec = sdb.buf[agent_id];
        saved_frec[2] = '\0';
        sf = atoi(saved_frec);

        if (sf > 99) {
            sf = 0;
        }

        mdebug2("Agent: %d, location: <%s>, file: <%s>, sum: <%s>, saved: <%s>", agent_id, lf->location, f_name, c_sum, saved_sum);

        if (!Config.syscheck_auto_ignore) {
            syscheck_decoder_id = sdb.id1;
            sf = 1;
        } else {
            if (lf->time.tv_sec - st < Config.syscheck_ignore_time) {
                if (sf >= Config.syscheck_ignore_frequency) {
                    /* No send alert */
                    lf->data = NULL;
                    w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
                    return (0);
                }
                else {
                    syscheck_decoder_id = sdb.id1;
                    sf++;
                    if (sf > 99) {
                        sf = 99;
                    }
                }
            }
            else {
                syscheck_decoder_id = sdb.id1;
                sf = 1;
                st = lf->time.tv_sec;
            }
        }

        /* Add new checksum to the database */
        /* Commenting the file entry and adding a new one later */
        if (fsetpos(fp, &sdb.init_pos[agent_id])) {
            merror("Error handling integrity database (fsetpos).");
            w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
            return (0);
        }
        fputc('#', fp);

        /* Add the new entry at the end of the file */
        fseek(fp, 0, SEEK_END);
        fprintf(fp, "%02u:%s !%ld %s\n",
                sf,
                c_sum,
                (long int)st,
                f_name);
        fflush(fp);

        if (result = sk_decode_sum(&newsum, c_sum, w_sum), result != -1) {
            InsertWhodata(&newsum,user_name,effective_name,audit_name,group_name,process_id,process_name);
        }

        switch (result) {
        case -1:
            merror("Couldn't decode syscheck sum from log.");
            lf->data = NULL;
            sk_sum_clean(&newsum);
            w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
            return 0;

        case 0:
            switch (sk_decode_sum(&oldsum, saved_sum, NULL)) {
            case -1:
                merror("Couldn't decode syscheck sum from database.");
                lf->data = NULL;
                sk_sum_clean(&newsum);
                w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
                return 0;

            case 0:
                sk_fill_event(lf, f_name, &newsum);

                /* Generate size message */
                if (strcmp(oldsum.size, newsum.size) == 0) {
                    size[0] = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "size", ',');
                    snprintf(size, OS_FLSIZE,
                             "Size changed from '%s' to '%s'\n",
                             oldsum.size, newsum.size);

                    os_strdup(oldsum.size, lf->size_before);
                }

                /* Permission message */
                if (oldsum.perm == newsum.perm) {
                    perm[0] = '\0';
                } else if (oldsum.perm > 0 && newsum.perm > 0) {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "perm", ',');
                    char opstr[10];
                    char npstr[10];

                    strncpy(opstr, agent_file_perm(oldsum.perm), sizeof(opstr) - 1);
                    strncpy(npstr, agent_file_perm(newsum.perm), sizeof(npstr) - 1);
                    opstr[9] = npstr[9] = '\0';

                    snprintf(perm, OS_FLSIZE, "Permissions changed from "
                             "'%9.9s' to '%9.9s'\n", opstr, npstr);

                    lf->perm_before = oldsum.perm;
                }

                /* Ownership message */
                if (newsum.uid && oldsum.uid) {
                    if (strcmp(newsum.uid, oldsum.uid) == 0) {
                        owner[0] = '\0';
                    } else {
                        changes = 1;
                        wm_strcat(&lf->fields[SK_CHFIELDS].value, "uid", ',');
                        if (oldsum.uname && newsum.uname) {
                            snprintf(owner, OS_FLSIZE, "Ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum.uname, oldsum.uid, newsum.uname, newsum.uid);
                            os_strdup(oldsum.uname, lf->uname_before);
                        } else {
                            snprintf(owner, OS_FLSIZE, "Ownership was '%s', now it is '%s'\n", oldsum.uid, newsum.uid);
                        }
                        os_strdup(oldsum.uid, lf->owner_before);
                    }
                }

                /* Group ownership message */
                if (newsum.gid && oldsum.gid) {
                    if (strcmp(newsum.gid, oldsum.gid) == 0) {
                        gowner[0] = '\0';
                    } else {
                        changes = 1;
                        wm_strcat(&lf->fields[SK_CHFIELDS].value, "gid", ',');
                        if (oldsum.gname && newsum.gname) {
                            snprintf(gowner, OS_FLSIZE, "Group ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum.gname, oldsum.gid, newsum.gname, newsum.gid);
                            os_strdup(oldsum.gname, lf->gname_before);
                        } else {
                            snprintf(gowner, OS_FLSIZE, "Group ownership was '%s', now it is '%s'\n", oldsum.gid, newsum.gid);
                        }
                        os_strdup(oldsum.gid, lf->gowner_before);
                    }
                }
                /* MD5 message */
                if (!*newsum.md5 || !*oldsum.md5 || strcmp(newsum.md5, oldsum.md5) == 0) {
                    md5[0] = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "md5", ',');
                    snprintf(sdb.md5, OS_FLSIZE, "Old md5sum was: '%s'\nNew md5sum is : '%s'\n",
                             oldsum.md5, newsum.md5);
                    os_strdup(oldsum.md5, lf->md5_before);
                }

                /* SHA-1 message */
                if (!*newsum.sha1 || !*oldsum.sha1 || strcmp(newsum.sha1, oldsum.sha1) == 0) {
                    sha1[0] = '\0';
                } else {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha1", ',');
                    snprintf(sha1, OS_FLSIZE, "Old sha1sum was: '%s'\nNew sha1sum is : '%s'\n",
                             oldsum.sha1, newsum.sha1);
                    os_strdup(oldsum.sha1, lf->sha1_before);
                }

                /* SHA-256 message */
                if(newsum.sha256 && newsum.sha256[0] != '\0')
                {
                    if(oldsum.sha256) {
                        if (strcmp(newsum.sha256, oldsum.sha256) == 0) {
                            sha256[0] = '\0';
                        } else {
                            changes = 1;
                            wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha256", ',');
                            snprintf(sha256, OS_FLSIZE, "Old sha256sum was: '%s'\nNew sha256sum is : '%s'\n",
                                    oldsum.sha256, newsum.sha256);
                            os_strdup(oldsum.sha256, lf->sha256_before);
                        }
                    } else {
                        changes = 1;
                        wm_strcat(&lf->fields[SK_CHFIELDS].value, "sha256", ',');
                        snprintf(sha256, OS_FLSIZE, "New sha256sum is : '%s'\n", newsum.sha256);
                    }
                } else {
                    sha256[0] = '\0';
                }

                /* Modification time message */
                if (oldsum.mtime && newsum.mtime && oldsum.mtime != newsum.mtime) {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "mtime", ',');
                    char *old_ctime = strdup(ctime(&oldsum.mtime));
                    char *new_ctime = strdup(ctime(&newsum.mtime));
                    old_ctime[strlen(old_ctime) - 1] = '\0';
                    new_ctime[strlen(new_ctime) - 1] = '\0';

                    snprintf(mtime, OS_FLSIZE, "Old modification time was: '%s', now it is '%s'\n", old_ctime, new_ctime);
                    lf->mtime_before = oldsum.mtime;
                    free(old_ctime);
                    free(new_ctime);
                } else {
                    mtime[0] = '\0';
                }

                /* Inode message */
                if (oldsum.inode && newsum.inode && oldsum.inode != newsum.inode) {
                    changes = 1;
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, "inode", ',');
                    snprintf(inode, OS_FLSIZE, "Old inode was: '%ld', now it is '%ld'\n", oldsum.inode, newsum.inode);
                    lf->inode_before = oldsum.inode;
                } else {
                    inode[0] = '\0';
                }

                /* Provide information about the file */
                comment_buf = snprintf(comment, OS_MAXSTR, "Integrity checksum changed for: "
                        "'%.756s'\n"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s",
                        f_name,
                        size,
                        mtime,
                        inode,
                        perm,
                        owner,
                        gowner,
                        md5,
                        sha1,
                        sha256,
                        user_name,
                        audit_name,
                        effective_name,
                        group_name,
                        process_id,
                        process_name);

                if(!changes) {
                    lf->data = NULL;
                    sk_sum_clean(&newsum);
                    return 0;
                } else {
                    wm_strcat(&lf->fields[SK_CHFIELDS].value, ",", '\0');
                }

                if(lf->data) {
                    snprintf(comment+comment_buf, OS_MAXSTR-comment_buf, "What changed:\n%s", lf->data);
                    os_strdup(lf->data, lf->diff);
                }

                lf->event_type = FIM_MODIFIED;
                break;

            case 1:
                /* If file was re-added, do not compare changes */
                syscheck_decoder_id = sdb.idn;
                lf->event_type = FIM_READDED;
                sk_fill_event(lf, f_name, &newsum);
                snprintf(comment, OS_MAXSTR,
                     "File '%.756s' was re-added."
                     "%s"
                     "%s"
                     "%s"
                     "%s"
                     "%s"
                     "%s"
                     "%s",
                     f_name,
                     (user_name[0] != '\0' || process_name[0] != '\0') ? "\n" : "",
                     user_name,
                     audit_name,
                     effective_name,
                     group_name,
                     process_id,
                     process_name);
                break;
            }

            break;

        case 1:
            /* File deleted */
            syscheck_decoder_id = sdb.idd;
            sk_fill_event(lf, f_name, &newsum);
            lf->event_type = FIM_DELETED;

            snprintf(comment, OS_MAXSTR,
                 "File '%.756s' was deleted."
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s",
                 f_name,
                 (user_name[0] != '\0') ? "\n" : "",
                 user_name,
                 audit_name,
                 effective_name,
                 group_name,
                 process_id,
                 process_name);
            break;
        }

        /* Create a new log message */
        free(lf->full_log);
        os_strdup(comment, lf->full_log);
        lf->log = lf->full_log;
        lf->data = NULL;

        /* Set decoder */
        lf->decoder_info = sdb.syscheck_dec;
        sk_sum_clean(&newsum);
        w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
        return (1);

    } /* Continue */

    /* If we reach here, this file is not present in our database */
    fseek(fp, 0, SEEK_END);
    fprintf(fp, "00:%s !%ld %s\n", c_sum, (long int)lf->time.tv_sec, f_name);
    fflush(fp);

    /* Insert row in SQLite DB*/

    switch (sk_decode_sum(&newsum, c_sum, w_sum)) {
        case -1:
            merror("Couldn't decode syscheck sum from log.");
            break;

        case 0:
            lf->event_type = FIM_ADDED;

            /* Alert if configured to notify on new files */
            if ((Config.syscheck_alert_new == 1) && DB_IsCompleted(agent_id)) {
                syscheck_decoder_id = sdb.idn;
                InsertWhodata(&newsum,user_name,effective_name,audit_name,group_name,process_id,process_name);
                sk_fill_event(lf, f_name, &newsum);

                /* New file message */
                snprintf(comment, OS_MAXSTR,
                         "New file '%.756s' "
                         "added to the file system.\n%s%s%s%s%s%s",
                         f_name,
                         user_name,
                         audit_name,
                         effective_name,
                         group_name,
                         process_id,
                         process_name);

                /* Create a new log message */
                free(lf->full_log);
                os_strdup(comment, lf->full_log);
                lf->log = lf->full_log;

                /* Set decoder */
                lf->decoder_info = sdb.syscheck_dec;
                lf->decoder_syscheck_id = syscheck_decoder_id;
                lf->data = NULL;
                sk_sum_clean(&newsum);
                w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
                return (1);
            }

            break;

        case 1:
            mwarn("Missing file entry.");
            break;
    }

    lf->data = NULL;
    sk_sum_clean(&newsum);

    w_mutex_unlock(&sdb.syscheck_mutex[agent_id]);
    return (0);
}

/* Special decoder for syscheck
 * Not using the default decoding lib for simplicity
 * and to be less resource intensive
 */
int DecodeSyscheck(Eventinfo *lf)
{
    char *c_sum;
    char *w_sum;
    char *f_name;

    /* Every syscheck message must be in the following format:
     * checksum filename
     * or
     * checksum!whodatasum filename
     */
    f_name = wstr_chr(lf->log, ' ');
    if (f_name == NULL) {
        /* If we don't have a valid syscheck message, it may be
         * a database completed message
         */
        if (strcmp(lf->log, HC_SK_DB_COMPLETED) == 0) {
            DB_SetCompleted(lf);
            return (0);
        }

        merror(SK_INV_MSG);
        return (0);
    }

    /* Zero to get the check sum */
    *f_name = '\0';
    f_name++;

    //Change in Windows paths all slashes for backslashes for compatibility agent<3.4 with manager>=3.4
    normalize_path(f_name);

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

    /* Get w_sum */
    if (w_sum = strchr(c_sum, '!'), w_sum) {
        *(w_sum++) = '\0';
    }

    /* Search for file changes */
    return (DB_Search(f_name, c_sum, w_sum, lf));
}

/* Compare the first common fields between sum strings */
int SumCompare(const char *s1, const char *s2) {
    const char *ptr1 = strchr(s1, ':');
    const char *ptr2 = strchr(s2, ':');
    size_t size1;
    size_t size2;

    while (ptr1 && ptr2) {
        ptr1 = strchr(ptr1 + 1, ':');
        ptr2 = strchr(ptr2 + 1, ':');
    }

    size1 = ptr1 ? (size_t)(ptr1 - s1) : strlen(s1);
    size2 = ptr2 ? (size_t)(ptr2 - s2) : strlen(s2);

    return size1 == size2 ? strncmp(s1, s2, size1) : 1;
}

void InsertWhodata(const sk_sum_t * sum,char * user_name,char * effective_name, char * audit_name,char * group_name,char * process_id,char * process_name) {
    /* Whodata user */
    if(sum->wdata.user_id && sum->wdata.user_name && *sum->wdata.user_id != '\0') {
        snprintf(user_name, OS_FLSIZE, "(Audit) User: '%s (%s)'\n", sum->wdata.user_name, sum->wdata.user_id);
    } else {
        *user_name = '\0';
    }

    /* Whodata effective user */
    if(sum->wdata.effective_uid && sum->wdata.effective_name && *sum->wdata.effective_uid != '\0') {
        snprintf(effective_name, OS_FLSIZE, "(Audit) Effective user: '%s (%s)'\n", sum->wdata.effective_name, sum->wdata.effective_uid);
    } else {
        *effective_name = '\0';
    }

    /* Whodata Audit user */
    if(sum->wdata.audit_uid && sum->wdata.audit_name && *sum->wdata.audit_uid != '\0') {
        snprintf(audit_name, OS_FLSIZE, "(Audit) Login user: '%s (%s)'\n", sum->wdata.audit_name, sum->wdata.audit_uid);
    } else {
        *audit_name = '\0';
    }

    /* Whodata Group */
    if(sum->wdata.group_id && sum->wdata.group_name && *sum->wdata.group_id != '\0') {
        snprintf(group_name, OS_FLSIZE, "(Audit) Group: '%s (%s)'\n", sum->wdata.group_name, sum->wdata.group_id);
    } else {
        *group_name = '\0';
    }

    /* Whodata process */
    if(sum->wdata.process_id && *sum->wdata.process_id != '\0') {
        snprintf(process_id, OS_FLSIZE, "(Audit) Process id: '%s'\n", sum->wdata.process_id);
    } else {
        *process_id = '\0';
    }

    if(sum->wdata.process_name && *sum->wdata.process_name != '\0') {
        snprintf(process_name, OS_FLSIZE, "(Audit) Process name: '%s'\n", sum->wdata.process_name);
    } else {
        *process_name = '\0';
    }
}
