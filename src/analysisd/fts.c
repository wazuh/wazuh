/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* First time seen functions */

#include "fts.h"
#include "eventinfo.h"
#include "config.h"

/* Local variables */
unsigned int fts_minsize_for_str = 0;
int fts_list_size;

static OSList *fts_list = NULL;
static OSHash *fts_store = NULL;

static FILE *fp_list = NULL;
static FILE **fp_ignore = NULL;

/* Multiple readers / one write mutex */
static pthread_rwlock_t file_update_rwlock;
static pthread_mutex_t fts_write_lock;

/* Start the FTS module */
int FTS_Init(int threads)
{
    char _line[OS_FLSIZE + 1];
    int i;

    _line[OS_FLSIZE] = '\0';

    fts_list = OSList_Create();
    if (!fts_list) {
        merror(LIST_ERROR);
        return (0);
    }

    pthread_rwlock_init(&file_update_rwlock, NULL);
    fts_write_lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;

    fp_ignore = (FILE **)calloc(threads, sizeof(FILE*));
    if (!fp_ignore) {
        merror(MEM_ERROR, errno, strerror(errno));
        return (0);
    }

    /* Create store data */
    fts_store = OSHash_Create();
    if (!fts_store) {
        merror(LIST_ERROR);
        return (0);
    }
    if (!OSHash_setSize(fts_store, 2048)) {
        merror(LIST_ERROR);
        return (0);
    }

    /* Get default list size */
    fts_list_size = getDefine_Int("analysisd",
                                  "fts_list_size",
                                  12, 512);

    /* Get minimum string size */
    fts_minsize_for_str = (unsigned int) getDefine_Int("analysisd",
                          "fts_min_size_for_str",
                          6, 128);

    if (!OSList_SetMaxSize(fts_list, fts_list_size)) {
        merror(LIST_SIZE_ERROR);
        return (0);
    }

    /* Create fts list */
    fp_list = fopen(FTS_QUEUE, "r+");
    if (!fp_list) {
        /* Create the file if we cant open it */
        fp_list = fopen(FTS_QUEUE, "w+");
        if (fp_list) {
            fclose(fp_list);
        }

        if (chmod(FTS_QUEUE, 0640) == -1) {
            merror(CHMOD_ERROR, FTS_QUEUE, errno, strerror(errno));
            return 0;
        }

        uid_t uid = Privsep_GetUser(USER);
        gid_t gid = Privsep_GetGroup(GROUPGLOBAL);
        if (uid != (uid_t) - 1 && gid != (gid_t) - 1) {
            if (chown(FTS_QUEUE, uid, gid) == -1) {
                merror(CHOWN_ERROR, FTS_QUEUE, errno, strerror(errno));
                return (0);
            }
        }

        fp_list = fopen(FTS_QUEUE, "r+");
        if (!fp_list) {
            merror(FOPEN_ERROR, FTS_QUEUE, errno, strerror(errno));
            return (0);
        }
    }

    /* Add content from the files to memory */
    fseek(fp_list, 0, SEEK_SET);
    while (fgets(_line, OS_FLSIZE , fp_list) != NULL) {
        char *tmp_s;

        /* Remove newlines */
        tmp_s = strchr(_line, '\n');
        if (tmp_s) {
            *tmp_s = '\0';
        }

        os_strdup(_line, tmp_s);
        if (OSHash_Add(fts_store, tmp_s, tmp_s) != 2) {
            free(tmp_s);
            merror(LIST_ADD_ERROR);
        }
        
        /* Reset pointer addresses before using strdup() again */
        /* The hash will keep the needed memory references */
        tmp_s = NULL;
    }

    /* Create ignore list */
    *fp_ignore = fopen(IG_QUEUE, "r+");
    if (!*fp_ignore) {
        /* Create the file if we cannot open it */
        *fp_ignore = fopen(IG_QUEUE, "w+");
        if (*fp_ignore) {
            fclose(*fp_ignore);
        }

        if (chmod(IG_QUEUE, 0640) == -1) {
            merror(CHMOD_ERROR, IG_QUEUE, errno, strerror(errno));
            return (0);
        }

        uid_t uid = Privsep_GetUser(USER);
        gid_t gid = Privsep_GetGroup(GROUPGLOBAL);
        if (uid != (uid_t) - 1 && gid != (gid_t) - 1) {
            if (chown(IG_QUEUE, uid, gid) == -1) {
                merror(CHOWN_ERROR, IG_QUEUE, errno, strerror(errno));
                return (0);
            }
        }

        *fp_ignore = fopen(IG_QUEUE, "r+");
        if (!*fp_ignore) {
            merror(FOPEN_ERROR, IG_QUEUE, errno, strerror(errno));
            return (0);
        }
    }

    for (i = 1; i < threads; i++) {
        fp_ignore[i] = fopen(IG_QUEUE, "r+");
    }

    mdebug1("FTSInit completed.");

    return (1);
}

/* Add a pattern to be ignored */
void AddtoIGnore(Eventinfo *lf, int pos)
{
    w_rwlock_wrlock(&file_update_rwlock);
    fseek(fp_ignore[pos], 0, SEEK_END);

#ifdef TESTRULE
    return;
#endif

    /* Assign the values to the FTS */
    fprintf(fp_ignore[pos], "\n%s %s %s %s %s %s %s %s",
            (lf->decoder_info->name && (lf->generated_rule->ignore & FTS_NAME)) ?
            lf->decoder_info->name : "",
            (lf->id && (lf->generated_rule->ignore & FTS_ID)) ? lf->id : "",
            (lf->dstuser && (lf->generated_rule->ignore & FTS_DSTUSER)) ?
            lf->dstuser : "",
            (lf->srcip && (lf->generated_rule->ignore & FTS_SRCIP)) ?
            lf->srcip : "",
            (lf->dstip && (lf->generated_rule->ignore & FTS_DSTIP)) ?
            lf->dstip : "",
            (lf->data && (lf->generated_rule->ignore & FTS_DATA)) ?
            lf->data : "",
            (lf->systemname && (lf->generated_rule->ignore & FTS_SYSTEMNAME)) ?
            lf->systemname : "",
            (lf->generated_rule->ignore & FTS_LOCATION) ? lf->location : "");

    if (lf->generated_rule->ignore & FTS_DYNAMIC) {
        int i;

        for (i = 0; i < Config.decoder_order_size && lf->generated_rule->ignore_fields[i]; i++) {
            const char *field = FindField(lf, lf->generated_rule->ignore_fields[i]);

            if (field)
                fprintf(fp_ignore[pos], " %s", field);
        }
    }

    fprintf(fp_ignore[pos], "\n");
    fflush(fp_ignore[pos]);
    w_rwlock_unlock(&file_update_rwlock);

    return;
}

/* Check if the event is to be ignored.
 * Only after an event is matched (generated_rule must be set).
 */
int IGnore(Eventinfo *lf, int pos)
{
    FILE *fp_ig = fp_ignore[pos];

    char _line[OS_FLSIZE + 1];
    char _fline[OS_FLSIZE + 1];

    _line[OS_FLSIZE] = '\0';

    /* Assign the values to the FTS */
    snprintf(_line, OS_FLSIZE, "%s %s %s %s %s %s %s %s",
             (lf->decoder_info->name && (lf->generated_rule->ckignore & FTS_NAME)) ?
             lf->decoder_info->name : "",
             (lf->id && (lf->generated_rule->ckignore & FTS_ID)) ? lf->id : "",
             (lf->dstuser && (lf->generated_rule->ckignore & FTS_DSTUSER)) ?
             lf->dstuser : "",
             (lf->srcip && (lf->generated_rule->ckignore & FTS_SRCIP)) ?
             lf->srcip : "",
             (lf->dstip && (lf->generated_rule->ckignore & FTS_DSTIP)) ?
             lf->dstip : "",
             (lf->data && (lf->generated_rule->ignore & FTS_DATA)) ?
             lf->data : "",
             (lf->systemname && (lf->generated_rule->ignore & FTS_SYSTEMNAME)) ?
             lf->systemname : "",
             (lf->generated_rule->ckignore & FTS_LOCATION) ? lf->location : "");

    if (lf->generated_rule->ckignore & FTS_DYNAMIC) {
        int i;

        for (i = 0; i < Config.decoder_order_size && lf->generated_rule->ckignore_fields[i]; i++) {
            const char *field = FindField(lf, lf->generated_rule->ckignore_fields[i]);

            if (field) {
                strncat(_line, " ", OS_FLSIZE - strlen(_line));
                strncat(_line, field, OS_FLSIZE - strlen(_line));
            }
        }
    }

    w_rwlock_rdlock(&file_update_rwlock);
    _fline[OS_FLSIZE] = '\0';

    /** Check if the ignore is present **/
    /* Point to the beginning of the file */
    fseek(fp_ig, 0, SEEK_SET);
    while (fgets(_fline, OS_FLSIZE , fp_ig) != NULL) {
        if (strcmp(_fline, _line) != 0) {
            continue;
        }
        w_rwlock_unlock(&file_update_rwlock);
        /* If we match, we can return 1 */
        return (1);
    }
    w_rwlock_unlock(&file_update_rwlock);
    return (0);
}

/*  Check if the word "msg" is present on the "queue".
 *  If it is not, write it there.
 */
char * FTS(Eventinfo *lf)
{
    int i;
    int number_of_matches = 0;
    char *_line = NULL;
    char *line_for_list = NULL;
    OSListNode *fts_node = NULL;
    const char *field;

    os_calloc(OS_FLSIZE + 1,sizeof(char),_line);

    _line[OS_FLSIZE] = '\0';

    /* Assign the values to the FTS */
    snprintf(_line, OS_FLSIZE, "%s %s %s %s %s %s %s %s %s",
             lf->decoder_info->name,
             (lf->id && (lf->decoder_info->fts & FTS_ID)) ? lf->id : "",
             (lf->dstuser && (lf->decoder_info->fts & FTS_DSTUSER)) ? lf->dstuser : "",
             (lf->srcuser && (lf->decoder_info->fts & FTS_SRCUSER)) ? lf->srcuser : "",
             (lf->srcip && (lf->decoder_info->fts & FTS_SRCIP)) ? lf->srcip : "",
             (lf->dstip && (lf->decoder_info->fts & FTS_DSTIP)) ? lf->dstip : "",
             (lf->data && (lf->decoder_info->fts & FTS_DATA)) ? lf->data : "",
             (lf->systemname && (lf->decoder_info->fts & FTS_SYSTEMNAME)) ? lf->systemname : "",
             (lf->decoder_info->fts & FTS_LOCATION) ? lf->location : "");

    for (i = 0; i < Config.decoder_order_size; i++) {
        if (lf->decoder_info->fts_fields[i] && (field = FindField(lf, lf->decoder_info->fields[i]))) {
            strncat(_line, " ", OS_FLSIZE - strlen(_line));
            strncat(_line, field, OS_FLSIZE - strlen(_line));
        }
    }

    /** Check if FTS is already present **/
    if (OSHash_Get_ex(fts_store, _line)) {
        free(_line);
        return NULL;
    }

    /* Check if from the last FTS events, we had at least 3 "similars" before.
     * If yes, we just ignore it.
     */
    if (lf->decoder_info->type == IDS) {
        fts_node = OSList_GetLastNode(fts_list);
        while (fts_node) {
            if (OS_StrHowClosedMatch((char *)fts_node->data, _line) >
                    fts_minsize_for_str) {
                number_of_matches++;

                /* We go and add this new entry to the list */
                if (number_of_matches > 2) {
                    _line[fts_minsize_for_str] = '\0';
                    break;
                }
            }

            fts_node = OSList_GetPrevNode(fts_list);
        }

        fts_node = NULL;
        
        os_strdup(_line, line_for_list);
        if (!line_for_list) {
            merror(MEM_ERROR, errno, strerror(errno));
            free(_line);
            return NULL;
        }
        
        fts_node = OSList_AddData(fts_list, line_for_list);
        if (!fts_node) {
            free(line_for_list);
            free(_line);
            return NULL;
        }
    }

    /* Store new entry */
    if (line_for_list == NULL) {
        os_strdup(_line, line_for_list);
        if (!line_for_list) {
            merror(MEM_ERROR, errno, strerror(errno));
            free(_line);
            return NULL;
        }
    }

    if (OSHash_Add_ex(fts_store, line_for_list, line_for_list) != 2) {
        if (fts_node) OSList_DeleteThisNode(fts_list, fts_node);
        free(line_for_list);
        free(_line);
        return NULL;
    }

    return _line;
}

FILE **w_get_fp_ignore(){
    return fp_ignore;
}

void FTS_Fprintf(char * _line){
    /* Save to fts fp */
    w_mutex_lock(&fts_write_lock);
    fseek(fp_list, 0, SEEK_END);
    fprintf(fp_list, "%s\n", _line);
    w_mutex_unlock(&fts_write_lock);
}

void FTS_Flush(){
    w_mutex_lock(&fts_write_lock);
    fflush(fp_list);
    w_mutex_unlock(&fts_write_lock);
}
