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
#include "logcollector.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/* Timeout functions */
STATIC bool multiline_restore_timeout(char * buffer, int * readed_lines, w_multiline_timeout_ctxt_t * to_ctxt);
STATIC void multiline_backup_timeout(char * buffer, int readed_lines, w_multiline_timeout_ctxt_t * to_ctxt);
STATIC void multiline_free_timeout(w_multiline_timeout_ctxt_t * to_ctxt);

/**
 * @brief Get log from file with multiline log support.
 * 
 * @param buffer readed log output
 * @param length max lenth
 * @param stream log file
 * @param ml_cfg multiline configuration
 * @return  if < 0 indicates incomplete reading. 
 *          if = 0 indicates no more logs available.
 *          if > 0 indicate log's lines count.
 */
STATIC int multiline_getlog(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);

/**
 * @brief Get log from file with multiline log support using \ref ML_MATCH_START
 * 
 * @param buffer readed log output
 * @param length max lenth
 * @param stream log file
 * @param ml_cfg multiline configuration
 * @return  if < 0 indicates incomplete reading. 
 *          if = 0 indicates no more logs available.
 *          if > 0 indicate log's lines count.
 */
STATIC int multiline_getlog_start(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);

/**
 * @brief Get log from file with multiline log support using \ref ML_MATCH_END
 * 
 * @param buffer readed log output
 * @param length max lenth
 * @param stream log file
 * @param ml_cfg multiline configuration
 * @return  if < 0 indicates incomplete reading. 
 *          if = 0 indicates no more logs available.
 *          if > 0 indicate log's lines count.
 */
STATIC int multiline_getlog_end(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);

/**
 * @brief Get log from file with multiline log support using \ref ML_MATCH_ALL
 * 
 * @param buffer readed log output
 * @param length max lenth
 * @param stream log file
 * @param ml_cfg multiline configuration
 * @return  if < 0 indicates incomplete reading. 
 *          if = 0 indicates no more logs available.
 *          if > 0 indicate log's lines count.
 */
STATIC int multiline_getlog_all(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);

/* Misc functions */

/**
 * @brief If the last character of the string is an end of line, replace it.
 * 
 * Replace the last character of `str` (only if it is an end of line) according to` type`.
 * if type is ML_REPLACE_NO_REPLACE does not replace the end of the line
 * if type is ML_REPLACE_NONE remove the end of the line
 * if type is ML_REPLACE_WSPACE replace the end of line with a blank space ' '
 * if type is ML_REPLACE_TAB replace the end of line with a tab character '\t'
 * @param str String to replace character.
 * @param type Replacement type
 */
STATIC void multiline_replace(char * str, w_multiline_replace_type_t type);

void *read_multiline_regex(logreader *lf, int *rc, int drop_it) {
    char read_buffer[OS_MAXSTR + 1];
    int count_logs, count_lines, ret;
    fpos_t fp_pos;
    const int max_line_len =  OS_MAXSTR - OS_HEADER_SIZE - 1;

    read_buffer[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get initial file location */
    fgetpos(lf->fp, &fp_pos);
    
    for (count_lines = 0, count_logs = 0;
        ret = multiline_getlog(read_buffer, max_line_len, lf->fp, lf->multiline),
            ret && count_lines < maximum_lines;
        count_lines += ret, count_logs++) {

        if (drop_it == 0) {
            w_msg_hash_queues_push(read_buffer, lf->file, strlen(read_buffer), lf->log_target, LOCALFILE_MQ);
        }
    }

    return NULL;
}

STATIC int multiline_getlog(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg) {

    int readed_lines = 0;

    switch (ml_cfg->match_type) {
        case ML_MATCH_START:
            readed_lines = multiline_getlog_start(buffer,length,stream,ml_cfg);
            break;

        case ML_MATCH_END:
            readed_lines = multiline_getlog_end(buffer,length,stream,ml_cfg);
            break;

        case ML_MATCH_ALL:
            readed_lines = multiline_getlog_all(buffer,length,stream,ml_cfg);
            break;

        default:
            *buffer = '\0';
            break;
    }

    return readed_lines;
}

STATIC int multiline_getlog_start(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg) {

    char * str = buffer;
    char * retstr = NULL;
    int offset = 0, chunk_sz = 0;
    long pos = w_ftell(stream);
    bool already_match = false;
    int readed_lines = 0;

    if (multiline_restore_timeout(str, &readed_lines, ml_cfg->timeout_ctxt)) {
        offset = strlen(str);
        already_match = true;
    } else {
        readed_lines = 0;
        *str = '\0';
        offset = 0;
        already_match = false;
    }

    for (chunk_sz = 0;
        retstr = fgets(str, length - offset, stream), retstr;
        str += chunk_sz, readed_lines++, pos = w_ftell(stream)) {
        if (already_match ^ w_expression_match(ml_cfg->regex, str, NULL, NULL)) {
            // start pattern finded or already found
            already_match = true;
            multiline_replace(str,ml_cfg->replace_type);
            chunk_sz = strlen(str);
            offset += chunk_sz;
        } else{
            if(already_match){
                // Discard the last readed line. It purpose was to detect the end of multiline log
                buffer[offset] = '\0';
                fseek(stream, pos, SEEK_SET);
                break;
            }
            else{
                // Single line log
                readed_lines++;
                break;
            }

        }
    }

    if (already_match && !retstr) {
        // Multiline log start found but not finished yet
        multiline_backup_timeout(buffer, readed_lines, ml_cfg->timeout_ctxt);
        readed_lines = 0;
    }

    return readed_lines;
}

STATIC int multiline_getlog_end(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg) {
    char * str = buffer;
    int offset, chunk_sz;
    int readed_lines = 0;

    if (multiline_restore_timeout(str, &readed_lines, ml_cfg->timeout_ctxt)) {
        offset = strlen(str);
    } else {
        readed_lines = 0;
        *str = '\0';
        offset = 0;
    }

    for (chunk_sz = 0;
        fgets(str, length - offset, stream);
        str += chunk_sz) {
        readed_lines++;
        chunk_sz = strlen(str);
        offset += chunk_sz;
        multiline_replace(str,ml_cfg->replace_type);
        if (w_expression_match(ml_cfg->regex, str, NULL, NULL)) {
            break;
        }
    }
    /** TODO: check if timeout backup is necessary in this case **/

    return readed_lines;
}

STATIC int multiline_getlog_all(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg) {

    char * str = buffer;
    int offset, chunk_sz;
    int readed_lines = 0;

    if (multiline_restore_timeout(str, &readed_lines, ml_cfg->timeout_ctxt)) {
        offset = strlen(str);
    } else {
        readed_lines = 0;
        *str = '\0';
        offset = 0;
    }

    for (chunk_sz = 0; 
        fgets(str, length - offset, stream);
        str += chunk_sz) {
        readed_lines++;
        chunk_sz = strlen(str);
        offset += chunk_sz;
        multiline_replace(str,ml_cfg->replace_type);
        if (w_expression_match(ml_cfg->regex, buffer, NULL, NULL)) {
            break;
        }
    }

    /** TODO: check if timeout backup is necessary in this case **/
    return readed_lines;
}

STATIC void multiline_replace(char * str, w_multiline_replace_type_t type) {

    const char newline = '\n';
    const char creturn = '\r';
    const char tab = '\t';
    const char wspace = ' ';
    char * pos_newline;
    char * pos_creturn;

    if (!str || str[0] == '\0') {
        return;
    }

    if(pos_newline = (str + strlen(str) - 1),  *pos_newline != newline) {
        return;
    }

    pos_creturn = (*(pos_newline - 1) == creturn) ? (pos_newline - 1) : NULL;

    switch (type) {
    case ML_REPLACE_WSPACE:
        if (pos_creturn) {
            *pos_creturn = wspace;
            *pos_newline = '\0';
        } else {
            *pos_newline = wspace;
        }

        break;

    case ML_REPLACE_TAB:
        if (pos_creturn) {
            *pos_creturn = tab;
            *pos_newline = '\0';
        } else {
            *pos_newline = tab;
        }

        break;

    case ML_REPLACE_NONE:
        if (pos_creturn) {
            *pos_creturn = '\0';
        } else {
            *pos_newline = '\0';
        }
        break;

    default:
    case ML_REPLACE_NO_REPLACE:
        break;
    }
}

STATIC void multiline_backup_timeout(char * buffer, int readed_lines, w_multiline_timeout_ctxt_t * to_ctxt){
    if(to_ctxt){ /** TODO: check if barely freeing last to_ctxt is the right thing*/
        multiline_free_timeout(to_ctxt);
    }
    os_calloc(1, sizeof(w_multiline_timeout_ctxt_t), to_ctxt);
    os_malloc(strlen(buffer)+ 1, to_ctxt->buffer);
    strcpy(to_ctxt->buffer, buffer);
    to_ctxt->lines_count = readed_lines;
    /** TODO: implement time set here*/
}

STATIC void multiline_free_timeout(w_multiline_timeout_ctxt_t * to_ctxt){
    if(!to_ctxt){
        return;
    }
    if(to_ctxt->buffer)
        os_free(to_ctxt->buffer);

    os_free(to_ctxt);
    to_ctxt = NULL;
}

STATIC bool multiline_restore_timeout(char * buffer, int * readed_lines, w_multiline_timeout_ctxt_t * to_ctxt){

    if(!to_ctxt)
        return false;
    if(true){ /** TODO: check timeexpiration. True if it's expired */
        multiline_free_timeout(to_ctxt);
        return false;
    }

    strcpy(buffer, to_ctxt->buffer);
    *readed_lines = to_ctxt->lines_count;
}
