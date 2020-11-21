/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "getlog.h"

static char * replace_char(char * const str, char find, char replace){
    char *current_pos = strchr(str, find);
    while (current_pos){
        *current_pos = replace;
        current_pos = strchr(current_pos, find);
    }
    return str;
}

static char * remove_char(char * str, char find){
    char *c;
    char *d;
    char find_str[] = {find, '\0'};

    if(str != NULL) {
        str = &str[strspn(str, find_str)];
        for (c = str + strcspn(str, find_str); *(d = c + strspn(c, find_str)); c = d + strcspn(d, find_str));
        *c = '\0';
    }
    return str;
}

char * getlog_singleline(getlog_params_t * params) { 
    return fgets(params->buffer, params->length, params->stream);
}

char * getlog_multiline(getlog_params_t * params) {
    w_multiline_config_t * ml_cfg = (w_multiline_config_t *) params->ctxt;
    const char newline = '\n';
    const char tab = '\t';
    const char wspace = ' ';
    char * str = params->buffer;
    int offset, chunk_sz;
    long pos = ftell(params->stream);
    bool already_match = false;

    for(*str = '\0', offset = 0, chunk_sz = 0, already_match = false;
        fgets(str, params->length - offset, params->stream);
        str+= chunk_sz){
            
        pos = w_ftell(params->stream);
        chunk_sz = strlen(str);
        offset += chunk_sz;

        if(already_match ^ w_expression_match(ml_cfg->regex, str, NULL, NULL)){
            already_match = true;
        } else {
            //Discard the last readed line. It purpose was to detect the end of multiline log
            params->buffer[offset - chunk_sz]='\0';
            fseek(params->stream,pos,SEEK_SET);
            break;
        }
    }

    switch (ml_cfg->replace_type) {
        case ML_REPLACE_WSPACE:
            replace_char(params->buffer,newline,wspace);
            break;

        case ML_REPLACE_TAB:
            replace_char(params->buffer,newline,tab);
            break;

        case ML_REPLACE_NONE:
            remove_char(params->buffer,newline);
            break;

        default:
        case ML_REPLACE_NO_REPLACE:
            break;
    }

    return params->buffer;
}
