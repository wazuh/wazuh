/*
 * Wazuh module parser
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

static int msg_to_print_according_to_debugLevel (char *output, char * tokenized_line, char *str_level, char* service_title);


static int msg_to_print_according_to_debugLevel (char *buff_output, char * tokenized_line, char *str_level, char* service_title) {
    char *p_line = NULL;
    int retVal = 0;

    if (buff_output != NULL && tokenized_line != NULL){
        if ((p_line = strstr(tokenized_line, str_level))) {
            p_line += strlen(str_level);

            if (service_title != NULL) {
                snprintf(buff_output, strlen(service_title) + strlen(p_line) + 2, "%s %s", service_title, p_line);
            } else {
                snprintf(buff_output, strlen(p_line) + 2, "%s", p_line);
            }
            retVal = 1;
        }
    }
    return retVal;
}

void wm_parse_output(char *output, char *logger_name, char *tag, char* service_title) {
    char *line;
    char * parsing_output = output;
    int debug_level = isDebug();

    if (output != NULL && logger_name != NULL) {
        for (line = strstr(parsing_output, logger_name); line; line = strstr(parsing_output, logger_name)) {
            char * tokenized_line;
            os_calloc(_W_STRING_MAX, sizeof(char), tokenized_line);
            char * next_lines;

            line += strlen(logger_name);
            next_lines = strstr(line, logger_name);

            int next_lines_chars = next_lines == NULL ? 0 : strlen(next_lines);

            // 1 is added because it's mandatory to consider the null byte
            int cp_length = 1 + strlen(line) - next_lines_chars > _W_STRING_MAX ? _W_STRING_MAX : 1 + strlen(line) - next_lines_chars;
            snprintf(tokenized_line, cp_length, "%s", line);
            if (tokenized_line[cp_length - 2] == '\n') tokenized_line[cp_length - 2] = '\0';

            char * buff;
            os_calloc(_W_STRING_MAX, sizeof(char), buff);


            if (debug_level >= 1) {
                if(msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_DEBUG, service_title)) {
                    mtdebug1(tag, "%s", buff);
                }
            }
            if (debug_level >= 0) {
                if (msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_INFO, service_title)) {
                    mtinfo(tag, "%s", buff);
                }
                if (msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_CRITICAL, service_title)) {
                    mterror(tag, "%s", buff);
                }
                if (msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_ERROR, service_title)) {
                    mterror(tag, "%s", buff);
                }
                if (msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_WARNING, service_title)) {
                    mtwarn(tag, "%s", buff);
                }
            }

            parsing_output += cp_length + strlen(logger_name) - 1;

            os_free(tokenized_line);
            os_free(buff);
        }
    }
}