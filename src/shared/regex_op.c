/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#include "shared.h"


int OS_PRegex(const char *str, const char *regex)
{
    regex_t preg;

    if (!str || !regex) {
        return (0);
    }

    if (regcomp(&preg, regex, REG_EXTENDED | REG_NOSUB) != 0) {
        merror("Posix Regex compile error (%s).", regex);
        return (0);
    }

    if (regexec(&preg, str, 0, NULL, 0) != 0) {
        /* Didn't match */
        regfree(&preg);
        return (0);
    }

    regfree(&preg);
    return (1);
}


int w_regexec(const char * pattern, const char * string, size_t nmatch, regmatch_t * pmatch) {
    regex_t regex;
    int result;

    if (!(pattern && string)) {
        return 0;
    }

    if (regcomp(&regex, pattern, REG_EXTENDED)) {
        merror("Couldn't compile regular expression '%s'", pattern);
        return 0;
    }

    result = regexec(&regex, string, nmatch, pmatch, 0);
    regfree(&regex);
    return !result;
}

void w_sql_regex(sqlite3_context *context, int argc, sqlite3_value **argv) {
    char *pattern;
    char *to_match;
    regex_t regex;
    char *error_msg;

    if (argc != 2) {
        sqlite3_result_error(context, "regexp(): invalid arguments.\n", -1);
        return;
    }

    pattern = (char*)sqlite3_value_text(argv[0]);
    to_match = (char*)sqlite3_value_text(argv[1]);

    if (!pattern || !to_match) {
        if (pattern == to_match) {
            sqlite3_result_int(context, 1);
        } else {
            sqlite3_result_int(context, 0);
        }

        return;
    }

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB)) {
        os_calloc(OS_SIZE_1024, sizeof(char), error_msg);
        snprintf(error_msg, OS_SIZE_1024, "regexp(): could not compile '%s'.\n", pattern);
        sqlite3_result_error(context, error_msg, -1);
        free(error_msg);
        return;
    }

    sqlite3_result_int(context, !regexec(&regex, to_match , 0, NULL, 0));
    regfree(&regex);
}

#endif /* !WIN32 */
