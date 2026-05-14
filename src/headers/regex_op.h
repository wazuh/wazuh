/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_REGEX_OP_H
#define OS_REGEX_OP_H

#ifndef WIN32
#include <regex.h>
#include "../external/sqlite/sqlite3.h"

/**
 * @brief Compare a string with a regular expression.
 *
 * @param str String to check.
 * @param regex Regex to match.
 * @return Returns 1 if matches, 0 if not.
 */
int OS_PRegex(const char *str, const char *regex);


/**
 * @brief Compare a string with a expression.
 *
 * @details This function extends the POSIX function regexec().
 *          In this function the pattern is self compiled.
 *
 * @param pattern Regex to match.
 * @param string String to check.
 * @param nmatch The maximum number of matches to record in pmatch.
 * @param pmatch Array of regmatch_t objects where the function can record the matches.
 * @return Returns 1 on success or 0 on error.
 */
int w_regexec(const char * pattern, const char * string, size_t nmatch, regmatch_t * pmatch);

// Callback to use POSIX regex with the SQLite engine
void w_sql_regex(sqlite3_context *context, int argc, sqlite3_value **argv);

#endif
#endif
