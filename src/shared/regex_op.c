/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

#endif /* !WIN32 */
