/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

#undef ARGV0
#define ARGV0 "ossec-regex"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\n%s %s: ossec-regex <pattern>\n", __ossec_name, ARGV0);
    exit(1);
}

int main(int argc, char **argv)
{
    const char *pattern;
    char * string;
    int i;
    char msg[OS_MAXSTR + 1];

    memset(msg, '\0', OS_MAXSTR + 1);
    OSRegex regex;
    OSMatch matcher;

    OS_SetName(ARGV0);

    /* User arguments */
    if (argc != 2) {
        helpmsg();
        return (-1);
    }

    /* User options */
    if (strcmp(argv[1], "-h") == 0) {
        helpmsg();
        return (-1);
    }

    pattern = argv[1];

    if (!OSRegex_Compile(pattern, &regex, OS_RETURN_SUBSTRING)) {
        printf("Pattern '%s' does not compile with OSRegex_Compile\n", pattern);
        return (-1);
    }
    if (!OSMatch_Compile(pattern, &matcher, 0)) {
        printf("Pattern '%s' does not compile with OSMatch_Compile\n", pattern);
        return (-1);
    }

    while ((fgets(msg, OS_MAXSTR, stdin)) != NULL) {
        /* Remove newline */
        if (msg[strlen(msg) - 1] == '\n') {
            msg[strlen(msg) - 1] = '\0';
        }

        string = strdup(msg);
        if (OSRegex_Execute(string, &regex)) {
            printf("+OSRegex_Execute: %s\n", string);
            for (i = 0; regex.d_sub_strings[i]; i++) {
                printf(" -Substring: %s\n", regex.d_sub_strings[i]);
            }
        }

        if (OS_Regex(pattern, string)) {
            printf("+OS_Regex       : %s\n", string);
        }

        if (OSMatch_Execute(string, strlen(string), &matcher)) {
            printf("+OSMatch_Compile: %s\n", string);
        }

        if (OS_Match2(pattern, string)) {
            printf("+OS_Match2      : %s\n", string);
        }

        w_FreeArray(regex.d_sub_strings);
        free(string);
    }

    OSRegex_FreePattern(&regex);
    OSMatch_FreePattern(&matcher);

    return (0);
}
