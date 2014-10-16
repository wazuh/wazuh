/* @(#) $Id: ./src/util/ossec-regex.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* This tool will clear the project statistics */

#include "shared.h"

#undef ARGV0
#define ARGV0 "ossec-regex"

static void helpmsg(void) __attribute__((noreturn));

/** help **/
static void helpmsg()
{
    printf("\nOSSEC HIDS %s: ossec-regex pattern\n", ARGV0);
    exit(1);
}


/** main **/
int main(int argc, char **argv)
{
    const char *pattern;

    char msg[OS_MAXSTR +1];
    memset(msg, '\0', OS_MAXSTR +1);
    OSRegex regex;
    OSMatch matcher;

    OS_SetName(ARGV0);


    /* user arguments */
    if(argc != 2)
    {
        helpmsg();
        return(-1);
    }

    /* User options */
    if(strcmp(argv[1], "-h") == 0)
    {
        helpmsg();
        return(-1);
    }

    pattern = argv[1];

    if(!OSRegex_Compile(pattern, &regex, 0))
    {
        printf("pattern does not compile with OSRegex_Compile\n");
        return(-1);
    }
    if(!OSMatch_Compile(pattern, &matcher, 0))
    {
        printf("pattern does not compile with OSMatch_Compile\n");
        return(-1);
    }


    while((fgets(msg, OS_MAXSTR, stdin)) != NULL)
    {
        /* Removing new line. */
        if(msg[strlen(msg) -1] == '\n')
            msg[strlen(msg) -1] = '\0';

        /* Make sure we ignore blank lines. */
        if(strlen(msg) < 2) { continue; }

        if(OSRegex_Execute(msg, &regex))
            printf("+OSRegex_Execute: %s\n",msg);
        /*
        else
            printf("-OSRegex_Execute: \n");
            */

        if(OS_Regex(pattern, msg))
            printf("+OS_Regex       : %s\n", msg);
        /*
        else
            printf("-OS_Regex: \n");
            */

        if(OSMatch_Execute(msg, strlen(msg), &matcher))
            printf("+OSMatch_Compile: %s\n", msg);

        if(OS_Match2(pattern, msg))
            printf("+OS_Match2      : %s\n", msg);
    }
    return(0);
}


/* EOF */
