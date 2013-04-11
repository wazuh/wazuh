/* @(#) $Id: ./src/win32/service-stop.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* Setup windows after install */
int main(int argc, char **argv)
{
    printf("%s: Attempting to stop ossec.", argv[0]);

    system("net stop OssecSvc");

    system("pause");
    return(0);
}
