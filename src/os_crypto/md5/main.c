/* Copyright (C) 2015-2019, Wazuh Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5_op.h"
#include "headers/defs.h"


void usage(char **argv)
{
    printf("%s file str\n%s str string\n", argv[0], argv[0]);
    exit(1);
}

int main(int argc, char **argv)
{
    os_md5 filesum;

    if (argc < 3) {
        usage(argv);
    }

    if (strcmp(argv[1], "file") == 0) {
        OS_MD5_File(argv[2], filesum, OS_BINARY);
    }

    else if (strcmp(argv[1], "str") == 0) {
        OS_MD5_Str(argv[2], -1, filesum);
    }

    else {
        usage(argv);
    }

    printf("MD5Sum for \"%s\" is: %s\n", argv[2], filesum);
    return (0);
}
