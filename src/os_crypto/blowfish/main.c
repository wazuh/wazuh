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

#include "bf_op.h"


int main(int argc, char **argv)
{
    int i;
    char output[1024];
    char output2[1024];

    memset(output, '\0', 1024);
    memset(output2, '\0', 1024);

    if (argc < 3) {
        printf("%s: string key\n", argv[0]);
        exit(1);
    }

    if ((strlen(argv[1]) > 1020) || (strlen(argv[2]) > 512)) {
        printf("%s: size err\n", argv[0]);
        exit(1);
    }

    /* Encrypt */
    OS_BF_Str(argv[1], output, argv[2], strlen(argv[1]), OS_ENCRYPT);

    /* Decrypt */
    OS_BF_Str(output, output2, argv[2], strlen(argv[1]), OS_DECRYPT);

    printf("finished.\n");
    printf("input: '%s'\n", argv[1]);
    printf("crpt: ");
    for (i = 0; i <= strlen(argv[1]); i++) {
        printf("%d", output[i]);
    }
    printf("\n");
    printf("output2: '%s'\n", output2);
    return (0);
}

