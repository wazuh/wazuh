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
#include <unistd.h>

#include "math_op.h"


int main(int argc, char **argv)
{
    if (!argv[1]) {
        printf("%s <int>\n", argv[0]);
        exit(1);
    }

    printf("Value: %d\n", os_getprime(atoi(argv[1])));

    return (0);
}

