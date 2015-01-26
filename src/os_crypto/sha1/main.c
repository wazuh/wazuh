#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1_op.h"


void usage(char **argv)
{
    printf("%s file\n", argv[0]);
    exit(1);
}

int main(int argc, char **argv)
{
    os_sha1 filesum;

    if (argc < 2) {
        usage(argv);
    }

    if (OS_SHA1_File(argv[1], filesum) == 0) {
        printf("SHA1Sum for \"%s\" is: %s\n", argv[1], filesum);
    } else {
        printf("SHA1Sum for \"%s\" failed\n", argv[1]);
    }
    return (0);
}

