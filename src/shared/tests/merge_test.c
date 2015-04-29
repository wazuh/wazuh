#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "file_op.h"


int main(int argc, char **argv)
{
    if (!argv[1]) {
        printf("%s [mu] <merged file> <file to merge1> <file to merge2> ..\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[1], "m") == 0) {
        MergeFiles(argv[2], argv + 3);
    } else if (strcmp(argv[1], "u") == 0) {
        UnmergeFiles(argv[2]);
    } else {
        printf("ERROR\n");
    }

    return (0);
}

