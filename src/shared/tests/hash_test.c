#include <stdio.h>
#include <string.h>

#include "hash_op.h"


int main(int argc, char **argv)
{
    int i = 0;
    char *tmp;
    char buf[1024];
    OSHash *mhash;

    mhash = OSHash_Create();

    while (1) {
        fgets(buf, 1024, stdin);
        tmp = strchr(buf, '\n');
        if (tmp) {
            *tmp = '\0';
        }

        if (strncmp(buf, "get ", 4) == 0) {
            printf("Getting key: '%s'\n", buf + 4);
            printf("Found: '%s'\n", (char *)OSHash_Get(mhash, buf + 4));
        } else {
            printf("Adding key: '%s'\n", buf);
            i = OSHash_Add(mhash, strdup(buf), strdup(buf));

            printf("rc = %d\n", i);
        }
    }

    return (0);
}

