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

    while(1)
    {
        fgets(buf, 1024, stdin);
        tmp = strchr(buf, '\n');
        if(tmp)
            *tmp = '\0';

        printf("Adding key: '%s'\n", buf);
        i = OSHash_Add(mhash, strdup(buf), NULL);
        printf("rc = %d\n", i);
    }
    return(0);
}


/* EOF */
