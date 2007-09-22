#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../md5/md5_op.h"
#include "../sha1/sha1_op.h"
#include "md5_sha1_op.h"

void usage(char **argv)
{
    printf("%s file str\n%s str string\n",argv[0],argv[0]);
    exit(1);
}

/* make main to compile (after the make md5)
 * Example of the md5 API use
 * Daniel B. Cid, dcid@ossec.net
 */
int main(int argc, char ** argv)
{
    os_md5 filesum1;
    os_sha1 filesum2;

    if(argc < 3)
        usage(argv);
   
    
    if(strcmp(argv[1],"file") == 0)
    {
        OS_MD5_SHA1_File(argv[2], filesum1, filesum2);
    }
    
    else
        usage(argv);
    
    printf("MD5Sha1Sum for \"%s\" is: %s - %s\n",argv[2], filesum1, filesum2);
    return(0);
}

/* EOF */
