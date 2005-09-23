/* Copyright by Daniel B. Cid (2005)
 * Under the public domain. It is just an example.
 * Some examples of the usage for the os_regex library.
 */
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "os_regex.h"

int main(int argc,char **argv)
{
    char **ret;
    if(argc != 3)
    {
        printf("%s regex word\n",argv[0]);
        exit(1);
    }

    if((ret = OS_RegexStr(argv[1],argv[2])) == NULL)
    {
        printf("FALSE\n");
    }
    else
    {
        printf("Match:%s:\n",*ret);
        ret++;
        printf("Match:%s:\n",*ret);
    }
    return(0);
}
/* EOF */
