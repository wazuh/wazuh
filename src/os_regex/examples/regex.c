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

    if(argc != 3)
    {
        printf("%s regex word\n",argv[0]);
        exit(1);
    }

    printf("for REGEX: ");	
    if(OS_Regex(argv[1],argv[2]))
        printf("TRUE\n");
    else
        printf("FALSE\n");

    return(0);
}
/* EOF */
