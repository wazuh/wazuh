/*   $OSSEC, common.c, v0.1, 2005/10/01, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include <stdio.h>       
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>


/* is_file: Check if the file is present
 * by different attempts (to try to avoid syscall hidding).
 */
int is_file(char *file_name)
{
    struct stat statbuf;
    FILE *fp = NULL;
    
    if((lstat(file_name, &statbuf) < 0) &&
        ((fp = fopen(file_name, "r")) == NULL))
    {
        return(0);
    }

    /* must close it over here */
    if(fp)
        fclose(fp);
    
    printf("file: %s\n",file_name);    

    return(1);
}



/* EOF */
