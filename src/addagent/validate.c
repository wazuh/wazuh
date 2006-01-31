/*   $OSSEC, validate.c, v0.2, 2006/01/27, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "manage_agents.h"



/* ID Search (is valid ID) */
int IDExist(char *id)
{
    FILE *fp;
    char line_read[FILE_SIZE +1];
    line_read[FILE_SIZE] = '\0';
   
    /* ID must not be null */ 
    if(!id)
        return(0);
    
    fp = fopen(AUTH_FILE, "r");
    if(!fp)
        return(0);
        
    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);
    
    while(fgets(line_read,FILE_SIZE -1, fp) != NULL)
    {
        char *name;

        if(line_read[0] == '#')
        {
            fgetpos(fp, &fp_pos);
            continue;
        }
        
        name = index(line_read, ' ');
        if(name)
        {
            *name = '\0';
            if(strcmp(line_read,id) == 0)
            {
                fclose(fp);
                return (1); /*(fp_pos);*/
            }
        }

        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return(0);
}



/* Is_Name (is valid name) */
int NameExist(char *u_name)
{
    FILE *fp;
    char line_read[FILE_SIZE +1];
    line_read[FILE_SIZE] = '\0';

    if(!u_name)
        return(0);

    fp = fopen(AUTH_FILE, "r");
    if(!fp)
        return(0);


    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);


    while(fgets(line_read, FILE_SIZE-1, fp) != NULL)
    {
        char *name;

        if(line_read[0] == '#')
            continue;

        name = index(line_read, ' ');
        if(name)
        {
            char *ip;
            name++;
            ip = index(name, ' ');
            if(ip)
            {
                *ip = '\0';
                if(strcmp(u_name,name) == 0)
                {
                    fclose(fp);
                    return(1);
                }
            }
        }
        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return(0);
}



/* print available agents */
int print_agents()
{
    int total = 0;
    FILE *fp;
    char line_read[FILE_SIZE +1];
    line_read[FILE_SIZE] = '\0';

    fp = fopen(AUTH_FILE, "r");
    if(!fp)
        return(0);

    fseek(fp, 0, SEEK_SET);
    
    memset(line_read,'\0',FILE_SIZE);
    
    while(fgets(line_read, FILE_SIZE -1, fp) != NULL)
    {
        char *name;

        if(line_read[0] == '#')
            continue;
            
        name = index(line_read, ' ');
        if(name)
        {
            char *ip;
            *name = '\0';
            name++;
            ip = index(name, ' ');
            if(ip)
            {
                char *key;
                *ip = '\0';
                ip++;
                key = index(ip, ' ');
                if(key)
                {
                    *key = '\0';
                    if(!total)
                        printf(PRINT_AVAILABLE);
                    printf(PRINT_AGENT, line_read, name, ip);
                    total++;
                }
                
            }
        }
    }

    fclose(fp);
    if(total)
        return(1);
    
    return(0);    
}


/* EOF */
