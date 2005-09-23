/*   $OSSEC, addagent.c, v0.1, 2005/08/27, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Manage agents tool
 * Add/extract and remove agents from a server.
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "headers/debug_op.h"
#include "headers/defs.h"
#include "headers/privsep_op.h"

#include "os_regex/os_regex.h"

#include "os_crypto/md5/md5_op.h"

#include "error_messages/error_messages.h"

#define KEYS_FILE_NEW "client.keys"

#undef ARGV0
#define ARGV0 "manage_agents"

int dbg_flag=0;
int chroot_flag=0;

/* b64 function prototypes */
char *decode_base64(const char *src);
char *encode_base64(int size, char *src);


/* Global internal variables */
int time1 = 0;
int time2 = 0;
int time3 = 0;
int rand1 = 0;
int rand2 = 0;
char str1[66];
char str2[66];
os_md5 md1;
os_md5 md2;
FILE *fp;
fpos_t fp_pos;


char *dir=DEFAULTDIR;


/* chomp: remove \n, \r and ' ' of a string */
void chomp(char *str)
{
    char *tmp_str;
    int i = 0;

    while(1)
    {
        i = 0;
        tmp_str = index(str, '\n');
        if(tmp_str)
        {
            *tmp_str = '\0';
            i++;
        }

        tmp_str = index(str, '\r');
        if(tmp_str)
        {
            *tmp_str = '\0';
            i++;
        }

        if(i == 0)
            break;
        
        i = 0;    
    }

    return;
}


/* ID Search */
int Is_ID(char *id)
{
    char line_read[256];
    
    if(!fp || !id)
        return(-1);
        
    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);
    
    while(fgets(line_read,255, fp) != NULL)
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
                return (1); /*(fp_pos);*/
        }

        fgetpos(fp, &fp_pos);
    }
    return(-1);
}

int Is_Name(char *u_name)
{
    char line_read[256];
    
    if((!fp)||(!u_name))
        return(-1);
        
    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);
    
    while(fgets(line_read,255, fp) != NULL)
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
                    return(1);
            }
        }
        fgetpos(fp, &fp_pos);
    }
    return(-1);
}

int print_available()
{
    char line_read[256];
    
    if(!fp)
        return(0);
    
    printf("Available agents: \n");
    fseek(fp, 0, SEEK_SET);
    
    memset(line_read,'\0',256);
    
    while(fgets(line_read,255, fp) != NULL)
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
                    printf("   ID: %s, Name: %s, IP: %s\n",
                        line_read, name, ip);
                }
                
            }
        }
    }

    if(line_read[0] != '\0')
        return(1);
    
    return(0);    
}

int add()
{

    char line_read[256];

    char name[66];
    char id[66];
    char ip[66];

    printf("\n");
    fp = fopen(KEYS_FILE,"a");
    if(!fp)
        ErrorExit("%s: Impossible to open %s",ARGV0,KEYS_FILE);
    fclose(fp);

    /* Opening for reading */
    fp = fopen(KEYS_FILE,"r");

    time2 = time(0);

    srand(time2 + time1 + getpid() + getppid());
    rand1 = rand();

    /* Zeroing strings */
    memset(str1,'\0',66);
    memset(str2,'\0', 66);


    /* Getting name */
    printf("Adding a new agent. Please provide the following:\n");
    printf("   A name for the new agent: ");
    fflush(stdout);
    memset(name, '\0', 66);
    if(fgets(name, 65, stdin) == NULL || strlen(name) > 62)
    {
        printf("\n%s: Error reading input\n",ARGV0);
        exit(1);
    }
    chomp(name);

    /* Getting IP */
    printf("   The IP Address for the new agent: ");
    fflush(stdout);
    memset(ip, '\0', 66);
    if(fgets(ip, 65, stdin) == NULL || strlen(ip) > 62)
    {
        printf("\n%s: Error reading input\n",ARGV0);
        exit(1);
    }
    chomp(ip);

    /* Getting ID */
    printf("   A Key ID  for the new agent: ");
    fflush(stdout);
    memset(id, '\0', 66);
    if(fgets(id, 65, stdin) == NULL || strlen(id) > 62)
    {
        printf("\n%s: Error reading input\n",ARGV0);
        exit(1);
    }
    chomp(id);

    printf("\n");

    /* Search for ID KEY */
    if(Is_ID(id) >= 0)
    {
        printf("%s: Error. ID '%s' already present. Starting over again..\n",
                ARGV0, id);
    }
    if(Is_Name(name) >= 0)
    {
        printf("%s: Error. Name '%s' already present. Starting over again..\n",
                ARGV0,name);
    }

    if(fp)
        fclose(fp);

    printf("Agent information:\n");
    printf("   ID:%s\n",id);
    printf("   Name:%s\n",name);
    printf("   IP Address:%s\n\n",ip);
    printf("Confirm adding it?(y/n): ");
    fflush(stdout);
    if(fgets(line_read, 65, stdin) == NULL || strlen(line_read) > 62)
    {
        printf("\n%s: Error reading input\n",ARGV0);
        exit(1);
    }
    if(line_read[0] == 'y' || line_read[0] == 'Y')
    {
        time3 = time(0);
        rand2 = rand();

        fp = fopen(KEYS_FILE,"a");
        if(!fp)
            ErrorExit("%s: Impossible to open %s",ARGV0,KEYS_FILE);

        snprintf(str1, 64, "%d%s%d",time3-time2, name, rand1);
        snprintf(str2, 64, "%d%s%s%d", time2-time1, ip, id, rand2);

        OS_MD5_Str(str1, md1);
        OS_MD5_Str(str2, md2);

        snprintf(str1, 64, "%s%d%d",md1,getpid(),rand());
        OS_MD5_Str(str1, md1);

        fprintf(fp,"%s %s %s %s%s\n",id, name, ip, md1,md2);

        fclose(fp);

        printf("Added.\n");
        return(0);
    }
    else
    {
        return(1);
    }

}

/* remove an agent */
int k_remove()
{
    
    char line_read[256];
    char u_id[256];
    
    printf("\n");
    fp = fopen(KEYS_FILE,"r+");
    if(!fp)
    {
        printf("No agent available to remove.\n");
        return(0);
    }

    if(!print_available())
    {
        printf("No agent available to remove.\n");
        fclose(fp);
        return(0);
    }

    printf("Provide the ID of the agent you want to remove: ");
    fflush(stdout);
    if(fgets(line_read, 65, stdin) == NULL || strlen(line_read) > 62)
    {
        printf("\n%s: Error reading input\n",ARGV0);
        exit(1);
    }
    
    chomp(line_read);

    if(Is_ID(line_read) >= 0)
    {
        printf("Confirm adding it?(y/n): ");
        fflush(stdout);
    
        strcpy(u_id, line_read);
        
        if(fgets(line_read, 65, stdin) == NULL || strlen(line_read) > 62)
        {
            printf("\n%s: Error reading input\n",ARGV0);
            exit(1);
        }
        if(line_read[0] == 'y' || line_read[0] == 'Y')
        {
            fsetpos(fp, &fp_pos);
            fprintf(fp, "# # # #");
            printf("Agent '%s' removed.\n",u_id);    
        }
        else
        {
            printf("Not removing ..\n");
        }
    }

    else
    {
        printf("Invalid ID '%s' given.", line_read);
    }

    fclose(fp);
    return(0);
}

int k_import()
{
    char b64[512];
    char *b64_dec;
   
    char *name; char *ip;
     
    char line_read[256];
    
    printf("\n");
    
    fp = fopen(KEYS_FILE,"w");
    if(!fp)
    {
        printf("%s: Error. Impossible to open the agent key file for writting"
                ,ARGV0);
        exit(1);
    }

    printf("Provide the Key generated from the server.\n");
    printf("The best approach is to cut and paste it.\n"
            "** OBS: Do not include spaces or new lines.\n"
            "Paste it here:\n");

    memset(b64,'\0',512);
    if(fgets(b64, 510, stdin) == NULL)
    {
        printf("\n%s: Error reading input\n",ARGV0);
        exit(1);
    }

    chomp(b64);

    b64_dec = decode_base64(b64);
    if(b64_dec == NULL)
    {
        printf("\nInvalid authentication key. Try again.. \n");
        return(0);
    }
    
    memset(line_read, '\0', 256);
    strncpy(line_read, b64_dec, 255);

    name = index(b64_dec, ' ');
    if(name && strlen(line_read) < 255)
    {
        *name = '\0';
        name++;
        ip = index(name, ' ');
        if(ip)
        {
            *ip = '\0';
            ip++;
            
            printf("\n");
            printf("Agent information:\n");
            printf("   ID:%s\n",b64_dec);
            printf("   Name:%s\n",name);
            printf("   IP Address:%s\n\n",ip);
            printf("Confirm adding it?(y/n): ");
            fflush(stdout);

            if(fgets(b64, 65, stdin) == NULL || strlen(b64) > 62)
            {
                printf("\n%s: Error reading input\n",ARGV0);
                exit(1);
            }

            if(b64[0] == 'y' || b64[0] == 'Y')
            {
                fprintf(fp,"%s\n",line_read);
                printf("Added\n");
                fclose(fp);

                return(1);
            }
        }
    }
    
    fclose(fp);
    printf("\nInvalid authentication key. Try again.. \n");
    return(0);

}

/* extract base64 for a specific agent */
int k_extract()
{

    char line_read[256];

    printf("\n");
    fp = fopen(KEYS_FILE,"r");
    if(!fp)
    {
        printf("No agent available to extract the key.\n");
        return(0);
    }

    if(!print_available())
    {
        printf("No agent available to extract the key.\n");
        fclose(fp);
        return(0);
    }

    printf("Provide the ID of the agent you want to extract they key: ");
    fflush(stdout);
    if(fgets(line_read, 65, stdin) == NULL || strlen(line_read) > 62)
    {
        printf("\n%s: Error reading input\n",ARGV0);
        exit(1);
    }
   
    chomp(line_read);
     
    if(Is_ID(line_read) >= 0)
    {
        char n_id[36];
        char *b64_enc;
        fsetpos(fp, &fp_pos);

        memset(n_id, '\0', 36);
        strncpy(n_id, line_read, 34);
        if(strlen(n_id) >= 33)
        {
            printf("\n%s: Error reading input. Invalid ID.\n",ARGV0);
            exit(1);
        }

        if(fgets(line_read, 255, fp) == NULL)
        {
            printf("\n%s: Error handling keys file. Exiting.\n",ARGV0);
            exit(1);
        }

        chomp(line_read);
       
        b64_enc = encode_base64(strlen(line_read),line_read);
        if(b64_enc == NULL)
        {
            printf("\n%s: Error extracting agent key. Exiting.\n",ARGV0);
            exit(1);
        }
        
        printf("Agent key information for '%s' is: \n",n_id);
        printf("%s\n",b64_enc);

        free(b64_enc);
                
    }

    else
    {
        printf("Invalid ID '%s' given.", line_read);
    }

    fclose(fp);
    return(0);
}

int main(int argc, char **argv)
{
    char *answer;
    char *group = GROUPGLOBAL;
    gid_t gid;
    
   
    time1 = time(0);
     
    answer = (char *)calloc(sizeof(char), 74);
    if(!answer)
    {
        ErrorExit(MEM_ERROR,ARGV0);
    }
    
    /** Privilege seprating .. **/
    
    /* Getting the group */
    gid = Privsep_GetGroup(group);
    if(gid < 0)
	    ErrorExit(USER_ERROR,"",group);
	
    /* Setting the group */
    if(Privsep_SetGroup(gid) < 0)
	    ErrorExit(SETGID_ERROR,ARGV0,gid);
    
    /* Chrooting to the default directory */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit("%s: Impossible to chroot to: %s",ARGV0,dir);

    /* Setting umask */
   // n_umask = umask(0027);

    //fp = fopen(KEYS_FILE,"a");
    //if(!fp)
      //  ErrorExit("%s: Impossible to open %s",ARGV0,KEYS_FILE);
    
    
    /* Little shell */
    while(1)
    {
        printf("\n");
        printf("OSSEC HIDS Agent manager.\n");
        printf("The following options are available:\n");
        
        #ifndef CLIENT
        printf("   (A)dd an agent (A).\n");    
        printf("   (E)xtract key for an agent (E).\n");    
        printf("   (R)emove an agent (R).\n");
        #endif
        
        printf("   (I)mport key for an agent (I).\n");    
        printf("   (Q)uit.\n");

        #ifdef CLIENT
        printf("Choose your actions: I or Q: ");
        #else
        printf("Choose your actions: A,E,I,R or Q: ");
        #endif
        
        fflush(stdout);
        
        memset(answer,'\0',74);
        if(fgets(answer, 72, stdin) == NULL || strlen(answer) > 62)
        {
            printf("\n%s: Error reading input\n",ARGV0);
            exit(1);
        }

        /* Skippinh any  space */
        while(*answer == ' ' || *answer == '\t')
            answer++;
            
        switch(answer[0])
        {
            case 'A':
            case 'a':
                add();
                break;
            case 'e':
            case 'E':
                k_extract();
                break;
            case 'i':
            case 'I':
                k_import();
                break;    
            case 'r':
            case 'R':
                k_remove();
                break;
            case 'q':
            case 'Q':
                printf("\n Exiting..\n");
                exit(0);    
            default:    
                printf("\n ** Invalid Action ** \n\n");
                break;            
        }

        continue;
        
    }
    return(0);
}

/* EOF */
