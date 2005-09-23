/*   $OSSEC, addagent.c, v0.2, 2005/02/07, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.1: Creation of the tool (2005/02/01).
 * v0.1: Code inspection (2005/02/15).
 *
 * Last modification: 2005/02/07
 */

/* addagent tool
 * Adds an agent to a server.
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

#ifndef ARGV0
  #define ARGV0 "addagent"
#endif
    
int dbg_flag=0;
int chroot_flag=0;

char *dir=DEFAULTDIR;

/* Help function */
void help()
{
    printf("Usage: \n");
    printf("\t%s -n agent_name\n",ARGV0);
    printf("\t%s -i agent_id\n",ARGV0);
    printf("\t%s -p passphrase\n",ARGV0);
    printf("\t%s -a client ip address\n\n",ARGV0);
    printf("Addagent will read the argument above and generate\n");
    printf("an entry in the \"client.keys\" file to allow the client\n");
    printf("to access the server.\n\n");
    printf("It will also generate another file that is supposed to be\n");
    printf("moved to the client location.\n\n");
    printf("The passphrase is only used to generate some randoness. So\n");
    printf("you don't need to remember it. Choose anything you want.\n");
    printf("If the client is going to cross a NAT device before \n");
    printf("reaching the server, make sure to choose the IP after\n");
    printf("the translation!\n\n");
    printf("The IDs must be UNIQUE!\n\n");
    printf("Examples:\n");
    printf("\t%s/%s -n cl1 -i id123 -p \"adwjidijq\" -a 10.1.1.1\n",
                                        DEFAULTDIR, ARGV0);
    printf("\t/var/ossec/bin/addagent -n name -i 12 -p \"lala1\" "
            "-a 10.1.1.2\n\n");
    exit(0);
}

/* main, v0.1, 2005/02/07
 */
int main(int argc, char **argv)
{
    FILE *fp;
    char *name=NULL;
    char *id=NULL;
    char *pass=NULL;
    char *ip=NULL;
    int c;
    int gid;

    mode_t n_umask;

    unsigned short int rand0;
    unsigned short int rand1;
    unsigned short int rand2;

    os_md5 md1;	
    os_md5 md2;	

    char tmpstr1[65];
    char tmpstr2[65];
    
    char *group=GROUPGLOBAL;
    
    verbose("%s: Creating client key",ARGV0);

    while((c = getopt(argc, argv, "hp:a:i:n:")) != -1){
        switch(c){
            case 'n':
                if(!optarg)
                    ErrorExit("%s: -n needs an argument",ARGV0);
                name=optarg;
                break;
            case 'h':
                help();
                break;
            case 'i':
                if(!optarg)
                    ErrorExit("%s: -i needs an argument",ARGV0);
                id=optarg;
                break;
            case 'a':
                if(!optarg)
                    ErrorExit("%s: -a needs an argument",ARGV0);
                ip=optarg;
                break;
            case 'p':
                if(!optarg)
                    ErrorExit("%s: -p needs an argument",ARGV0);
                pass=optarg;
                break;		
        }
    }

    if(argc < 7)
    {
        printf("Not enough arguments. \n");
        help();
    }
    
    if(ip == NULL)
        ErrorExit("You need to specify an IP address");
    if(pass == NULL)
        ErrorExit("You need to choose a pass phrase to be used");
    if(id == NULL)
        ErrorExit("You need to choose a unique ID for the client");
    if(name == NULL)
        ErrorExit("You need to choose a unique name for the client");

    if(!OS_StrIsNum(id))
        ErrorExit("The ID needs to be an integer");

    if((strlen(id) > 6)||(strlen(ip) > 18) || (strlen(name) > 32)
            || (strlen(pass) > 64))
        ErrorExit("Maximum size reached for some variable. id(max:6), ip(max:16), name(max:32), pass(max:64)");

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
    n_umask = umask(0027);

    fp = fopen(KEYS_FILE,"a");
    if(!fp)
        ErrorExit("%s: Impossible to open %s",ARGV0,KEYS_FILE);

    /* some randoness to the key string */
    srand( (unsigned) time(0) + getpid() );
    rand0 = (unsigned short int)rand();

    srand( rand() + getppid() );
    rand1 = (unsigned short int)rand();

    srand( rand1 + strlen(pass) );
    rand2 = (unsigned short int)rand();

    memset(tmpstr1,'\0',65);
    memset(tmpstr2,'\0', 65);

    snprintf(tmpstr1,64, "%hd%s%hd%s%s%d",rand0,pass,rand1,name,ip,rand());

    OS_MD5_Str(tmpstr1, md1);

    snprintf(tmpstr2,64, "%hd%hd%d%d%s%s",rand0,rand2,(int)getpid(),
                         (int)getppid(),pass,tmpstr1);
    OS_MD5_Str(tmpstr2, md2);

    memset(tmpstr1,'\0',65);
    memset(tmpstr2,'\0',65);

    /* Writting to the server client.keys */
    fprintf(fp,"%s %s %s %s%s\n",id, name, ip, md1,md2);
    fclose(fp);

    /* Writting to the client client.keys */
    snprintf(tmpstr1,64,"%s-%s",KEYS_FILE_NEW,id);
    fp = fopen(tmpstr1,"w");
    if(!fp)
        ErrorExit("%s: Impossible to open \"%s\"",ARGV0,tmpstr1);

    fprintf(fp,"%s %s %s %s%s\n",id, name, ip, md1,md2);
    fclose(fp);

    /* Revering to the old umask */
    umask(n_umask);
    
    memset(tmpstr1,'\0',65);	
    memset(md1,'\0',33);
    memset(md2,'\0',33);

    /* Output message */
    printf("\nAn entry was added at '%s%s' for the client %s(%s)\n\n",
            DEFAULTDIR, KEYS_FILE,ip,id);
    printf("You now need to move the file '%s/%s-%s' to the agent system\n",
            DEFAULTDIR,KEYS_FILE_NEW,id);
    printf("and rename it from '%s-%s' to '%s%s'\n\n",KEYS_FILE_NEW,
            id,DEFAULTDIR,KEYS_FILE);
    
    return(0);
}

/* EOF */
