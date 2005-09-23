/*   $OSSEC, os_execd_client.c, v0.1, 2005/03/15, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "headers/defs.h"
#include "headers/debug_op.h"
#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"
#include "execd.h"

/* Clear the ExecdMSg */
void OS_FreeExecdMsg(ExecdMsg *msg)
{
    if(msg->name)
    {
        free(msg->name);
        msg->name=NULL;
    }
    if(msg->args)
    {
        register short int i=0;
        while(msg->args[i])
        {
            free(msg->args[i]);
            msg->args[i]=NULL;
            i++;
        }
        free(msg->args);
        msg->args=NULL;
    }
    msg->name_size=0;
    msg->args_size=0;
    return;
}


/* Clear on char and one **char */
void _ClearMem(char *ch1, char **ch2)
{
    if(ch1)
    {
        free(ch1);
        ch1=NULL;
    }
    
    if(ch2)
    {
        register short int i=0;
        while(ch2[i])
        {
            free(ch2[i]);
            ch2[i]=NULL;
            i++;
        }
        free(ch2);
        ch2=NULL;
    }
    return;
}

int OS_SendExecQ(int socket, ExecdMsg *execd)
{
    char *tmpstr=NULL;

    tmpstr = calloc(OS_MAXSTR,sizeof(char));
    if(tmpstr == NULL)
    {
        merror(MEM_ERROR,ARGV0);
        return(-1);
    }
    
    memset(tmpstr,'\0',OS_MAXSTR);
    snprintf(tmpstr,OS_MAXSTR-1,"%d:%d:%d:%s%s",execd->type,
            execd->name_size,
            execd->args_size,
            execd->name,
            "-h");
            /*execd->args);*/

    if(send(socket,tmpstr,strlen(tmpstr),0) < 0)
        return(-1);

    /* msg sent */
    OS_FreeExecdMsg(execd);
    return(0);
}

/* OS_RecvExecQ, v0.1, 2005/03/15
 * Receive a Message on the Mail queue
 */
int OS_RecvExecQ(int socket, ExecdMsg *execd)
{
    int i=0,ts=0;
    char  *ret=NULL;
    char  **pieces=NULL;

    execd->name=NULL;
    execd->args=NULL;
    execd->name_size=0;
    execd->args_size=0;
    execd->type=0;

    ret = (char  *) calloc(OS_MAXSTR,sizeof(char));
    if(ret == NULL)
        return(-1);

    if((ts=recvfrom(socket,ret,OS_MAXSTR-1,0,NULL,0))<0)
    {
        _ClearMem(ret,NULL);
        return(-1);
    }

    /* Breaking the string in 4 pieces */
    pieces = OS_StrBreak(':', ret, 4);
    if(pieces == NULL)
    {
        _ClearMem(ret,NULL);
        return(-1);
    }

    if(OS_StrIsNum(pieces[0]) == 0)
        execd->type = atoi(pieces[0]);
    if(OS_StrIsNum(pieces[1]) == 0)
        execd->name_size = atoi(pieces[1]);
    if(OS_StrIsNum(pieces[2]) == 0)
        execd->args_size = atoi(pieces[2]);

    execd->name = calloc(execd->name_size+1,sizeof(char));
    /*mail->body = calloc(mail->body_size+1,sizeof(char));*/
    if(execd->name == NULL)
    {
        OS_FreeExecdMsg(execd);
        _ClearMem(ret,pieces);
        return(-1);
    }

    for(i=0;i<(execd->name_size);i++)
        execd->name[i]=pieces[3][i];

/*
    for(;i<strlen(pieces[3]);i++)
    {
        if(j >= mail->body_size)
            break;
        mail->body[j++]=pieces[3][i];
    }
*/

    /* Cleaning the memory */
    _ClearMem(ret,pieces);
    return(0);
}
/* EOF */
