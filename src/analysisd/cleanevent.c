/*   $OSSEC, cleanevent.c, v0.2, 2005/08/26, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.2(2005/08/26): Fixing the decoder for snort-fast alerts
 * v0.1:
 */
  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "headers/debug_op.h"
#include "headers/mq_op.h"
#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"

/* local headers */
#include "eventinfo.h"
#include "analysisd.h"
#include "fts.h"
#include "config.h"

/* To translante between month (int) to month (char) */
char *(month[])={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug",
	            "Sept","Oct","Nov","Dec"};


/* current hour and weekday.
 * Used to generate hourly statistics 
 */
extern int  __crt_hour;
extern int  __crt_wday;

/* External Functions prototypes
 */
void DecodeEvent(Eventinfo *lf);
int DecodeSnort(Eventinfo *lf, char c);
void DecodeSyscheck(Eventinfo *lf);
                

                
/* OS_CleanMSG v0.2: 2005/03/22
 * Format a received message in the 
 * Eventinfo structure.
 */
int OS_CleanMSG(char *msg, Eventinfo *lf)
{
    char **pieces=NULL;
    char *log3;
    
    int hostname_size=0,loglen=0;
    
    struct tm *p;


    /* MSG Can't be NULL */
    if(msg == NULL)
    {
        merror(NULL_ERROR,ARGV0);
        return(-1);
    }

    /* Calling StrBreak */
    pieces = OS_StrBreak(':', msg, 4); /* Divide in 4 pieces */
    if(pieces == NULL)
    {
        merror(FORMAT_ERROR,ARGV0);
        return(-1);
    }

    
    if((pieces[0] == NULL)||(pieces[1] == NULL)||
            (pieces[2] == NULL)||(pieces[3] == NULL))
    {
        merror(FORMAT_ERROR,ARGV0);
        return(-1);
    }

    log3 = pieces[3]; /* to free later */
    loglen=strlen(pieces[3])+1;

    
    /* Zeroing the date - Syslog */	
    if(loglen > 16 && pieces[3][3] == ' '&& pieces[3][6] == ' ' && 
            pieces[3][9] == ':' && pieces[3][12] == ':' 
            && pieces[3][15] == ' ')
    {

        /* Use the date from the log instead of using the
         * date from when the log was received 
         */
        if(Config.keeplogdate)
        {
            lf->mon = (char *)calloc(4,sizeof(char));
            if(!lf->mon)
            {
                ErrorExit(MEM_ERROR,ARGV0);
            }
            strncpy(lf->mon,pieces[3],3);

            pieces[3]+=4;

            lf->day = atoi(pieces[3]);

            pieces[3]+=1;

            lf->hour = (char *)calloc(9,sizeof(char));
            if(!lf->hour)
            {
                ErrorExit(MEM_ERROR,ARGV0);
            }
            strncpy(lf->hour,pieces[3],8);

            pieces[3]+=11;
        }
        else
            pieces[3]+=16;

        /* Assining the memory for hostname */
        lf->hostname = calloc(256,sizeof(char));
        if(lf->hostname == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);    
        }
        
        do
        {
            if(hostname_size >= 255)
            {
                merror("%s: Error on message (hostname too big): '%s'",
                        ARGV0,pieces[3]);
                break;
            }
            lf->hostname[hostname_size++] = *pieces[3];
        }while(*(++pieces[3]) != ' ');

        /* Apending the \0 to the hostname string */
        lf->hostname[hostname_size] = '\0';
        /* Moving pieces[3] to the beginning of the log message */
        pieces[3]++;
    }


    
    /* Zeroing the date - snort */
    else if(loglen > 23 && pieces[3][2] == '/' && pieces[3][5] == '-'&&
            pieces[3][8] == ':' && pieces[3][11] == ':' &&
            pieces[3][14] == '.' && pieces[3][21] == ' ')
    {
        /* Use the date from the log instead of using the
         * date from when the log was received 
         */
        if(Config.keeplogdate)
        {
            lf->mon = (char *)calloc(4,sizeof(char));
            if(!lf->mon)
            {
                ErrorExit(MEM_ERROR,ARGV0);
            }
            snprintf(lf->mon,4,"%d",atoi(pieces[3]));

            pieces[3]+=3;

            lf->day = atoi(pieces[3]);

            pieces[3]+=3;
            
            lf->hour = (char *)calloc(9,sizeof(char));
            if(!lf->hour)
            {
                ErrorExit(MEM_ERROR,ARGV0);
            }
            
            strncpy(lf->hour,pieces[3],8);
            
            pieces[3]+=17;
        }
        else
            pieces[3]+=23;
    }

    /* Zeroing the date - apache-err */
    /* [Fri Feb 11 18:06:35 2004] [warn] */
    else if(loglen > 27 && pieces[3][0] == '[' && pieces[3][4] == ' '&&
            pieces[3][8] == ' '&& pieces[3][11] == ' ' &&
            pieces[3][14] == ':' && pieces[3][17] == ':'&&
            pieces[3][20] == ' ' && pieces[3][25] == ']')
    {
        
        /* Use the date from the log instead of using the
         * date from when the log was received 
         */
        if(Config.keeplogdate)
        {
            pieces[3]+=4;
            
            lf->mon = (char *)calloc(4,sizeof(char));
            if(!lf->mon)
            {
                ErrorExit(MEM_ERROR,ARGV0);
            }
            strncpy(lf->mon,pieces[3],3);
            
            pieces[3]+=4;
            
            lf->day = atoi(pieces[3]);

            pieces[3]+=3;

            
            lf->hour = (char *)calloc(9,sizeof(char));
            if(!lf->hour)
            {
                ErrorExit(MEM_ERROR,ARGV0);
            }
            
            strncpy(lf->hour,pieces[3],8);

            pieces[3]+=9;

            lf->year = atoi(pieces[3]);
            
            pieces[3]+=7;
        }
        
        else
            pieces[3]+=27;    
    }


    /* Assigning the values in the strucuture */
    lf->log = strdup(pieces[3]);
    lf->location = pieces[1];
    lf->group = pieces[2];
    lf->type = UNKNOWN;


    /* Setting up the event data */
    lf->time = c_time;
    p = localtime(&c_time);


    
    /* If the date was not gathered from the log,
     * assign it
     */
    if(lf->day == 0)
    {
        lf->day  = p->tm_mday;
    }

    if(lf->year == 0)
    {
        lf->year =  p->tm_year+1900;
    }
    
    if(!lf->mon)
    {
        lf->mon = strdup(month[p->tm_mon]);

        if(!lf->mon)
        {
            /* memory error.. 
             */
            ErrorExit(MEM_ERROR,ARGV0); 
        }
    }

    
    if(!lf->hour)
    {
        lf->hour = (char*)calloc(9,sizeof(char));

        if(!lf->hour)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        snprintf(lf->hour,9,"%02d:%02d:%02d",
                         p->tm_hour,
                         p->tm_min,
                         p->tm_sec);
    }
   


    /* Getting the global hour/weekday */
    __crt_hour = p->tm_hour;
    __crt_wday = p->tm_wday;   
  
    
    #ifdef DEBUG
    printf("%s: DEBUG: Going to the plugins checking.\n",ARGV0);
    #endif

    /***  Running plugins ***/
  
      
    /* Snort plugin */
    if((pieces[0][0] == SNORT_MQ_FULLC) || 
       (pieces[0][0] == SNORT_MQ_FASTC))
    {
        /* Beginning of the snort msg */
        if(strncmp("[**] [",lf->log,6) == 0)
            DecodeSnort(lf, pieces[0][0]);
    }

    /* Integrity check from syscheck */
    else if(pieces[0][0] == SYSCHECK_MQ_C)
    {
        DecodeSyscheck(lf);
    }
     
    /* Checking if it is a snort alert from syslog */
    else if(strncmp("snort: [",lf->log,8) == 0)
    {
        DecodeSnort(lf, 0);
    }

    /* Run the Decoder plugins */
    else
    {
        DecodeEvent(lf);
    }

    
    /* Clearing the memory */
    /* We can't clear pieces[1] amd pieces[2]. lf
     * is pointing to it.
     */
     
    free(pieces[0]);
    free(log3);
    
    free(pieces);
    pieces = NULL;

    free(msg);
    
    return(0);
}

    /* EOF */
