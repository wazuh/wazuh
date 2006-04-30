/*   $OSSEC, cleanevent.c, v0.3, 2006/03/04, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.3(2006/03/04): Moving the decoder away from here. Some
 *                   optimizations.
 * v0.2(2005/08/26): Fixing the decoder for snort-fast alerts
 * v0.1:
 */
  

#include "shared.h"
#include "os_regex/os_regex.h"


/* local headers */
#include "eventinfo.h"
#include "analysisd.h"
#include "fts.h"
#include "config.h"


/* To translante between month (int) to month (char) */
char *(month[])={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug",
	            "Sept","Oct","Nov","Dec"};



                
/* OS_CleanMSG v0.3: 2006/03/04
 * Format a received message in the 
 * Eventinfo structure.
 */
int OS_CleanMSG(char *msg, Eventinfo *lf)
{
    char *pieces[2];
    
    int hostname_size = 0, loglen;
    
    struct tm *p;

    /* Going after the first piece */
    msg+=2;

    pieces[0] = msg;
    
    pieces[1] = strchr(msg, ':');
    if(!pieces[1])
    {
        merror(FORMAT_ERROR,ARGV0);
        return(-1);
    }
    
    *pieces[1] = '\0';
    pieces[1]++;    
    
    /* Now pieces[0] is the location and pieces[1] the log itself */
    loglen = strlen(pieces[1]) + 1;
    
    
    /* Checking for the syslog date format. 
     * ( ex: Dec 29 10:00:01 ) 
     */	
    if( (loglen > 16) && 
        (pieces[1][3] == ' ') && 
        (pieces[1][6] == ' ') && 
        (pieces[1][9] == ':') && 
        (pieces[1][12] == ':') && 
        (pieces[1][15] == ' ') )
    {

        /* Use the date from the log instead of using the
         * date from when the log was received 
         */
        if(Config.keeplogdate)
        {
            /* Getting the month */
            strncpy(lf->mon,pieces[1],3);
            pieces[1]+=4;

            /* Getting the day */
            lf->day = atoi(pieces[1]);
            pieces[1] = index(pieces[1], ' ');
            if(!pieces[1])
            {
                merror(FORMAT_ERROR,ARGV0);
                return(-1);

            }
            pieces[1]++;

            /* Getting the hour */
            os_calloc(9,sizeof(char), lf->hour);
            strncpy(lf->hour,pieces[1],8);

            pieces[1]+=9;
        }
        else
        {
            pieces[1]+=16;
        }

        /* Assining the memory for hostname */
        os_calloc(OS_FLSIZE, sizeof(char), lf->hostname);
        do
        {
            if(hostname_size >= OS_FLSIZE)
            {
                merror("%s: Invalid hostname (greater than %d): '%s'",
                                             ARGV0, OS_FLSIZE, pieces[1]);
                return(-1);
                break;
            }
            lf->hostname[hostname_size++] = *pieces[1];
        }while(*(++pieces[1]) != ' ');


        /* Apending the \0 to the hostname string */
        lf->hostname[hostname_size] = '\0';
        
        /* Moving pieces[1] to the beginning of the log message */
        pieces[1]++;
    }
    
    /* xferlog date format 
     * Mon Apr 17 18:27:14 2006 1 64.160.42.130
     */
    else if((loglen > 28) &&
            (pieces[1][3] == ' ')&&
            (pieces[1][7] == ' ')&&
            (pieces[1][10] == ' ')&&
            (pieces[1][13] == ':')&&
            (pieces[1][16] == ':')&&
            (pieces[1][19] == ' ')&&
            (pieces[1][24] == ' ')&&
            (pieces[1][26] == ' '))
    {
        /* Moving pieces to the beginning of the message */
        pieces[1]+=24;
    }
    

    /* Checking for snort date format
     * ex: 01/28-09:13:16.240702  [**] 
     */ 
    else if( (loglen > 23) && 
             (pieces[1][2] == '/') && 
             (pieces[1][5] == '-') &&
             (pieces[1][8] == ':') && 
             (pieces[1][11]== ':') &&
             (pieces[1][14]== '.') && 
             (pieces[1][21] == ' ') )
    {
        /* Use the date from the log instead of using the
         * date from when the log was received 
         */
        if(Config.keeplogdate)
        {
            /* Getting the month */
            int month_int;
            month_int = atoi(pieces[1]) - 1;
            if((month_int < 0) || (month_int > 11))
            {
                merror(FORMAT_ERROR,ARGV0);
                return(-1);
            }
            
            strncpy(lf->mon, month[month_int], 3);
            pieces[1]+=3;


            /* Getting the day */
            lf->day = atoi(pieces[2]);
            pieces[1]+=3;
           
            os_calloc(9, sizeof(char),lf->hour); 
            strncpy(lf->hour,pieces[1],8);
            
            pieces[1]+=17;
        }
        else
        {
            pieces[1]+=23;
        }
    }

    /* Checking for apache log format */
    /* [Fri Feb 11 18:06:35 2004] [warn] */
    else if( (loglen > 27) && 
             (pieces[1][0] == '[') && 
             (pieces[1][4] == ' ') &&
             (pieces[1][8] == ' ') && 
             (pieces[1][11]== ' ') &&
             (pieces[1][14]== ':') && 
             (pieces[1][17]== ':') &&
             (pieces[1][20]== ' ') && 
             (pieces[1][25]== ']') )
    {
        /* Use the date from the log instead of using the
         * date from when the log was received 
         */
        if(Config.keeplogdate)
        {
            /* Getting the month */
            pieces[1]+=5;
            strncpy(lf->mon,pieces[1],3);
            
            pieces[1]+=4;
            
            /* Getting the day */
            lf->day = atoi(pieces[1]);
            pieces[1]+=3;

            /* Getting the hour */ 
            os_calloc(9,sizeof(char), lf->hour);
            strncpy(lf->hour,pieces[1],8);
            pieces[1]+=9;

            /* Getting the year */
            lf->year = atoi(pieces[1]);
            
            pieces[1]+=6;
        }
        
        else
        {
            pieces[1]+=27;
        }
    }
    /* Checking for squid date format
     * 1140804070.368  11623
     * seconds from 00:00:00 1970-01-01 UTC
     */
    else if((loglen > 32) && 
            (pieces[1][0] == '1') &&
            (pieces[1][1] == '1') &&
            (pieces[1][10] == '.') &&
            (isdigit((int)pieces[1][13])) &&
            (pieces[1][14] == ' ') &&
            ((pieces[1][21] == ' ')||(pieces[1][22] == ' ')))
    {
        pieces[1]+=14;

        /* We need to start at the size of the event */
        while(*pieces[1] == ' ')
        {
            pieces[1]++;
        }
    }


    /* Assigning the values in the strucuture */
    os_strdup(pieces[1], lf->log);


    /* location  */        
    lf->location = pieces[0];


    /* Setting up the event data */
    lf->time = c_time;
    p = localtime(&c_time);


    
    /* If the date was not gathered from the log,
     * assign it
     */
    if(lf->day == 0)
    {
        lf->day = p->tm_mday;
    }

    if(lf->year == 0)
    {
        lf->year = p->tm_year+1900;
    }
    
    if(lf->mon[0] == '\0')
    {
        strncpy(lf->mon,month[p->tm_mon],3);
    }

    
    if(!lf->hour)
    {
        os_calloc(9,sizeof(char), lf->hour);

        snprintf(lf->hour,9,"%02d:%02d:%02d",
                         p->tm_hour,
                         p->tm_min,
                         p->tm_sec);
    }
   


    /* Getting the global hour/weekday */
    __crt_hour = p->tm_hour;
    __crt_wday = p->tm_wday;   
  
    
    return(0);

}

/* EOF */
