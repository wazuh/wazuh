/*   $OSSEC, stats.c, v0.3, 2005/08/22, Daniel B. Cid$   */
                    
/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.3 (2005/08/22): Fixing gethour behavior.
 * v0.2 (2005/02/17): none
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "analysisd.h"
#include "stats.h"
#include "rules.h"

#include "error_messages/error_messages.h"

#include "headers/file_op.h"
#include "alerts/alerts.h"

#include "headers/debug_op.h"

char *(weekdays[])={"Sunday","Monday","Tuesday","Wednesday","Thursday",
		"Friday","Saturday"};


/* Stats definitions */
#define STATWQUEUE	"/stats/weekly"
#define STATQUEUE	"/stats/hourly"
#define MAXDIFF		300
#define MINDIFF	    20	

/* Global vars */
int _RWHour[7][24];
int _CWHour[7][24];

int _RHour[24];
int _CHour[24];

extern int __crt_wday;
extern int __crt_hour;

int _cignorehour = 0;
int _fired = 0;


char __comment[192];

/* Last msgs, to avoid floods */
char *_lastmsg;
char *_prevlast;
char *_pprevlast;


/* gethour: v0.2
 * Return the parameter (event_number + 15 % of it)
 * If event_number < MINDIFF, return MINDIFF
 * If event_number > MAXDIFF, return MAXDIFF
 */
int gethour(int event_number)
{
    int event_diff;

    event_diff = (event_number * 15)/100;

    event_diff++;
    
    if(event_diff < MINDIFF)
        return(event_number + MINDIFF);
    else if(event_diff > MAXDIFF)
        return(event_number + MAXDIFF);
        
    return(event_number + event_diff);
}


/* Update_Hour: done daily  */
void Update_Hour()
{
    int i=0,j=0;

    /* Hourly update */
    for(i=0;i<=23;i++)
    {
        char _hourly[128]; /* _hourly file */
        
        FILE *fp;
        
        /* If saved hourly = 0, just copy the current hourly rate */
        if(_RHour[i] == 0)
            _RHour[i]=_CHour[i];
        
        else if(_RHour[i] == 0)
            continue;
        
        else
        {
            /* The average is going to be 3* the saved hour +
             * the currently hourly rate, divided by 4 */
            _RHour[i]=((_CHour[i]+(3*_RHour[i]))/4)+1;
        }

        snprintf(_hourly,128,"%s/%d",STATQUEUE,i);
        fp = fopen(_hourly, "w");
        if(fp)
        {
            fprintf(fp,"%d",_RHour[i]);
            fclose(fp);
        }
        	
        else
            merror("%s: logstats: Impossible to open %s",ARGV0,_hourly);
            
        _CHour[i] = 0; /* Zeroing the currently  hour */
    }

    /* Weekly */
    for(i=0;i<=6;i++)
    {
        char _weekly[128];
        FILE *fp;

        for(j=0;j<=23;j++)
        {
            if(_RWHour[i][j] == 0)
                _RWHour[i][j] = _CWHour[i][j];
                
            else if(_RWHour[i][j] == 0)
                continue;
                
            else
                _RWHour[i][j]=((_CWHour[i][j]+(3*_RWHour[i][j]))/4)+1;	

            snprintf(_weekly,128,"%s/%d/%d",STATWQUEUE,i,j);
            fp = fopen(_weekly, "w");
            if(fp)
            {
                fprintf(fp,"%d",_RWHour[i][j]);
                fclose(fp);
            }
            else
                merror("%s: logstats: Impossible to open %s",ARGV0, _weekly);
            
            _CWHour[i][j]=0;	
        }   
    }

    return;
}


/* Check Hourly stats */
int Check_Hour(Eventinfo *lf)
{
    _CHour[__crt_hour]++;
    _CWHour[__crt_wday][__crt_hour]++;	


    /* checking if any message was already fired for this hour */
    if((_fired == 1)&&(_cignorehour == __crt_hour))
        return(0);

    else if(_cignorehour != __crt_hour)
    {
        _cignorehour=__crt_hour;
        _fired = 0;
    }


    /* checking if passed the threshold */
    if(_RHour[__crt_hour] != 0)
    {
        if(_CHour[__crt_hour] > (_RHour[__crt_hour]))
        {
            if(_CHour[__crt_hour] > (gethour(_RHour[__crt_hour])))
            {
                lf->sigid = STATS_PLUGIN;
                
                /* snprintf will null terminate */
                snprintf(__comment, 191,
                                     "Excessive number of connections during "
                                     "this hour.\n The average number of logs"
                                     " between %d:00 and %d:00 is %d. We "
                                     "reached %d.",__crt_hour,__crt_hour+1,
                                     _RHour[__crt_hour],_CHour[__crt_hour]);
                
                
                /* Safe, as comment is not used in the event list */
                lf->comment = __comment;                    
                
                _fired = 1;
                return(1);
            }
        }
    }

    /* checking for the hour during a specific day of the week */
    if(_RWHour[__crt_wday][__crt_hour] != 0)
    {
        if(_CWHour[__crt_wday][__crt_hour] > _RWHour[__crt_wday][__crt_hour])
        {
            if(_CWHour[__crt_wday][__crt_hour] > 
                    gethour(_RWHour[__crt_wday][__crt_hour]))
            {
                lf->sigid = STATS_PLUGIN;
                
                snprintf(__comment, 191,
                                     "Excessive number of connections during "
                                     "this hour.\n The average number of logs"
                                     " between %d:00 and %d:00 on %s is %d. We"
                                     " reached %d.",__crt_hour,__crt_hour+1,
                                     weekdays[__crt_wday],
                                     _RWHour[__crt_wday][__crt_hour],
                                     _CWHour[__crt_wday][__crt_hour]);
                
                
                lf->comment = __comment;
                _fired = 1;
                return(1);
            }
        }
    }
    return(0);	
}

/* Starting hourly stats and other necessary variables */
int Start_Hour(int *today, int *thishour)
{
    int i=0,j=0;
    struct tm *p;

    /* Current time */
    p = localtime(&c_time);

    /* Other global variables */
    _fired=0;
    _cignorehour=0;

    *today = p->tm_mday;
    *thishour = p->tm_hour;

    /* Last three messages
     * They are used to keep track of the last
     * messages received to avoid floods.
     */
    _lastmsg = NULL;
    _prevlast = NULL;
    _pprevlast = NULL;
            
    
    /* Creating the stat queue directories */        
    if(IsDir(STATWQUEUE) == -1)
        if(mkdir(STATWQUEUE,0770) == -1)
        {
            merror("%s: logstat: Impossible to create stat queue: %s",
                            ARGV0, STATWQUEUE);
            return(-1);
        }       

    if(IsDir(STATQUEUE) == -1)
        if(mkdir(STATQUEUE,0770) == -1)
        {
            merror("%s: logstat: Impossible to create stat queue: %s",
                            ARGV0, STATQUEUE);
            return(-1);
        }       

    /* Creating hourly directory */
    for(i=0;i<=23;i++)
    {
        char _hourly[128];
        snprintf(_hourly,128,"%s/%d",STATQUEUE,i);

        _CHour[i]=0;	
        if(File_DateofChange(_hourly) < 0)
            _RHour[i]=0;
            
        else
        {
            FILE *fp;
            fp = fopen(_hourly, "r");
            if(!fp)
                _RHour[i]=0;
            else
            {
                if(fscanf(fp,"%d",&_RHour[i]) <= 0)
                    _RHour[i]=0;
                fclose(fp);
            }	
        }
    }

    /* Creating weekly/hourly directories */
    for(i=0;i<=6;i++)
    {
        char _weekly[128];
        snprintf(_weekly,128,"%s/%d",STATWQUEUE,i);
        if(IsDir(_weekly) == -1)
            if(mkdir(_weekly,0770) == -1)
            {
                merror("%s: logstat: Impossible to create stat queue: %s",
                        ARGV0, _weekly);
                return(-1);
            }

        for(j=0;j<=23;j++)
        {
            _CWHour[i][j]=0;
            snprintf(_weekly,128,"%s/%d/%d",STATWQUEUE,i,j);
            if(File_DateofChange(_weekly) < 0)
                _RWHour[i][j]=0;
            else
            {
                FILE *fp;
                fp = fopen(_weekly, "r");
                if(!fp)
                    _RWHour[i][j]=0;
                else
                {
                    if(fscanf(fp,"%d",&_RWHour[i][j]) <= 0)
                        _RWHour[i][j]=0;
                    fclose(fp);
                }	
            }	
        }	
    }
    return(0);
}


/* LastMsg_Stats: v0.2: 2005/03/17 
 * check if the message received is repeated. Doing
 * it to avoid floods
 */
int LastMsg_Stats(char *log)
{
    char *nlog;

	if(_lastmsg == NULL)
		return(0);

    /* Moving the char pointer to after the p_name[pid]. 
     * BUG 1102
     */
    nlog = index(log,' ');
    if(nlog == NULL)
    {
        merror("%s: Message error (index)",ARGV0);
        return(0);
    }
    nlog++;

	if((_lastmsg != NULL)&&(strcmp(nlog,_lastmsg) == 0))
		return(1);		
		
	else if((_prevlast != NULL)&&(strcmp(nlog,_prevlast) == 0))
		return(1);

	else if((_pprevlast != NULL)&&(strcmp(nlog,_pprevlast) == 0))
		return(1);
	
	return(0);
}

/* LastMsg_Change: v0.2: 2005/03/17 
 * If the message is not repeated, rearrange the last
 * received messages
 */
void LastMsg_Change(char *log)
{
    char *nlog;

    if(_prevlast)
    {
        free(_pprevlast);
        _pprevlast = strdup(_prevlast);
    }
    if(_lastmsg)
    {
        free(_prevlast);
        _prevlast = strdup(_lastmsg);

        free(_lastmsg);
        _lastmsg = NULL;
    }

    /* Moving to after the proccess ID/PID 
     * Bug 1102
     */
    nlog = index(log,' ');
    if(nlog == NULL)
    {
        merror("%s: Message indexing error (index)",ARGV0);
        return;
    }
    nlog++;
        
    _lastmsg = strdup(nlog);
    return;
}


/* EOF */
