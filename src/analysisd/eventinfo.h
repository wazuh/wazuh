/*   $OSSEC, eventinfo.h, v0.2, 2005/09/08, Daniel B. Cid$   */

/* Copyright (C) 2004, 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.2(2005/09/08): Multiple additions.
 * v0.1:
 */



#ifndef _EVTINFO__H

#define _EVTINFO__H
#include "rules.h"

/* Event Information structure */
typedef struct _Eventinfo
{
    char *log_tag;
    
    char *log;
    char *location;
    char *hostname;
    char *group;
    char *comment;
    char *info;
    char *last_events[12];  /* Last 12 events can be printed */

    char *srcip;
    char *dstip;
    char *user;
    char *dstuser;
    char *id;
    char *command;      /* Command executed */

    int fts;          /* What is going to the FTS */
    
    short int type;
    short int level;
    
    int sigid;
    int time;
    int frequency;


    char *hour;
    char *mon;
    int day;
    int year;
    int matched;    /* if the event has been matched on the past */

}Eventinfo;

/* Events List structure */
typedef struct _EventNode
{
    Eventinfo *event;
    struct _EventNode *next;
    struct _EventNode *prev;
}EventNode;


/* Points to the currently event being analuzed */
Eventinfo *currently_lf;


/** Types of events (plugin usage) **/
#define UNKNOWN		0   /* Unkown */
#define SYSLOG		1   /* syslog messages */
#define SNORT		2   /* Snort alerts */
#define FIREWALL    3   /* Firewall events */
#define IDS         4   /* IDS alerts */
#define SYSCHECK    5   /* syscheck integrity events */
#define ROOTCHECK   6   /* rootcheck messages */

/* FTS allowed values */
#define FTS_NAME     0001000
#define FTS_USER     0002000
#define FTS_DSTUSER  0004000
#define FTS_SRCIP    0000100
#define FTS_DSTIP    0000200
#define FTS_LOCATION 0000400
#define FTS_ID       0000010


/** Functions for events **/

/* Search for matches in the last events */
Eventinfo *Search_LastEvents(Eventinfo *lf, RuleInfo *currently_rule);

/* Zero the eventinfo structure */
void Zero_Eventinfo(Eventinfo *lf);

/* Free the eventinfo structure */
void Free_Eventinfo(Eventinfo *lf);

/* Add and event to the list of previous events */
void OS_AddEvent(Eventinfo *lf);

/* Return the last event from the Event list */
EventNode *OS_GetLastEvent();

/* Create the event list. Maxsize must be specified */
void OS_CreateEventList(int maxsize);


#endif /* _EVTINFO__H */
