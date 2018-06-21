/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _EVTINFO__H
#define _EVTINFO__H

#include "rules.h"
#include "decoders/decoder.h"

typedef enum syscheck_event_t { FIM_ADDED, FIM_MODIFIED, FIM_READDED, FIM_DELETED } syscheck_event_t;

typedef struct _DynamicField {
    char *key;
    char *value;
} DynamicField;

/* Event Information structure */
typedef struct _Eventinfo {
    /* Extracted from the event */
    char *log;
    char *full_log;
    const char * log_after_parent;
    const char * log_after_prematch;
    char *agent_id;
    char *location;
    char *hostname;
    char *program_name;
    char *comment;
    char *dec_timestamp;

    /* Extracted from the decoders */
    char *srcip;
    char *srcgeoip;
    char *dstip;
    char *dstgeoip;
    char *srcport;
    char *dstport;
    char *protocol;
    char *action;
    char *srcuser;
    char *dstuser;
    char *id;
    char *status;
    char *command;
    char *url;
    char *data;
    char *systemname;
    DynamicField *fields;
    int nfields;

    /* Pointer to the rule that generated it */
    RuleInfo *generated_rule;

    /* Pointer to the decoder that matched */
    OSDecoderInfo *decoder_info;

    /* Sid node to delete */
    OSListNode *sid_node_to_delete;

    /* Extract when the event fires a rule */
    size_t size;
    size_t p_name_size;

    /* Other internal variables */
    int matched;

    struct timespec time;
    int day;
    int year;
    char hour[10];
    char mon[4];

    /* SYSCHECK Results variables */
    syscheck_event_t event_type;
    char *filename;
    int perm_before;
    int perm_after;
    char *md5_before;
    char *md5_after;
    char *sha1_before;
    char *sha1_after;
    char *sha256_before;
    char *sha256_after;
    char *size_before;
    char *size_after;
    char *owner_before;
    char *owner_after;
    char *gowner_before;
    char *gowner_after;
    char *uname_before;
    char *uname_after;
    char *gname_before;
    char *gname_after;
    long mtime_before;
    long mtime_after;
    long inode_before;
    long inode_after;
    char *user;
    char *process;
    char *diff;
    const char *previous;
    const wlabel_t *labels;
} Eventinfo;

/* Events List structure */
typedef struct _EventNode {
    Eventinfo *event;
    struct _EventNode *next;
    struct _EventNode *prev;
} EventNode;

#ifdef TESTRULE
extern int full_output;
extern int alert_only;
#endif

/* Types of events (from decoders) */
#define UNKNOWN         0   /* Unknown */
#define SYSLOG          1   /* syslog messages */
#define IDS             2   /* IDS alerts */
#define FIREWALL        3   /* Firewall events */
#define WEBLOG          7   /* Apache logs */
#define SQUID           8   /* Squid logs */
#define DECODER_WINDOWS 9   /* Windows logs */
#define HOST_INFO       10  /* Host information logs (from nmap or similar) */
#define OSSEC_RL        11  /* OSSEC rules */
#define OSSEC_ALERT     12  /* OSSEC alerts */

/* FTS allowed values */
#define FTS_NAME        001000
#define FTS_SRCUSER     002000
#define FTS_DSTUSER     004000
#define FTS_SRCIP       000100
#define FTS_DSTIP       000200
#define FTS_LOCATION    000400
#define FTS_ID          000010
#define FTS_DATA        000020
#define FTS_SYSTEMNAME  000040
#define FTS_DONE        010000
#define FTS_DYNAMIC     020000

/** Functions for events **/

/* Search for matches in the last events */
Eventinfo *Search_LastEvents(Eventinfo *lf, RuleInfo *currently_rule);
Eventinfo *Search_LastSids(Eventinfo *my_lf, RuleInfo *currently_rule);
Eventinfo *Search_LastGroups(Eventinfo *my_lf, RuleInfo *currently_rule);

/* Zero the eventinfo structure */
void Zero_Eventinfo(Eventinfo *lf);

/* Free the eventinfo structure */
void Free_Eventinfo(Eventinfo *lf);

/* Add and event to the list of previous events */
void OS_AddEvent(Eventinfo *lf);

/* Return the last event from the Event list */
EventNode *OS_GetLastEvent(void);

/* Create the event list. Maxsize must be specified */
void OS_CreateEventList(int maxsize);

/* Find index of a dynamic field. Returns -1 if not found. */
const char* FindField(const Eventinfo *lf, const char *name);

/* Parse rule comment with dynamic fields */
char* ParseRuleComment(Eventinfo *lf);

/* Pointers to the event decoders */
void *SrcUser_FP(Eventinfo *lf, char *field, const char *order);
void *DstUser_FP(Eventinfo *lf, char *field, const char *order);
void *SrcIP_FP(Eventinfo *lf, char *field, const char *order);
void *DstIP_FP(Eventinfo *lf, char *field, const char *order);
void *SrcPort_FP(Eventinfo *lf, char *field, const char *order);
void *DstPort_FP(Eventinfo *lf, char *field, const char *order);
void *Protocol_FP(Eventinfo *lf, char *field, const char *order);
void *Action_FP(Eventinfo *lf, char *field, const char *order);
void *ID_FP(Eventinfo *lf, char *field, const char *order);
void *Url_FP(Eventinfo *lf, char *field, const char *order);
void *Data_FP(Eventinfo *lf, char *field, const char *order);
void *Status_FP(Eventinfo *lf, char *field, const char *order);
void *SystemName_FP(Eventinfo *lf, char *field, const char *order);
void *DynamicField_FP(Eventinfo *lf, char *field, const char *order);
void *None_FP(Eventinfo *lf, char *field, const char *order);

#endif /* _EVTINFO__H */
