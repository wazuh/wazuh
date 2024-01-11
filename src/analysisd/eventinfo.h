/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef EVTINFO_H
#define EVTINFO_H

#include "rules.h"
#include "decoders/decoder.h"

typedef enum syscheck_event_t { FIM_ADDED, FIM_MODIFIED, FIM_READDED, FIM_DELETED } syscheck_event_t;
typedef struct _EventNode EventNode;


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
    char *url;
    char *data;
    char *extra_data;
    char *systemname;
    DynamicField *fields;
    int nfields;

    /* Pointer to the rule that generated it */
    RuleInfo *generated_rule;

    /* Pointer to the decoder that matched */
    OSDecoderInfo *decoder_info;

    /* Sid node to delete */
    OSListNode *sid_node_to_delete;

    /* Group node to delete */
    OSListNode **group_node_to_delete;

    /* Extract when the event fires a rule */
    size_t size;
    size_t p_name_size;

    /* Other internal variables */
    int matched;

    time_t generate_time;
    struct timespec time;
    int day;
    int year;
    char hour[10];
    char mon[4];

    char *previous;
    wlabel_t *labels;

    u_int16_t decoder_syscheck_id;
    int rootcheck_fts;
    int is_a_copy;
    char **last_events;
    int r_firedtimes;
    int queue_added;

    // Node reference
    EventNode *node;
    // Process thread id
    int tid;

    /* Pointer to the previous rule matched */
    void *prev_rule;

} Eventinfo;

/* Events List structure */
struct _EventNode {
    Eventinfo *event;
    pthread_mutex_t mutex;
    volatile int count;
    EventNode *next;
    EventNode *prev;
};

struct EventList {
    EventNode *first_node;
    EventNode *last_node;
    EventNode *last_added_node;

    int _memoryused;
    int _memorymaxsize;
    int _max_freq;
    pthread_mutex_t event_mutex;
};

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
Eventinfo *Search_LastEvents(Eventinfo *my_lf, EventList *last_events, RuleInfo *currently_rule, regex_matching *rule_match);
Eventinfo *Search_LastSids(Eventinfo *my_lf, EventList *last_events, RuleInfo *currently_rule, regex_matching *rule_match);
Eventinfo *Search_LastGroups(Eventinfo *my_lf, EventList *last_events, RuleInfo *currently_rule, regex_matching *rule_match);

/* Zero the eventinfo structure */
void Zero_Eventinfo(Eventinfo *lf);

/**
 * @brief Free the eventinfo structure
 * @param lf event to remove
 */
void Free_Eventinfo(Eventinfo *lf);

/**
 * @brief Clear the memory if the eventinfo was not added to the stateful memory
 *
 * @param lf Eventinfo to free
 */
void w_free_event_info(Eventinfo *lf);

/* Add and event to the list of previous events */
void OS_AddEvent(Eventinfo *lf, EventList *list);

/* Return the last event from the Event list */
EventNode *OS_GetFirstEvent(EventList *list);

/**
 * @brief Free a events list
 * @param list EventList to remove
 */
void os_remove_eventlist(EventList *list);

/* Create the event list. Maxsize must be specified */
void OS_CreateEventList(int maxsize, EventList *list);

/* Find index of a dynamic field. Returns -1 if not found. */
const char* FindField(const Eventinfo *lf, const char *name);

/* Parse rule comment with dynamic fields */
char* ParseRuleComment(Eventinfo *lf);

/**
 * @brief Function to check for repetitions from same fields
 *
 * @param rule has rule information
 * @param lf has event information
 * @param my_lf has last event information
 * @return true if lf and my_lf are the same
 * @return false if lf and my_lf are different
 */
bool same_loop(RuleInfo *rule, Eventinfo *lf, Eventinfo *my_lf);

/**
 * @brief Function to check for repetitions from different fields
 *
 * @param rule has rule information
 * @param lf has event information
 * @param my_lf has last event information
 * @return true if lf and my_lf are different
 * @return false if lf and my_lf are the same
 */
bool different_loop(RuleInfo *rule, Eventinfo *lf, Eventinfo *my_lf);

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
void *Extra_Data_FP(Eventinfo *lf, char *field, const char *order);
void *Status_FP(Eventinfo *lf, char *field, const char *order);
void *SystemName_FP(Eventinfo *lf, char *field, const char *order);
void *DynamicField_FP(Eventinfo *lf, char *field, const char *order);

/* Copy Eventinfo for writing log */
void w_copy_event_for_log(Eventinfo *lf,Eventinfo *lf_cpy);

/* Add an event to last_events array */
#define add_lastevt(x, y, z) os_realloc(x, sizeof(char *) * (y + 2), x); \
                             os_strdup(z, x[y]); \
                             x[y + 1] = NULL;

#endif /* EVTINFO_H */
