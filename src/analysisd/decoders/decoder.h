/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef DECODER_H
#define DECODER_H

#include "shared.h"
#include "os_regex/os_regex.h"

#define AFTER_PARENT    0x001   /* 1   */
#define AFTER_PREMATCH  0x002   /* 2   */
#define AFTER_PREVREGEX 0x004   /* 4   */
#define AFTER_ERROR     0x010

// JSON decoder flags
// null treatment
#define DISCARD     0
#define EMPTY       1
#define SHOW_STRING 2
// array treatment
#define CSV_STRING  4
#define JSON_ARRAY  8

struct _Eventinfo;

/**
 * @brief Decoder structure
 *
 * Allow saving the decoders information
 */
typedef struct {
    u_int8_t  get_next;
    u_int8_t  type;
    u_int8_t  use_own_name;
    u_int8_t  flags;

    u_int16_t id;
    u_int16_t regex_offset;
    u_int16_t prematch_offset;
    u_int16_t plugin_offset;

    int fts;
    int accumulate;
    char *parent;
    char *name;
    char *ftscomment;
    char **fields;
    char *fts_fields;

    OSRegex *regex;
    OSRegex *prematch;
    OSMatch *program_name;

    void (*plugindecoder)(void *lf, void *rule_hash, void *decoder_match);
    void* (**order)(struct _Eventinfo *, char *, const char *);

    bool internal_saving;      ///< Used to free decoderinfo structure in wazuh-logtest
} OSDecoderInfo;

/* List structure */
typedef struct _OSDecoderNode {
    struct _OSDecoderNode *next;
    struct _OSDecoderNode *child;
    OSDecoderInfo *osdecoder;
} OSDecoderNode;

typedef struct dbsync_context_t {
    // Persistent data (per dispatcher)
    int db_sock;
    int ar_sock;
    // Ephimeral data (per message)
    char * agent_id;
    char * component;
    cJSON * data;
} dbsync_context_t;

/**
 * @brief Initialize decoder lists to NULL
 *
 * Only used for analysisd decoder lists (os_analysisd_decoderlist_pn and os_analysisd_decoderlist_nopn)
 */
void OS_CreateOSDecoderList(void);

/**
 * @brief Add decoders to decoder lists
 * @param pi decoder to add in decoder list
 * @param pn_osdecodernode decoder list for events with program name
 * @param npn_osdecodernode decoder list for events without program name
 * @return 1 on success, otherwise 0
 */
int OS_AddOSDecoder(OSDecoderInfo *pi, OSDecoderNode **pn_osdecodernode, OSDecoderNode **npn_osdecodernode);

OSDecoderNode *OS_GetFirstOSDecoder(const char *pname);
int getDecoderfromlist(const char *name);
char *GetGeoInfobyIP(char *ip_addr);
int SetDecodeXML(void);
void HostinfoInit(void);
int fim_init(void);
void RootcheckInit(void);
void SyscollectorInit(void);
void CiscatInit(void);
void WinevtInit(void);
void SecurityConfigurationAssessmentInit(void);
int ReadDecodeXML(const char *file, OSDecoderNode **decoderlist_pn, OSDecoderNode **decoderlist_nopn);

/**
 * @brief Remove decoder information
 * @param pi OSDecoderInfo struct to remove
 */
void FreeDecoderInfo(OSDecoderInfo *pi);

/**
 * @brief Remove decoder list
 * @param decoderlist_pn list of decoders which have program_name
 * @param decoderlist_npn ist of decoders which haven't program_name
 * @param num_decoders number of decoder nodes on memory
 */
void os_remove_decoders_list(OSDecoderNode *decoderlist_pn, OSDecoderNode *decoderlist_npn);

/**
 * @brief Remove a decoder node
 * @param node OSDecoderNode node to remove
 * @param decoders hash to save the reference to decoder information
 */
void os_remove_decodernode(OSDecoderNode *node, OSDecoderInfo **decoders, int *pos, int *max_size);

/**
 * @brief Count the number of decoders in a list
 * @param node the first node of the list
 * @param num_decoders the number of decoders
 */
void os_count_decoders(OSDecoderNode *node, int *num_decoders);

#endif /* DECODER_H */
