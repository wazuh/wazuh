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
#include "../expression.h"

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

/* Decoder structure */
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

    w_expression_t * regex;
    w_expression_t * prematch;
    w_expression_t * program_name;

    void (*plugindecoder)(void *lf, void *decoder_match);
    void* (**order)(struct _Eventinfo *, char *, const char *);
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

/* Functions to Create the list, add a osdecoder to the
 * list and to get the first osdecoder
 */
void OS_CreateOSDecoderList(void);
int OS_AddOSDecoder(OSDecoderInfo *pi);
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
int ReadDecodeXML(const char *file);

#endif /* DECODER_H */
