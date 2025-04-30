/* Copyright (C) 2015, Wazuh Inc.
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
#include "../logmsg.h"
#include "expression.h"

#define AFTER_PARENT    0x001   /* 1   */
#define AFTER_PREMATCH  0x002   /* 2   */
#define AFTER_PREVREGEX 0x004   /* 4   */
#define AFTER_ERROR     0x010
#define AFTER_ERR_VAL   (AFTER_ERROR << 1)
#define AFTER_ERR_NAME  (AFTER_ERROR << 2)

// JSON decoder flags
// null treatment
#define JSON_TREAT_NULL_AS_DISCARD     (0x1 << 0)
#define JSON_TREAT_NULL_AS_STRING      (0x1 << 1)
// array treatment
#define JSON_TREAT_ARRAY_AS_CSV_STRING (0x1 << 2)
#define JSON_TREAT_ARRAY_AS_ARRAY      (0x1 << 3)

#define JSON_TREAT_NULL_MASK           (JSON_TREAT_NULL_AS_DISCARD | JSON_TREAT_NULL_AS_STRING)
#define JSON_TREAT_ARRAY_MASK          (JSON_TREAT_ARRAY_AS_CSV_STRING | JSON_TREAT_ARRAY_AS_ARRAY)
// Default values
#define JSON_TREAT_ARRAY_DEFAULT       JSON_TREAT_ARRAY_AS_ARRAY
#define JSON_TREAT_NULL_DEFAULT        JSON_TREAT_NULL_AS_STRING



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

    w_expression_t * regex;
    w_expression_t * prematch;
    w_expression_t * program_name;

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
 * @brief Struct used to have a 1:1 matching between upcoming agent syscollector
 *  data fields and their corresponding table
 */
struct deltas_fields_match {
    char *key;
    char *value;
};

/**
 * @brief Linked list of deltas fields match
 */
struct deltas_fields_match_list {
    struct deltas_fields_match current;
    const struct deltas_fields_match_list *next;
};


/**
 * @brief Generic function to handle value mapping
 *
 */
typedef bool (*mapping_t)(cJSON*,const char*);

/**
 * @brief Struct to map a field name their custom value mapper function
 *
 */
struct delta_values_mapping {
    char *key;
    mapping_t mapping;
};

/**
 * @brief Linked list of deltas values mappers
 *
 */
struct delta_values_mapping_list {
    struct delta_values_mapping current;
    const struct delta_values_mapping_list *next;
};

/**
 * @brief Structure to save decoders which have program_name or parent with program_name
 */
extern OSDecoderNode *os_analysisd_decoderlist_pn;

/**
 * @brief Structure to save decoders which haven't program_name or parent without program_name
 */
extern OSDecoderNode *os_analysisd_decoderlist_nopn;

/**
 * @brief Hash to save data which have the same id
 *
 * Only for Analysisd use
 */
extern OSHash *os_analysisd_acm_store;

/**
 * @brief Decoder list to save internals decoders
 */
extern OSStore *os_analysisd_decoder_store;

/**
 * @brief Decoding a event
 * @param lf struct to save the event decoded
 * @param rules_hash hash of rules
 * @param decoder_match struct to save the regex which match
 * @param node first node of decoders list
 */
void DecodeEvent(struct _Eventinfo *lf, OSHash *rules_hash, regex_matching *decoder_match, OSDecoderNode *node);

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
 * @return status code
 * @retval 1 success
 * @retval 0 failure, the decoder has not been added to the list
 * @retval -1 failure, but the decoder has already been added to the list
 */
int OS_AddOSDecoder(OSDecoderInfo *pi, OSDecoderNode **pn_osdecodernode,
                    OSDecoderNode **npn_osdecodernode, OSList* log_msg);

OSDecoderNode *OS_GetFirstOSDecoder(const char *pname);

/**
 * @brief Get decoder from list
 * @param name decoder name
 * @param decoder_store decoder list
 * @return decoder position on success, otherwise 0
 */
int getDecoderfromlist(const char *name, OSStore **decoder_store);

char *GetGeoInfobyIP(char *ip_addr);

/**
 * @brief Add internal decoders to decoder_list and set ids to xml decoders
 * @param log_msg list to save log messages.
 * @param decoder_list list to save all decoders (internals and xml decoders)
 * @param decoderlist_npn list of decoders which haven't program_name
 * @param decoderlist_pn list of decoders which have program_name
 * @retval 0 in case of error.
 * @retval 1 successful.
 */
int SetDecodeXML(OSList* log_msg, OSStore **decoder_list, OSDecoderNode **decoderlist_npn, OSDecoderNode **decoderlist_pn);

/* Internal decoders init */
void HostinfoInit(void);
int fim_init(void);
void RootcheckInit(void);
void SyscollectorInit(void);
void CiscatInit(void);
void WinevtInit(void);
void SecurityConfigurationAssessmentInit(void);

/* Hot reload internal decoders */
void HostinfoHotReload(void);
void fim_hot_reload(void);
void RootcheckHotReload(void);
void SyscollectorHotReload(void);
void CiscatHotReload(void);
void WinevtHotReload(void);
void SecurityConfigurationAssessmentHotReload(void);

/**
 * @brief Read decoder files and save them in the decoder list
 * @param file name of file which read
 * @param decoderlist_pn list of decoders which have program_name
 * @param decoderlist_nopn list of decoders which haven't program_name
 * @param decoder_store list to save all decoders (internals and xml decoders)
 * @param log_msg list to save log messages
 * @return
 */
int ReadDecodeXML(const char *file, OSDecoderNode **decoderlist_pn,
                  OSDecoderNode **decoderlist_nopn, OSStore **decoder_list,
                  OSList* log_msg);

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
