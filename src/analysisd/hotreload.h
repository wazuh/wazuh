/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010-2012 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "decoders/decoder.h"
#include "rules.h"
#include "config.h"

/* For hot reload ruleset */
typedef struct _w_hotreload_ruleset_data_t {
    // Ruleset data
    RuleNode * rule_list; ///< Rule list [os_analysisd_rulelist]
    OSDecoderNode *
        decoderlist_forpname; ///< Decoder list to match logs which have a program name [os_analysisd_decoderlist_pn]
    OSDecoderNode * decoderlist_nopname; ///< Decoder list to match logs which haven't a program name
                                         ///< [os_analysisd_decoderlist_nopn]
    OSStore * decoder_store;             ///< Decoder list to save internals decoders [os_analysisd_decoder_store]
    ListNode * cdblistnode;              ///< List of CDB lists [os_analysisd_cdblists]
    ListRule * cdblistrule;              ///< List to attach rules and CDB lists [os_analysisd_cdbrules]
    EventList * eventlist;               ///< Previous events list [os_analysisd_last_events]
    OSHash * rules_hash;                 ///< Hash table of rules [Config.g_rules_hash]
    OSList * fts_list;                   ///< Save FTS previous events [os_analysisd_fts_list]
    OSHash * fts_store;                  ///< Save FTS values processed [os_analysisd_fts_store]
    OSHash * acm_store;                  ///< Hash to save data which have the same id [os_analysisd_acm_store]
    int acm_lookups;     ///< Counter of the number of times purged. Option accumulate [os_analysisd_acm_lookups]
    time_t acm_purge_ts; ///< Counter of the time interval of last purge. Option accumulate [os_analysisd_acm_purge_ts]
    // Config data
    char ** decoders; ///< List of decoders [Config.decoders]
    char ** includes; ///< List of rules [Config.includes]
    char ** lists;    ///< List of lists [Config.lists]

} w_hotreload_ruleset_data_t;

/**
 * @brief Reload the internal decoders
 *
 * Reload the internal decoders, updating decoder store internally
 */
void w_hotreload_reload_internal_decoders();

/**
 * @brief Switch the current ruleset with the new one
 *
 * This function will switch the current ruleset with the new one, updating the global configuration
 * This function is not thread safe
 * @param new_ruleset New ruleset to be set
 * @return w_hotreload_ruleset_data_t* a struct pointing to the old ruleset
 */
w_hotreload_ruleset_data_t * w_hotreload_switch_ruleset(w_hotreload_ruleset_data_t * new_ruleset);

/**
 * @brief Create a new ruleset
 *
 * @param list_msg [output] List of messages to be logged (error, warning and info messages)
 * @return w_hotreload_ruleset_data_t* new ruleset, NULL if error
 */
w_hotreload_ruleset_data_t * w_hotreload_create_ruleset(OSList * list_msg);

/**
 * @brief Clean a ruleset
 *
 * @param ptr_ruleset Pointer to the ruleset to be cleaned
 * @return void
 */
void w_hotreload_clean_ruleset(w_hotreload_ruleset_data_t ** ptr_ruleset);

/**
 * @brief Load the ruleset files from ossec.conf
 *
 * @param ruleset_config [output] Ruleset configuration
 * @param list_msg [output] List of messages to be logged (error, warning and info messages)
 * @return false if the ruleset was loaded successfully, true otherwise
 */
bool w_hotreload_ruleset_load(_Config * ruleset_config, OSList * list_msg);

/**
 * @brief Load the ruleset configuration
 *
 * @param xml XML object
 * @param conf_section_nodes xml nodes from ossec_config
 * @param ruleset_config Ruleset configuration files
 * @param list_msg [output] List of messages to be logged (error, warning and info messages)
 * @return false if the ruleset was loaded successfully, true otherwise
 */
bool w_hotreload_ruleset_load_config(OS_XML * xml, XML_NODE conf_section_nodes, _Config * ruleset_config,
                                     OSList * list_msg);

/**
 * @brief Check if the queue of the pipeline are empty
 *
 * @return true if the queues are empty. False otherwise
 */
bool w_hotreload_queues_are_empty();
