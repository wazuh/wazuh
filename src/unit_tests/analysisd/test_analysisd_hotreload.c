/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <cmocka.h>

#include "../../analysisd/hotreload.h"
#include "../wrappers/wazuh/os_xml/os_xml_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

// Global variables
extern ListNode * os_analysisd_cdblists;
extern ListRule * os_analysisd_cdbrules;
extern OSList * os_analysisd_fts_list;
extern OSHash * os_analysisd_fts_store;
extern OSHash * os_analysisd_acm_store;
extern int os_analysisd_acm_lookups;
extern time_t os_analysisd_acm_purge_ts;


// Global test variables
bool g_test_load_acm_store = true;

/* Internal decoder reload wrappers */
void __wrap_RootcheckHotReload(void) { function_called(); }

void __wrap_SyscollectorHotReload(void) { function_called(); }

void __wrap_CiscatHotReload(void) { function_called(); }

void __wrap_HostinfoHotReload(void) { function_called(); }

void __wrap_WinevtHotReload(void) { function_called(); }

void __wrap_SecurityConfigurationAssessmentHotReload(void) { function_called(); }

void __wrap_fim_hot_reload(void) { function_called(); }

void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func, const char * file,
                                     char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected_ptr(list);
    check_expected(formatted_msg);
}

int __wrap_Read_Rules(XML_NODE node, void * configp, void * list) {

    int retval = mock_type(int);
    _Config * ruleset = (_Config *) configp;

    if (retval < 0) {
        return retval;
    }

    ruleset->decoders = calloc(2, sizeof(char *));
    os_strdup("test_decoder.xml", ruleset->decoders[0]);

    ruleset->lists = calloc(2, sizeof(char *));
    os_strdup("test_list.xml", ruleset->lists[0]);

    ruleset->includes = calloc(2, sizeof(char *));
    os_strdup("test_rule.xml", ruleset->includes[0]);

    return retval;
}

void __wrap_OS_CreateEventList(int maxsize, EventList *list) {
    function_called();
}

int __wrap_ReadDecodeXML(const char * file, OSDecoderNode ** decoderlist_pn, OSDecoderNode ** decoderlist_nopn,
                         OSStore ** decoder_list, OSList * log_msg) {
    int retval = mock_type(int);

    if (retval > 0) {
        *decoder_list = (OSStore *) 1;
    }
    return retval;
}

int __wrap_SetDecodeXML(OSList * log_msg, OSStore ** decoder_list, OSDecoderNode ** decoderlist_npn,
                        OSDecoderNode ** decoderlist_pn) {
    return mock_type(int);
}

int __wrap_Lists_OP_LoadList(char * files, ListNode ** cdblistnode, OSList * msg) { return mock_type(int); }

void __wrap_Lists_OP_MakeAll(int force, int show_message, ListNode ** lnode) { 
    function_called();
 }

int __wrap_Rules_OP_ReadRules(char * file, RuleNode ** rule_list, ListNode ** cbd, EventList ** evet, OSList * msg) {
    return mock_type(int);
}

void __wrap_OS_ListLoadRules(ListNode ** l_node, ListRule ** lrule) { 
    function_called();
 }

int __wrap__setlevels(RuleNode * node, int nnode) { return mock_type(int); }

int __wrap_AddHash_Rule(RuleNode * node) { return mock_type(int); }

int __wrap_Accumulate_Init(OSHash ** acm_store, int * acm_lookups, time_t * acm_purge_ts) {
    if (g_test_load_acm_store) {
        *acm_store = (OSHash *) 8;
    }
    return mock_type(int);
}

OSStore *__wrap_OSStore_Free(OSStore *list) {
    return mock_type(OSStore *);
}

OSHash *__wrap_OSHash_Create() {
    return mock_type(OSHash *);
}

/* Test for w_hotreload_reload_internal_decoders */
void test_w_hotreload_reload_internal_decoders(void ** state) {
    expect_function_call(__wrap_RootcheckHotReload);
    expect_function_call(__wrap_SyscollectorHotReload);
    expect_function_call(__wrap_CiscatHotReload);
    expect_function_call(__wrap_HostinfoHotReload);
    expect_function_call(__wrap_WinevtHotReload);
    expect_function_call(__wrap_SecurityConfigurationAssessmentHotReload);
    expect_function_call(__wrap_fim_hot_reload);

    w_hotreload_reload_internal_decoders();
}

/* Test for w_hotreload_switch_ruleset */
void test_w_hotreload_switch_ruleset(void ** state) {
    w_hotreload_ruleset_data_t * new_ruleset = NULL;
    w_hotreload_ruleset_data_t * expected_old_ruleset = NULL;
    w_hotreload_ruleset_data_t * old_ruleset = NULL;

    // New ruleset
    {
        os_calloc(1, sizeof(w_hotreload_ruleset_data_t), new_ruleset);
        new_ruleset->rule_list = (RuleNode *) (0x1 << 0);
        new_ruleset->decoderlist_forpname = (OSDecoderNode *) (0x1 << 1);
        new_ruleset->decoderlist_nopname = (OSDecoderNode *) (0x1 << 2);
        new_ruleset->decoder_store = (OSStore *) (0x1 << 3);
        new_ruleset->cdblistnode = (ListNode *) (0x1 << 4);
        new_ruleset->cdblistrule = (ListRule *) (0x1 << 5);
        new_ruleset->eventlist = (EventList *) (0x1 << 6);
        new_ruleset->rules_hash = (OSHash *) (0x1 << 7);
        new_ruleset->fts_list = (OSList *) (0x1 << 8);
        new_ruleset->fts_store = (OSHash *) (0x1 << 9);
        new_ruleset->acm_store = (OSHash *) (0x1 << 10);
        new_ruleset->acm_lookups = (0x1 << 11);
        new_ruleset->acm_purge_ts = (0x1 << 12);
        new_ruleset->decoders = (char **) (0x1 << 13);
        new_ruleset->includes = (char **) (0x1 << 14);
        new_ruleset->lists = (char **) (0x1 << 15);
    }

    // Current ruleset
    {
        os_analysisd_rulelist = (RuleNode *) (0x1 << 0 | 0x1 << 20);
        os_analysisd_decoderlist_pn = (OSDecoderNode *) (0x1 << 1 | 0x1 << 20);
        os_analysisd_decoderlist_nopn = (OSDecoderNode *) (0x1 << 2 | 0x1 << 20);
        os_analysisd_decoder_store = (OSStore *) (0x1 << 3 | 0x1 << 20);
        os_analysisd_cdblists = (ListNode *) (0x1 << 4 | 0x1 << 20);
        os_analysisd_cdbrules = (ListRule *) (0x1 << 5 | 0x1 << 20);
        os_analysisd_last_events = (EventList *) (0x1 << 6 | 0x1 << 20);
        Config.g_rules_hash = (OSHash *) (0x1 << 7 | 0x1 << 20);
        os_analysisd_fts_list = (OSList *) (0x1 << 8 | 0x1 << 20);
        os_analysisd_fts_store = (OSHash *) (0x1 << 9 | 0x1 << 20);
        os_analysisd_acm_store = (OSHash *) (0x1 << 10 | 0x1 << 20);
        os_analysisd_acm_lookups = (0x1 << 11 | 0x1 << 20);
        os_analysisd_acm_purge_ts = (0x1 << 12 | 0x1 << 20);
        Config.decoders = (char **) (0x1 << 13 | 0x1 << 20);
        Config.includes = (char **) (0x1 << 14 | 0x1 << 20);
        Config.lists = (char **) (0x1 << 15 | 0x1 << 20);
    }

    // Expected old ruleset
    {
        os_calloc(1, sizeof(w_hotreload_ruleset_data_t), expected_old_ruleset);
        expected_old_ruleset->rule_list = os_analysisd_rulelist;
        expected_old_ruleset->decoderlist_forpname = os_analysisd_decoderlist_pn;
        expected_old_ruleset->decoderlist_nopname = os_analysisd_decoderlist_nopn;
        expected_old_ruleset->decoder_store = os_analysisd_decoder_store;
        expected_old_ruleset->cdblistnode = os_analysisd_cdblists;
        expected_old_ruleset->cdblistrule = os_analysisd_cdbrules;
        expected_old_ruleset->eventlist = os_analysisd_last_events;
        expected_old_ruleset->rules_hash = Config.g_rules_hash;
        expected_old_ruleset->fts_list = os_analysisd_fts_list;
        expected_old_ruleset->fts_store = os_analysisd_fts_store;
        expected_old_ruleset->acm_store = os_analysisd_acm_store;
        expected_old_ruleset->acm_lookups = os_analysisd_acm_lookups;
        expected_old_ruleset->acm_purge_ts = os_analysisd_acm_purge_ts;
        expected_old_ruleset->decoders = Config.decoders;
        expected_old_ruleset->includes = Config.includes;
        expected_old_ruleset->lists = Config.lists;
    }

    old_ruleset = w_hotreload_switch_ruleset(new_ruleset);

    assert_non_null(old_ruleset);

    assert_ptr_equal(old_ruleset->rule_list, expected_old_ruleset->rule_list);
    assert_ptr_equal(old_ruleset->decoderlist_forpname, expected_old_ruleset->decoderlist_forpname);
    assert_ptr_equal(old_ruleset->decoderlist_nopname, expected_old_ruleset->decoderlist_nopname);
    assert_ptr_equal(old_ruleset->decoder_store, expected_old_ruleset->decoder_store);
    assert_ptr_equal(old_ruleset->cdblistnode, expected_old_ruleset->cdblistnode);
    assert_ptr_equal(old_ruleset->cdblistrule, expected_old_ruleset->cdblistrule);
    assert_ptr_equal(old_ruleset->eventlist, expected_old_ruleset->eventlist);
    assert_ptr_equal(old_ruleset->rules_hash, expected_old_ruleset->rules_hash);
    assert_ptr_equal(old_ruleset->fts_list, expected_old_ruleset->fts_list);
    assert_ptr_equal(old_ruleset->fts_store, expected_old_ruleset->fts_store);
    assert_ptr_equal(old_ruleset->acm_store, expected_old_ruleset->acm_store);
    assert_int_equal(old_ruleset->acm_lookups, expected_old_ruleset->acm_lookups);
    assert_int_equal(old_ruleset->acm_purge_ts, expected_old_ruleset->acm_purge_ts);
    assert_ptr_equal(old_ruleset->decoders, expected_old_ruleset->decoders);
    assert_ptr_equal(old_ruleset->includes, expected_old_ruleset->includes);
    assert_ptr_equal(old_ruleset->lists, expected_old_ruleset->lists);

    assert_ptr_equal(os_analysisd_rulelist, new_ruleset->rule_list);
    assert_ptr_equal(os_analysisd_decoderlist_pn, new_ruleset->decoderlist_forpname);
    assert_ptr_equal(os_analysisd_decoderlist_nopn, new_ruleset->decoderlist_nopname);
    assert_ptr_equal(os_analysisd_decoder_store, new_ruleset->decoder_store);
    assert_ptr_equal(os_analysisd_cdblists, new_ruleset->cdblistnode);
    assert_ptr_equal(os_analysisd_cdbrules, new_ruleset->cdblistrule);
    assert_ptr_equal(os_analysisd_last_events, new_ruleset->eventlist);
    assert_ptr_equal(Config.g_rules_hash, new_ruleset->rules_hash);
    assert_ptr_equal(os_analysisd_fts_list, new_ruleset->fts_list);
    assert_ptr_equal(os_analysisd_fts_store, new_ruleset->fts_store);
    assert_ptr_equal(os_analysisd_acm_store, new_ruleset->acm_store);
    assert_int_equal(os_analysisd_acm_lookups, new_ruleset->acm_lookups);
    assert_int_equal(os_analysisd_acm_purge_ts, new_ruleset->acm_purge_ts);
    assert_ptr_equal(Config.decoders, new_ruleset->decoders);
    assert_ptr_equal(Config.includes, new_ruleset->includes);
    assert_ptr_equal(Config.lists, new_ruleset->lists);

    // Clean up
    os_free(new_ruleset);
    os_free(expected_old_ruleset);
    os_free(old_ruleset);
}

/* Test for w_hotreload_ruleset_load_config */
void test_w_hotreload_ruleset_load_config_empty_element(void ** state) {
    bool retval = true;
    bool EXPECT_RETVAL = false;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    retval = w_hotreload_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);
    assert_int_equal(retval, EXPECT_RETVAL);

    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);
}

void test_w_hotreload_ruleset_load_config_empty_option_node(void ** state) {
    bool retval = true;
    bool EXPECT_RETVAL = false;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    conf_section_nodes[0]->element = (char *) 1;

    will_return(__wrap_OS_GetElementsbyNode, NULL);
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    retval = w_hotreload_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);
    assert_int_equal(retval, EXPECT_RETVAL);

    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);
}

void test_w_hotreload_ruleset_load_config_fail_read_rules(void ** state) {
    bool retval = true;
    bool EXPECT_RETVAL = false;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);

    /* xml ruleset */
    expect_function_call_any(__wrap_OS_ClearNode);
    os_strdup("ruleset", conf_section_nodes[0]->element);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, -1);

    retval = w_hotreload_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);
    assert_int_equal(retval, EXPECT_RETVAL);

    os_free(conf_section_nodes[0]->element);
    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);
}

void test_w_hotreload_ruleset_load_config_ok(void ** state) {

    bool retval = false;
    bool EXPECT_RETVAL = true;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);

    /* xml ruleset */
    expect_function_call_any(__wrap_OS_ClearNode);
    os_strdup("ruleset", conf_section_nodes[0]->element);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    retval = w_hotreload_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
    assert_non_null(ruleset_config.decoders);
    assert_non_null(ruleset_config.decoders[0]);
    assert_non_null(ruleset_config.includes);
    assert_non_null(ruleset_config.includes[0]);
    assert_non_null(ruleset_config.lists);
    assert_non_null(ruleset_config.lists[0]);

    os_free(conf_section_nodes[0]->element);
    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);

    free_strarray(ruleset_config.decoders);
    free_strarray(ruleset_config.includes);
    free_strarray(ruleset_config.lists);
}

/* Test for w_hotreload_ruleset_load */
void test_w_hotreload_ruleset_load_fail_readxml(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    will_return(__wrap_OS_ReadXML, -1);
    will_return(__wrap_OS_ReadXML, "unknown");
    will_return(__wrap_OS_ReadXML, 5);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(1226): Error reading XML file 'etc/ossec.conf': "
                  "unknown (line 5).");

    retval = w_hotreload_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_logtest_ruleset_empty_file(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    will_return(__wrap_OS_ReadXML, 0);
    will_return(__wrap_OS_GetElementsbyNode, NULL);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "There are no configuration blocks inside of 'etc/ossec.conf'");

    retval = w_hotreload_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_hotreload_ruleset_load_null_element(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);

    will_return(__wrap_OS_GetElementsbyNode, node);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    retval = w_hotreload_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_hotreload_ruleset_load_empty_ossec_label(void ** state) {

    bool retval = false;
    bool EXPECT_RETVAL = true;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    will_return(__wrap_OS_GetElementsbyNode, NULL);

    retval = w_hotreload_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_hotreload_ruleset_load_fail_load_ruleset_config(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);

    // Fail w_hotreload_ruleset_load_config
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1202): Configuration error at 'etc/ossec.conf'.");

    retval = w_hotreload_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_hotreload_ruleset_load_ok(void ** state) {

    bool retval = false;
    bool EXPECT_RETVAL = true;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);

    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

    /* xml ruleset */
    os_strdup("ruleset", conf_section_nodes[0]->element);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    retval = w_hotreload_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
    assert_non_null(ruleset_config.decoders);
    assert_non_null(ruleset_config.decoders[0]);
    assert_non_null(ruleset_config.includes);
    assert_non_null(ruleset_config.includes[0]);
    assert_non_null(ruleset_config.lists);
    assert_non_null(ruleset_config.lists[0]);

    free_strarray(ruleset_config.decoders);
    free_strarray(ruleset_config.includes);
    free_strarray(ruleset_config.lists);
}

/* w_hotreload_create_ruleset */
void test_w_hotreload_create_ruleset_fail_ruleset_load(void ** state) {

    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_CreateEventList);

    /* Fail ruleset load */
    {
        will_return(__wrap_OS_ReadXML, -1);
        will_return(__wrap_OS_ReadXML, "unknown");
        will_return(__wrap_OS_ReadXML, 5);
        expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
        expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
        expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                      "(1226): Error reading XML file 'etc/ossec.conf': "
                      "unknown (line 5).");
    }

    w_hotreload_ruleset_data_t * ruleset = NULL;
    ruleset = w_hotreload_create_ruleset(&list_msg);
    assert_null(ruleset);
}

void test_w_hotreload_create_ruleset_fail_ReadDecodeXML(void ** state) {

    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_CreateEventList);

    // Success ruleset load
    {
        expect_function_call_any(__wrap_OS_ClearNode);
        will_return(__wrap_OS_ReadXML, 0);
        XML_NODE node;
        os_calloc(2, sizeof(xml_node *), node);
        /* <ossec_config></> */
        os_calloc(1, sizeof(xml_node), node[0]);
        os_strdup("ossec_config", node[0]->element);
        will_return(__wrap_OS_GetElementsbyNode, node);

        // w_logtest_ruleset_load_config ok
        XML_NODE conf_section_nodes;
        os_calloc(3, sizeof(xml_node *), conf_section_nodes);
        os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
        will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

        /* xml ruleset */
        os_strdup("ruleset", conf_section_nodes[0]->element);

        will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
        will_return(__wrap_Read_Rules, 0);
    }

    // Fail ReadDecodeXML
    {
        will_return(__wrap_ReadDecodeXML,0);
    }

    w_hotreload_ruleset_data_t * ruleset = NULL;
    ruleset = w_hotreload_create_ruleset(&list_msg);
    assert_null(ruleset);
}

void test_w_hotreload_create_ruleset_fail_setDecodeXML(void ** state) {

    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_CreateEventList);

    // Success ruleset load
    {
        expect_function_call_any(__wrap_OS_ClearNode);
        will_return(__wrap_OS_ReadXML, 0);
        XML_NODE node;
        os_calloc(2, sizeof(xml_node *), node);
        /* <ossec_config></> */
        os_calloc(1, sizeof(xml_node), node[0]);
        os_strdup("ossec_config", node[0]->element);
        will_return(__wrap_OS_GetElementsbyNode, node);

        // w_logtest_ruleset_load_config ok
        XML_NODE conf_section_nodes;
        os_calloc(3, sizeof(xml_node *), conf_section_nodes);
        os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
        will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

        /* xml ruleset */
        os_strdup("ruleset", conf_section_nodes[0]->element);

        will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
        will_return(__wrap_Read_Rules, 0);
    }

    // Fail SetDecodeXML
    {
        will_return(__wrap_ReadDecodeXML, 1);
        will_return(__wrap_SetDecodeXML, 0);
    }

    // Free
    {
        will_return(__wrap_OSStore_Free, NULL);
    }

    w_hotreload_ruleset_data_t * ruleset = NULL;
    ruleset = w_hotreload_create_ruleset(&list_msg);
    assert_null(ruleset);
}


void test_w_hotreload_create_ruleset_fail_OP_LoadList(void ** state) {

    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_CreateEventList);

    // Success ruleset load
    {
        expect_function_call_any(__wrap_OS_ClearNode);
        will_return(__wrap_OS_ReadXML, 0);
        XML_NODE node;
        os_calloc(2, sizeof(xml_node *), node);
        /* <ossec_config></> */
        os_calloc(1, sizeof(xml_node), node[0]);
        os_strdup("ossec_config", node[0]->element);
        will_return(__wrap_OS_GetElementsbyNode, node);

        // w_logtest_ruleset_load_config ok
        XML_NODE conf_section_nodes;
        os_calloc(3, sizeof(xml_node *), conf_section_nodes);
        os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
        will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

        /* xml ruleset */
        os_strdup("ruleset", conf_section_nodes[0]->element);

        will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
        will_return(__wrap_Read_Rules, 0);
    }

    // Load decoders OK
    {
        will_return(__wrap_ReadDecodeXML, 1);
        will_return(__wrap_SetDecodeXML, 1);
    }


    // Fail load CDB
    {
        will_return(__wrap_Lists_OP_LoadList, -1);
    }

    // Free expected
    {
        will_return(__wrap_OSStore_Free, NULL);
    }

    w_hotreload_ruleset_data_t * ruleset = NULL;
    ruleset = w_hotreload_create_ruleset(&list_msg);
    assert_null(ruleset);
}

void test_w_hotreload_create_ruleset_fail_Read_OP_Readrules(void ** state) {

    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_CreateEventList);

    // Success ruleset load
    {
        expect_function_call_any(__wrap_OS_ClearNode);
        will_return(__wrap_OS_ReadXML, 0);
        XML_NODE node;
        os_calloc(2, sizeof(xml_node *), node);
        /* <ossec_config></> */
        os_calloc(1, sizeof(xml_node), node[0]);
        os_strdup("ossec_config", node[0]->element);
        will_return(__wrap_OS_GetElementsbyNode, node);

        // w_logtest_ruleset_load_config ok
        XML_NODE conf_section_nodes;
        os_calloc(3, sizeof(xml_node *), conf_section_nodes);
        os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
        will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

        /* xml ruleset */
        os_strdup("ruleset", conf_section_nodes[0]->element);

        will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
        will_return(__wrap_Read_Rules, 0);
    }

    // Load decoders OK
    {
        will_return(__wrap_ReadDecodeXML, 1);
        will_return(__wrap_SetDecodeXML, 1);
    }

    // Load CDB OK
    {
        will_return(__wrap_Lists_OP_LoadList, 0);
        expect_function_call_any(__wrap_Lists_OP_MakeAll);
    }

    // Load rules fail
    {
        will_return(__wrap_Rules_OP_ReadRules, -1);
    }

    // Free expected
    {
        will_return(__wrap_OSStore_Free, NULL);
    }

    w_hotreload_ruleset_data_t * ruleset = NULL;
    ruleset = w_hotreload_create_ruleset(&list_msg);
    assert_null(ruleset);
}

void test_w_hotreload_create_ruleset_fail_rule_hash(void ** state) {

    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_CreateEventList);

    // Success ruleset load
    {
        expect_function_call_any(__wrap_OS_ClearNode);
        will_return(__wrap_OS_ReadXML, 0);
        XML_NODE node;
        os_calloc(2, sizeof(xml_node *), node);
        /* <ossec_config></> */
        os_calloc(1, sizeof(xml_node), node[0]);
        os_strdup("ossec_config", node[0]->element);
        will_return(__wrap_OS_GetElementsbyNode, node);

        // w_logtest_ruleset_load_config ok
        XML_NODE conf_section_nodes;
        os_calloc(3, sizeof(xml_node *), conf_section_nodes);
        os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
        will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

        /* xml ruleset */
        os_strdup("ruleset", conf_section_nodes[0]->element);

        will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
        will_return(__wrap_Read_Rules, 0);
    }

    // Load decoders OK
    {
        will_return(__wrap_ReadDecodeXML, 1);
        will_return(__wrap_SetDecodeXML, 1);
    }

    // Load CDB OK
    {
        will_return(__wrap_Lists_OP_LoadList, 0);
        expect_function_call_any(__wrap_Lists_OP_MakeAll);
    }

    // Load rules fail ash
    {
        will_return(__wrap_Rules_OP_ReadRules, 0);
        expect_function_call(__wrap_OS_ListLoadRules);
        will_return(__wrap__setlevels, 100);

        will_return(__wrap_OSHash_Create, NULL);
    }

    // Free expected
    {
        will_return(__wrap_OSStore_Free, NULL);
    }

    w_hotreload_ruleset_data_t * ruleset = NULL;
    ruleset = w_hotreload_create_ruleset(&list_msg);
    assert_null(ruleset);
}

int main(void) {
    const struct CMUnitTest tests[] = {

        /* Test for w_hotreload_reload_internal_decoders */
        cmocka_unit_test(test_w_hotreload_reload_internal_decoders),

        /* Test for w_hotreload_switch_ruleset */
        cmocka_unit_test(test_w_hotreload_switch_ruleset),

        /* Test for w_hotreload_ruleset_load_config */
        cmocka_unit_test(test_w_hotreload_ruleset_load_config_empty_element),
        cmocka_unit_test(test_w_hotreload_ruleset_load_config_empty_option_node),
        cmocka_unit_test(test_w_hotreload_ruleset_load_config_fail_read_rules),
        cmocka_unit_test(test_w_hotreload_ruleset_load_config_ok),

        /* Test for w_hotreload_ruleset_load */
        cmocka_unit_test(test_w_hotreload_ruleset_load_fail_readxml),
        cmocka_unit_test(test_w_hotreload_ruleset_load_null_element),
        cmocka_unit_test(test_w_hotreload_ruleset_load_empty_ossec_label),
        cmocka_unit_test(test_w_hotreload_ruleset_load_fail_load_ruleset_config),
        cmocka_unit_test(test_w_hotreload_ruleset_load_ok),

        /* Test for w_hotreload_create_ruleset */
        cmocka_unit_test(test_w_hotreload_create_ruleset_fail_ruleset_load),
        cmocka_unit_test(test_w_hotreload_create_ruleset_fail_ReadDecodeXML),
        cmocka_unit_test(test_w_hotreload_create_ruleset_fail_setDecodeXML),
        cmocka_unit_test(test_w_hotreload_create_ruleset_fail_OP_LoadList),
        cmocka_unit_test(test_w_hotreload_create_ruleset_fail_Read_OP_Readrules),
        cmocka_unit_test(test_w_hotreload_create_ruleset_fail_rule_hash),

        /* Test for w_hotreload_clean_ruleset */

        /* w_hotreload_reload */
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
