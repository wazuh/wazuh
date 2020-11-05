/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "rules_op.h"

/* Change path for test rule */
#ifdef TESTRULE
#undef RULEPATH
#define RULEPATH "ruleset/rules/"
#endif

/* Prototypes */
static int _OS_GetRulesAttributes(char **attributes,
                                  char **values,
                                  RuleInfo *ruleinfo_pt) __attribute__((nonnull));
static RuleInfo *_OS_AllocateRule(void);
static void _OS_FreeRule(RuleInfo *ruleinfo);

/**
 * @brief Check if a option has attribute negate
 * @param node xml node which contains the rule
 * @param rule_id rule identifier
 * @return true if it must be negated, otherwise false
 */
bool w_check_attr_negate(xml_node *node, int rule_id);

/**
 * @brief Check if field name is valid
 * @param node xml node which contains the rule
 * @param field field to validate
 * @param rule_id rule identifier
 * @return true on success, otherwise false
 */
bool w_check_attr_field_name(xml_node * node, FieldInfo ** field, int rule_id);

/**
 * @brief Get regex type attribute of a node
 * @param node node to find regex type value
 * @param default_type default type be returned in case of invalid or missing type
 * @param rule_id rule identifier
 * @return regex type
 */
w_exp_type_t w_check_attr_type(xml_node * node, w_exp_type_t default_type, int rule_id);

/* Read the log rules */
int OS_ReadXMLRules(const char *rulefile,
                    void *(*ruleact_function)(RuleInfo *rule_1, void *data_1),
                    void *datadb)
{
    OS_XML xml;
    XML_NODE node = NULL;
    int retval = 0;
    XML_NODE rule = NULL;
    XML_NODE rule_opt = NULL;
    RuleInfo *config_ruleinfo = NULL;

    char *regex = NULL, *match = NULL, *url = NULL,
         *if_matched_regex = NULL, *if_matched_group = NULL,
         *user = NULL, *id = NULL, *srcport = NULL,
         *dstport = NULL, *status = NULL, *hostname = NULL,
         *extra_data = NULL, *program_name = NULL, *location = NULL,
         *dstgeoip = NULL, *srcgeoip = NULL, *system_name = NULL,
         *action = NULL, *protocol = NULL, *data = NULL;

    /** XML variables **/
    /* These are the available options for the rule configuration */

    const char *xml_group = "group";
    const char *xml_rule = "rule";

    const char *xml_regex = "regex";
    const char *xml_match = "match";
    const char *xml_decoded = "decoded_as";
    const char *xml_category = "category";
    const char *xml_cve = "cve";
    const char *xml_info = "info";
    const char *xml_day_time = "time";
    const char *xml_week_day = "weekday";
    const char *xml_comment = "description";
    const char *xml_ignore = "ignore";
    const char *xml_check_if_ignored = "check_if_ignored";

    const char *xml_srcip = "srcip";
    const char *xml_srcport = "srcport";
    const char *xml_dstip = "dstip";
    const char *xml_dstport = "dstport";
    const char *xml_user = "user";
    const char *xml_url = "url";
    const char *xml_id = "id";
    const char *xml_extra_data = "extra_data";
    const char *xml_hostname = "hostname";
    const char *xml_program_name = "program_name";
    const char *xml_status = "status";
    const char *xml_action = "action";
    const char *xml_compiled = "compiled_rule";
    const char *xml_location = "location";
    const char *xml_srcgeoip = "srcgeoip";
    const char *xml_dstgeoip = "dstgeoip";
    const char *xml_system_name = "system_name";
    const char *xml_data = "data";
    const char *xml_protocol = "protocol";

    const char *xml_if_sid = "if_sid";
    const char *xml_if_group = "if_group";
    const char *xml_if_level = "if_level";
    const char *xml_fts = "if_fts";

    const char *xml_if_matched_regex = "if_matched_regex";
    const char *xml_if_matched_group = "if_matched_group";
    const char *xml_if_matched_sid = "if_matched_sid";

    const char *xml_same_source_ip = "same_source_ip";
    const char *xml_same_srcip = "same_srcip";
    const char *xml_same_src_port = "same_src_port";
    const char *xml_same_srcport = "same_srcport";
    const char *xml_same_dst_port = "same_dst_port";
    const char *xml_same_dstport = "same_dstport";
    const char *xml_same_srcuser = "same_srcuser";
    const char *xml_same_user = "same_user";
    const char *xml_same_location = "same_location";
    const char *xml_same_id = "same_id";
    const char *xml_dodiff = "check_diff";
    const char *xml_same_field = "same_field";
    const char *xml_same_dstip = "same_dstip";
    const char *xml_same_agent = "same_agent";
    const char *xml_same_url = "same_url";
    const char *xml_same_srcgeoip = "same_srcgeoip";
    const char *xml_same_protocol = "same_protocol";
    const char *xml_same_action = "same_action";
    const char *xml_same_data = "same_data";
    const char *xml_same_extra_data = "same_extra_data";
    const char *xml_same_status = "same_status";
    const char *xml_same_systemname = "same_system_name";
    const char *xml_same_dstgeoip = "same_dstgeoip";

    const char *xml_different_url = "different_url";
    const char *xml_different_srcip = "different_srcip";
    const char *xml_different_srcgeoip = "different_srcgeoip";
    const char *xml_different_dstip = "different_dstip";
    const char *xml_different_src_port = "different_src_port";
    const char *xml_different_srcport = "different_srcport";
    const char *xml_different_dst_port = "different_dst_port";
    const char *xml_different_dstport = "different_dstport";
    const char *xml_different_location = "different_location";
    const char *xml_different_protocol = "different_protocol";
    const char *xml_different_action = "different_action";
    const char *xml_different_srcuser = "different_srcuser";
    const char *xml_different_user = "different_user";
    const char *xml_different_id = "different_id";
    const char *xml_different_data = "different_data";
    const char *xml_different_extra_data = "different_extra_data";
    const char *xml_different_status = "different_status";
    const char *xml_different_systemname = "different_system_name";
    const char *xml_different_dstgeoip = "different_dstgeoip";
    const char *xml_different_field = "different_field";

    const char *xml_notsame_source_ip = "not_same_source_ip";
    const char *xml_notsame_user = "not_same_user";
    const char *xml_notsame_agent = "not_same_agent";
    const char *xml_notsame_id = "not_same_id";
    const char *xml_notsame_field = "not_same_field";
    const char *xml_global_frequency = "global_frequency";

    const char *xml_options = "options";

    const char *xml_mitre = "mitre";
    const char *xml_mitre_id = "id";

    char *rulepath = NULL;

    size_t i;

    /* If no directory in the rulefile, add the default */
    if ((strchr(rulefile, '/')) == NULL) {
        /* Build the rule file name + path */
        i = strlen(RULEPATH) + strlen(rulefile) + 2;
        rulepath = (char *)calloc(i, sizeof(char));
        if (!rulepath) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
        snprintf(rulepath, i, "%s/%s", RULEPATH, rulefile);
    } else {
        os_strdup(rulefile, rulepath);
        mdebug1("%s is the rulefile", rulefile);
        mdebug1("Not modifing the rule path");
    }

    /* Read the XML */
    if (OS_ReadXML(rulepath, &xml) < 0) {
        merror(XML_ERROR, rulepath, xml.err, xml.err_line);
        retval = -1;
        goto cleanup;
    }
    mdebug1("Read xml for rule '%s'.", rulepath);

    /* Apply any variables found */
    if (OS_ApplyVariables(&xml) != 0) {
        merror(XML_ERROR_VAR, rulepath, xml.err);
        retval = -1;
        goto cleanup;
    }
    mdebug1("XML Variables applied.");

    /* Check if the file is empty */
    if(FileSize(rulepath) == 0){
        retval = 0;
        goto cleanup;
    }

    /* Get the root elements */
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        merror(CONFIG_ERROR, rulepath);
        retval = -1;
        goto cleanup;
    }

    /* Zero the rule memory -- not used anymore */
    free(rulepath);
    rulepath = NULL;

    /* Check if there is any invalid global option */
    i = 0;
    while (node[i]) {
        if (node[i]->element) {
            /* Verify group */
            if (strcasecmp(node[i]->element, xml_group) != 0) {
                merror(RL_INV_ROOT, node[i]->element);
                retval = -1;
                goto cleanup;
            }
            /* Check group attribute -- only name is allowed */
            if ((!node[i]->attributes) || (!node[i]->values) ||
                    (!node[i]->values[0]) || (!node[i]->attributes[0]) ||
                    (strcasecmp(node[i]->attributes[0], "name") != 0) ||
                    (node[i]->attributes[1])) {
                merror(RL_INV_ROOT, node[i]->element);
                retval = -1;
                goto cleanup;
            }
        } else {
            merror(XML_READ_ERROR);
            retval = -1;
            goto cleanup;
        }
        i++;
    }

    /* Get the rules */
    i = 0;
    while (node[i]) {
        int j = 0;

        /* Get all rules for a global group */
        rule = OS_GetElementsbyNode(&xml, node[i]);
        if (rule == NULL) {
            i++;
            continue;
        }

        /* Loop over the rules node */
        while (rule[j]) {
            /* Rules options */
            int k = 0;
            int mitre_size = 0;

            config_ruleinfo = NULL;

            bool negate_regex = false;
            bool negate_match = false;
            bool negate_data = false;
            bool negate_extra_data = false;
            bool negate_hostname = false;
            bool negate_id = false;
            bool negate_location = false;
            bool negate_program_name = false;
            bool negate_protocol = false;
            bool negate_user = false;
            bool negate_url = false;
            bool negate_status = false;
            bool negate_srcport = false;
            bool negate_dstport = false;
            bool negate_system_name = false;
            bool negate_srcgeoip = false;
            bool negate_dstgeoip = false;
            bool negate_action = false;

            w_exp_type_t match_type;
            w_exp_type_t regex_type;
            w_exp_type_t extra_data_type;
            w_exp_type_t hostname_type;
            w_exp_type_t location_type;
            w_exp_type_t program_name_type;
            w_exp_type_t protocol_type;
            w_exp_type_t user_type;
            w_exp_type_t url_type;
            w_exp_type_t srcport_type;
            w_exp_type_t dstport_type;
            w_exp_type_t status_type;
            w_exp_type_t system_name_type;
            w_exp_type_t data_type;
            w_exp_type_t srcgeoip_type;
            w_exp_type_t dstgeoip_type;
            w_exp_type_t id_type;
            w_exp_type_t action_type;

            /* Check if the rule element is correct */
            if (!rule[j]->element) {
                goto cleanup;
            }

            if (strcasecmp(rule[j]->element, xml_rule) != 0) {
                merror(RL_INV_RULE, node[i]->element);
                retval = -1;
                goto cleanup;
            }

            /* Check for the attributes of the rule */
            if ((!rule[j]->attributes) || (!rule[j]->values)) {
                merror(RL_INV_RULE, rulefile);
                retval = -1;
                goto cleanup;
            }

            /* Attribute block */
            config_ruleinfo = _OS_AllocateRule();

            if (_OS_GetRulesAttributes(rule[j]->attributes, rule[j]->values,
                                       config_ruleinfo) < 0) {
                merror(RL_INV_ATTR, rulefile);
                retval = -1;
                goto cleanup;
            }

            /* We must have an id or level */
            if ((config_ruleinfo->sigid == -1) || (config_ruleinfo->level == -1)) {
                merror(RL_INV_ATTR, rulefile);
                retval = -1;
                goto cleanup;
            }

            /* Assign the group name to the rule. The level is correct so
             * the rule is probably going to be fine.
             */
            os_strdup(node[i]->values[0], config_ruleinfo->group);

            /* Get rules options */
            rule_opt =  OS_GetElementsbyNode(&xml, rule[j]);
            if (rule_opt == NULL) {
                merror(RL_NO_OPT, config_ruleinfo->sigid);
                retval = -1;
                goto cleanup;
            }

            /* Read the whole rule block */
            while (rule_opt[k]) {

                if ((!rule_opt[k]->element) || (!rule_opt[k]->content)) {
                    break;

                } else if (strcasecmp(rule_opt[k]->element, xml_regex) == 0) {                
                    regex =  os_LoadString(regex, rule_opt[k]->content);
                    negate_regex = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    regex_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSREGEX, config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_match) == 0) {
                    match =  os_LoadString(match, rule_opt[k]->content);
                    negate_match = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    match_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_decoded) == 0) {

                } else if (strcasecmp(rule_opt[k]->element, xml_info) == 0) {
                    config_ruleinfo->info =
                        os_LoadString(config_ruleinfo->info,
                                      rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_day_time) == 0) {
                    config_ruleinfo->day_time =
                        OS_IsValidTime(rule_opt[k]->content);
                    if (!config_ruleinfo->day_time) {
                        merror(INVALID_CONFIG, rule_opt[k]->element, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_week_day) == 0) {
                    config_ruleinfo->week_day =
                        OS_IsValidDay(rule_opt[k]->content);

                    if (!config_ruleinfo->week_day) {
                        merror(INVALID_CONFIG, rule_opt[k]->element, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }
                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_group) == 0) {
                    config_ruleinfo->group =
                        os_LoadString(config_ruleinfo->group,
                                      rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_cve) == 0) {
                    config_ruleinfo->cve =
                        os_LoadString(config_ruleinfo->cve,
                                      rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_comment) == 0) {
                    char *newline;

                    newline = strchr(rule_opt[k]->content, '\n');
                    if (newline) {
                        *newline = ' ';
                    }
                    config_ruleinfo->comment =
                        os_LoadString(config_ruleinfo->comment,
                                      rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_srcip) == 0) {
                    if (!w_expression_add_osip(&config_ruleinfo->srcip, rule_opt[k]->content)) {
                        merror(INVALID_IP, rule_opt[k]->content);
                        goto cleanup;
                    }

                    if (!config_ruleinfo->srcip) {
                        goto cleanup;
                    }

                    config_ruleinfo->srcip->negate = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_dstip) == 0) {
                    if (!w_expression_add_osip(&config_ruleinfo->dstip, rule_opt[k]->content)) {
                        merror(INVALID_IP, rule_opt[k]->content);
                        goto cleanup;
                    }

                    if (!config_ruleinfo->dstip) {
                        goto cleanup;
                    }

                    config_ruleinfo->dstip->negate = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_user) == 0) {
                    user = os_LoadString(user, rule_opt[k]->content);
                    negate_user = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    user_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element,xml_srcgeoip) == 0) {
                    srcgeoip = os_LoadString(srcgeoip, rule_opt[k]->content);
                    negate_srcgeoip = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    srcgeoip_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element,xml_dstgeoip) == 0) {
                    dstgeoip = os_LoadString(dstgeoip, rule_opt[k]->content);
                    negate_dstgeoip = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    dstgeoip_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_id) == 0) {
                    id = os_LoadString(id, rule_opt[k]->content);
                    negate_id = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    id_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_srcport) == 0) {
                    srcport = os_LoadString(srcport, rule_opt[k]->content);
                    negate_srcport = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    srcport_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_dstport) == 0) {
                    dstport = os_LoadString(dstport, rule_opt[k]->content);
                    negate_dstport = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    dstport_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_status) == 0) {
                    status = os_LoadString(status, rule_opt[k]->content);
                    negate_status = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    status_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_hostname) == 0) {
                    hostname = os_LoadString(hostname, rule_opt[k]->content);
                    negate_hostname = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    hostname_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_data) == 0) {
                    data = os_LoadString(data, rule_opt[k]->content);
                    negate_data = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    data_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_extra_data) == 0) {
                    extra_data = os_LoadString(extra_data, rule_opt[k]->content);
                    negate_extra_data = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    extra_data_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }

                } else if(strcasecmp(rule_opt[k]->element, xml_system_name) == 0){
                    system_name = os_LoadString(system_name, rule_opt[k]->content);
                    negate_system_name = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    system_name_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH,
                                                            config_ruleinfo->sigid);

                }  else if(strcasecmp(rule_opt[k]->element, xml_protocol) == 0){
                    protocol = os_LoadString(protocol, rule_opt[k]->content);
                    negate_protocol = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    protocol_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_program_name) == 0) {
                    program_name = os_LoadString(program_name, rule_opt[k]->content);
                    negate_program_name = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    program_name_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH,
                                                          config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_location) == 0) {
                    location = os_LoadString(location, rule_opt[k]->content);
                    negate_location = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    location_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_action) == 0) {
                    config_ruleinfo->action->string = os_LoadString(config_ruleinfo->action->string,
                                                                    rule_opt[k]->content);
                    negate_action = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    action_type = w_check_attr_type(rule_opt[k], EXP_TYPE_STRING, config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_url) == 0) {
                    url = os_LoadString(url, rule_opt[k]->content);
                    negate_url = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                    url_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                } else if (strcasecmp(rule_opt[k]->element, xml_compiled) == 0) {
                    /* Not using this in here */
                }

                /* We allow these categories so far */
                else if (strcasecmp(rule_opt[k]->element, xml_category) == 0) {
                    if (strcmp(rule_opt[k]->content, "firewall") == 0) {
                        config_ruleinfo->category = FIREWALL;
                    } else if (strcmp(rule_opt[k]->content, "ids") == 0) {
                        config_ruleinfo->category = IDS;
                    } else if (strcmp(rule_opt[k]->content, "syslog") == 0) {
                        config_ruleinfo->category = SYSLOG;
                    } else if (strcmp(rule_opt[k]->content, "web-log") == 0) {
                        config_ruleinfo->category = WEBLOG;
                    } else if (strcmp(rule_opt[k]->content, "squid") == 0) {
                        config_ruleinfo->category = SQUID;
                    } else if (strcmp(rule_opt[k]->content, "windows") == 0) {
                        config_ruleinfo->category = DECODER_WINDOWS;
                    } else if (strcmp(rule_opt[k]->content, "ossec") == 0) {
                        config_ruleinfo->category = OSSEC_RL;
                    } else {
                        merror(INVALID_CAT, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_if_sid) == 0) {
                    config_ruleinfo->if_sid = os_LoadString(config_ruleinfo->if_sid, rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_if_level) == 0) {
                    if (!OS_StrIsNum(rule_opt[k]->content)) {
                        merror(INVALID_CONFIG, xml_if_level, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }

                    config_ruleinfo->if_level = os_LoadString(config_ruleinfo->if_level, rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_if_group) == 0) {
                    config_ruleinfo->if_group =  os_LoadString(config_ruleinfo->if_group, rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_if_matched_regex) == 0) {
                    config_ruleinfo->context = 1;
                    if_matched_regex = os_LoadString(if_matched_regex, rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_if_matched_group) == 0) {
                    config_ruleinfo->context = 1;
                    if_matched_group = os_LoadString(if_matched_group, rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_if_matched_sid) == 0) {
                    config_ruleinfo->context = 1;
                    if (!OS_StrIsNum(rule_opt[k]->content)) {
                        merror(INVALID_CONFIG, rule_opt[k]->element, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }
                    config_ruleinfo->if_matched_sid = atoi(rule_opt[k]->content);

                } else if (strcasecmp(rule_opt[k]->element, xml_same_source_ip) == 0 ||
                           strcasecmp(rule_opt[k]->element, xml_same_srcip) == 0) {
                    config_ruleinfo->same_field |= FIELD_SRCIP;

                } else if (strcasecmp(rule_opt[k]->element, xml_same_dstip) == 0) {
                    config_ruleinfo->same_field |= FIELD_DSTIP;
                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_same_src_port) == 0 ||
                           strcasecmp(rule_opt[k]->element, xml_same_srcport) == 0) {
                    config_ruleinfo->same_field |= FIELD_SRCPORT;
                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }

                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_same_dst_port) == 0 ||
                           strcasecmp(rule_opt[k]->element,
                                      xml_same_dstport) == 0) {
                    config_ruleinfo->same_field |= FIELD_DSTPORT;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_same_protocol) == 0) {
                    config_ruleinfo->same_field |= FIELD_PROTOCOL;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_same_action) == 0) {
                    config_ruleinfo->same_field |= FIELD_ACTION;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element, xml_same_id) == 0) {
                    config_ruleinfo->same_field |= FIELD_ID;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element, xml_same_url) == 0) {
                    config_ruleinfo->same_field |= FIELD_URL;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_same_data) == 0) {
                    config_ruleinfo->same_field |= FIELD_DATA;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_same_extra_data) == 0) {
                    config_ruleinfo->same_field |= FIELD_EXTRADATA;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_same_status) == 0) {
                    config_ruleinfo->same_field |= FIELD_STATUS;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_same_systemname) == 0) {
                    config_ruleinfo->same_field |= FIELD_SYSTEMNAME;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_same_srcgeoip) == 0) {
                    config_ruleinfo->same_field |= FIELD_SRCGEOIP;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_same_dstgeoip) == 0) {
                    config_ruleinfo->same_field |= FIELD_DSTGEOIP;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_same_location) == 0) {
                    config_ruleinfo->same_field |= FIELD_LOCATION;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_same_agent) == 0) {
                    mwarn("Detected a deprecated field option for rule, %s is not longer available.", xml_same_agent);
                } else if (strcasecmp(rule_opt[k]->element,
                                        xml_same_srcuser) == 0) {
                    config_ruleinfo->same_field |= FIELD_SRCUSER;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_same_user) == 0) {
                    config_ruleinfo->same_field |= FIELD_USER;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_dodiff) == 0) {
                    config_ruleinfo->context = 1;
                    config_ruleinfo->context_opts |= FIELD_DODIFF;
                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }
                } else if(strcmp(rule_opt[k]->element,
                                 xml_different_srcip) == 0 ||
                          strcmp(rule_opt[k]->element,
                                 xml_notsame_source_ip) == 0) {
                    config_ruleinfo->different_field |= FIELD_SRCIP;

                    if(!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_different_dstip) == 0) {
                    config_ruleinfo->different_field |= FIELD_DSTIP;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_different_src_port) == 0 ||
                           strcasecmp(rule_opt[k]->element,
                                      xml_different_srcport) == 0) {
                    config_ruleinfo->different_field |= FIELD_SRCPORT;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_different_dst_port) == 0 ||
                           strcasecmp(rule_opt[k]->element,
                                      xml_different_dstport) == 0) {
                    config_ruleinfo->different_field |= FIELD_DSTPORT;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_protocol) == 0) {
                    config_ruleinfo->different_field |= FIELD_PROTOCOL;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_action) == 0) {
                    config_ruleinfo->different_field |= FIELD_ACTION;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element, xml_different_id) == 0 || 
                           strcmp(rule_opt[k]->element, xml_notsame_id) == 0) {
                    config_ruleinfo->different_field |= FIELD_ID;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_url) == 0) {
                    config_ruleinfo->different_field |= FIELD_URL;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_data) == 0) {
                    config_ruleinfo->different_field |= FIELD_DATA;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_extra_data) == 0) {
                    config_ruleinfo->different_field |= FIELD_EXTRADATA;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_status) == 0) {
                    config_ruleinfo->different_field |= FIELD_STATUS;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_systemname) == 0) {
                    config_ruleinfo->different_field |= FIELD_SYSTEMNAME;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_srcgeoip) == 0) {
                    config_ruleinfo->different_field |= FIELD_SRCGEOIP;

                    if(!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcmp(rule_opt[k]->element,
                                  xml_different_dstgeoip) == 0) {
                    config_ruleinfo->different_field |= FIELD_DSTGEOIP;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_fts) == 0) {
                    config_ruleinfo->alert_opts |= DO_FTS;
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_different_srcuser) == 0) {
                    config_ruleinfo->different_field |= FIELD_SRCUSER;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_different_user) == 0 ||
                           strcasecmp(rule_opt[k]->element, 
                                      xml_notsame_user) == 0) {
                    config_ruleinfo->different_field |= FIELD_USER;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_notsame_agent) == 0) {
                    mwarn("Detected a deprecated field option for rule, %s is not longer available.", xml_notsame_agent);
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_different_location) == 0) {
                    config_ruleinfo->different_field |= FIELD_LOCATION;

                    if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                    } 
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_global_frequency) == 0) {
                    config_ruleinfo->context_opts |= FIELD_GFREQUENCY;
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_same_field) == 0) {

                    if (config_ruleinfo->same_field & FIELD_DYNAMICS) {

                        int size;
                        for (size = 0; config_ruleinfo->same_fields[size] != NULL; size++);

                        os_realloc(config_ruleinfo->same_fields, (size + 2) * sizeof(char *), config_ruleinfo->same_fields);
                        os_strdup(rule_opt[k]->content, config_ruleinfo->same_fields[size]);
                        config_ruleinfo->same_fields[size + 1] = NULL;

                    } else {

                        config_ruleinfo->same_field |= FIELD_DYNAMICS;
                        os_calloc(2, sizeof(char *), config_ruleinfo->same_fields);
                        os_strdup(rule_opt[k]->content, config_ruleinfo->same_fields[0]);
                        config_ruleinfo->same_fields[1] = NULL;

                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_notsame_field) == 0 ||
                           strcasecmp(rule_opt[k]->element, xml_different_field) == 0) {

                    if (config_ruleinfo->different_field & FIELD_DYNAMICS) {
                        int size;
                        for (size = 0; config_ruleinfo->not_same_fields[size] != NULL; size++);

                        os_realloc(config_ruleinfo->not_same_fields, (size + 2) * sizeof(char *), config_ruleinfo->not_same_fields);
                        os_strdup(rule_opt[k]->content, config_ruleinfo->not_same_fields[size]);
                        config_ruleinfo->not_same_fields[size + 1] = NULL;

                    } else {
                        config_ruleinfo->different_field |= FIELD_DYNAMICS;
                        os_calloc(2, sizeof(char *), config_ruleinfo->not_same_fields);
                        os_strdup(rule_opt[k]->content, config_ruleinfo->not_same_fields[0]);
                        config_ruleinfo->not_same_fields[1] = NULL;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_options) == 0) {
                    if (strcmp("alert_by_email", rule_opt[k]->content) == 0) {
                        if (!(config_ruleinfo->alert_opts & DO_MAILALERT)) {
                            config_ruleinfo->alert_opts |= DO_MAILALERT;
                        }
                    } else if (strcmp("no_email_alert", rule_opt[k]->content) == 0) {
                        if (config_ruleinfo->alert_opts & DO_MAILALERT) {
                            config_ruleinfo->alert_opts &= 0xfff - DO_MAILALERT;
                        }
                    } else if (strcmp("log_alert", rule_opt[k]->content) == 0) {
                        if (!(config_ruleinfo->alert_opts & DO_LOGALERT)) {
                            config_ruleinfo->alert_opts |= DO_LOGALERT;
                        }
                    } else if (strcmp("no_log", rule_opt[k]->content) == 0) {
                        if (config_ruleinfo->alert_opts & DO_LOGALERT) {
                            config_ruleinfo->alert_opts &= 0xfff - DO_LOGALERT;
                        }
                    } else if (strcmp("no_ar", rule_opt[k]->content) == 0) {
                        if (!(config_ruleinfo->alert_opts & NO_AR)) {
                            config_ruleinfo->alert_opts |= NO_AR;
                        }
                    } else if (strcmp("no_full_log", rule_opt[k]->content) == 0) {
                        config_ruleinfo->alert_opts |= NO_FULL_LOG;
                    } else if (strcmp("no_counter", rule_opt[k]->content) == 0) {
                        config_ruleinfo->alert_opts |= NO_COUNTER;
                    } else {
                        merror(XML_VALUEERR, xml_options, rule_opt[k]->content);

                        merror(INVALID_ELEMENT, rule_opt[k]->element, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_ignore) == 0) {
                    if (strstr(rule_opt[k]->content, "user") != NULL) {
                        config_ruleinfo->ignore |= FTS_USER;
                    }
                    if (strstr(rule_opt[k]->content, "srcip") != NULL) {
                        config_ruleinfo->ignore |= FTS_SRCIP;
                    }
                    if (strstr(rule_opt[k]->content, "dstip") != NULL) {
                        config_ruleinfo->ignore |= FTS_DSTIP;
                    }
                    if (strstr(rule_opt[k]->content, "id") != NULL) {
                        config_ruleinfo->ignore |= FTS_ID;
                    }
                    if (strstr(rule_opt[k]->content, "location") != NULL) {
                        config_ruleinfo->ignore |= FTS_LOCATION;
                    }
                    if (strstr(rule_opt[k]->content, "data") != NULL) {
                        config_ruleinfo->ignore |= FTS_DATA;
                    }
                    if (strstr(rule_opt[k]->content, "name") != NULL) {
                        config_ruleinfo->ignore |= FTS_NAME;

                    }
                    if (!config_ruleinfo->ignore) {
                        merror(INVALID_ELEMENT, rule_opt[k]->element, rule_opt[k]->content);

                        retval = -1;
                        goto cleanup;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_check_if_ignored) == 0) {
                    if (strstr(rule_opt[k]->content, "user") != NULL) {
                        config_ruleinfo->ckignore |= FTS_USER;
                    }
                    if (strstr(rule_opt[k]->content, "srcip") != NULL) {
                        config_ruleinfo->ckignore |= FTS_SRCIP;
                    }
                    if (strstr(rule_opt[k]->content, "dstip") != NULL) {
                        config_ruleinfo->ckignore |= FTS_DSTIP;
                    }
                    if (strstr(rule_opt[k]->content, "id") != NULL) {
                        config_ruleinfo->ckignore |= FTS_ID;
                    }
                    if (strstr(rule_opt[k]->content, "location") != NULL) {
                        config_ruleinfo->ckignore |= FTS_LOCATION;
                    }
                    if (strstr(rule_opt[k]->content, "data") != NULL) {
                        config_ruleinfo->ckignore |= FTS_DATA;
                    }
                    if (strstr(rule_opt[k]->content, "name") != NULL) {
                        config_ruleinfo->ckignore |= FTS_NAME;
                    }
                    if (!config_ruleinfo->ckignore) {
                        merror(INVALID_ELEMENT, rule_opt[k]->element, rule_opt[k]->content);

                        retval = -1;
                        goto cleanup;
                    }

                } else if (strcasecmp(rule_opt[k]->element, xml_mitre) == 0) {
                    int ind;
                    int l;
                    XML_NODE mitre_opt = NULL;
                    mitre_opt = OS_GetElementsbyNode(&xml, rule_opt[k]);

                    if (mitre_opt == NULL) {
                        mwarn("Empty Mitre information for rule '%d'",
                            config_ruleinfo->sigid);
                        k++;
                        continue;
                    }

                    for (ind = 0; mitre_opt[ind] != NULL; ind++) {
                        if ((!mitre_opt[ind]->element) || (!mitre_opt[ind]->content)) {
                            break;
                        } else if (strcasecmp(mitre_opt[ind]->element, xml_mitre_id) == 0) {
                            if (strlen(mitre_opt[ind]->content) == 0) {
                                mwarn("No Mitre Technique ID found for rule '%d'",
                                    config_ruleinfo->sigid);
                            } else {
                                int inarray = 0;
                                for (l = 0; l < mitre_size; l++) {
                                    if (strcmp(config_ruleinfo->mitre_id[l],mitre_opt[ind]->content) == 0) {
                                        inarray = 1;
                                    }
                                }
                                if (!inarray) {
                                    os_realloc(config_ruleinfo->mitre_id, (mitre_size + 2) * sizeof(char *),
                                               config_ruleinfo->mitre_id);
                                    os_strdup(mitre_opt[ind]->content, config_ruleinfo->mitre_id[mitre_size]);
                                    config_ruleinfo->mitre_id[mitre_size + 1] = NULL;
                                    mitre_size++;
                                }
                            }
                        } else {
                            merror("Invalid option '%s' for "
                            "rule '%d'", mitre_opt[ind]->element,
                            config_ruleinfo->sigid);

                            for (l = 0; config_ruleinfo->mitre_id[l] != NULL; l++) {
                                os_free(config_ruleinfo->mitre_id[l]);
                            }
                            os_free(config_ruleinfo->mitre_id);
                            OS_ClearNode(mitre_opt);
                            goto cleanup;
                        }
                    }
                    OS_ClearNode(mitre_opt);
                }
                /* XXX As new features are added into ../analysisd/rules.c
                 * This code needs to be updated to match, but is out of date
                 * it's become a nightmare to correct with out just make the
                 * problem for someone later.
                 *
                 * This hack will allow any crap xml to pass without an
                 * error.  The correct fix is to refactor the code so that
                 * ../analysisd/rules* and this code are not duplicates
                 *
                else
                {
                    merror(XML_INVELEM, rule_opt[k]->element);
                    OS_ClearXML(&xml);
                    return(-1);
                }
                */

                k++;
            }

            /* Check for a valid use of frequency */
            if ((config_ruleinfo->context_opts || config_ruleinfo->same_field || 
                 config_ruleinfo->different_field || config_ruleinfo->frequency) &&
                 !config_ruleinfo->context) {
                merror("Invalid use of frequency/context options. Missing if_matched on rule '%d'.", config_ruleinfo->sigid);
                retval = -1;
                goto cleanup;
            }

            /* If if_matched_group we must have a if_sid or if_group */
            if (if_matched_group) {
                if (!config_ruleinfo->if_sid && !config_ruleinfo->if_group) {
                    os_strdup(if_matched_group, config_ruleinfo->if_group);
                }
            }

            /* If_matched_sid, we need to get the if_sid */
            if (config_ruleinfo->if_matched_sid &&
                    !config_ruleinfo->if_sid &&
                    !config_ruleinfo->if_group) {
                os_calloc(16, sizeof(char), config_ruleinfo->if_sid);
                snprintf(config_ruleinfo->if_sid, 15, "%d",
                         config_ruleinfo->if_matched_sid);
            }

            /* Check the regexes */
            if (regex) {
                w_calloc_expression_t(&config_ruleinfo->regex, regex_type);
                config_ruleinfo->regex->negate = negate_regex;

                if (!w_expression_compile(config_ruleinfo->regex, regex, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_regex, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(regex);
            }

            /* Add in match */
            if (match) {
                w_calloc_expression_t(&config_ruleinfo->match, match_type);
                config_ruleinfo->match->negate = negate_match;

                if (!w_expression_compile(config_ruleinfo->match, match, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_match, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(match);
            }

            /* Add in id */
            if (id) {
                w_calloc_expression_t(&config_ruleinfo->id, id_type);
                config_ruleinfo->id->negate = negate_id;

                if (!w_expression_compile(config_ruleinfo->id, id, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_id, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(id);
            }

            /* Add srcport */
            if (srcport) {
                w_calloc_expression_t(&config_ruleinfo->srcport, srcport_type);
                config_ruleinfo->srcport->negate = negate_srcport;

                if (!w_expression_compile(config_ruleinfo->srcport, srcport, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_srcport, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(srcport);
            }

            /* Add dstport */
            if (dstport) {
                w_calloc_expression_t(&config_ruleinfo->dstport, dstport_type);
                config_ruleinfo->dstport->negate = negate_dstport;

                if (!w_expression_compile(config_ruleinfo->dstport, dstport, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_dstport, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(dstport);

            }

            /* Add in status */
            if (status) {
                w_calloc_expression_t(&config_ruleinfo->status, status_type);
                config_ruleinfo->status->negate = negate_status;

                if (!w_expression_compile(config_ruleinfo->status, status, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_status, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(status);
            }

            /* Add in hostname */
            if (hostname) {
                w_calloc_expression_t(&config_ruleinfo->hostname, hostname_type);
                config_ruleinfo->hostname->negate = negate_hostname;

                if (!w_expression_compile(config_ruleinfo->hostname, hostname, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_hostname, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(hostname);
            }

            /* Add data */
            if (data) {
                w_calloc_expression_t(&config_ruleinfo->data, data_type);
                config_ruleinfo->data->negate = negate_data;

                if (!w_expression_compile(config_ruleinfo->data, data, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_data, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(data);
            }

            /* Add extra data */
            if (extra_data) {
                w_calloc_expression_t(&config_ruleinfo->extra_data, extra_data_type);
                config_ruleinfo->extra_data->negate = negate_extra_data;

                if (!w_expression_compile(config_ruleinfo->extra_data, extra_data, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_extra_data, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(extra_data);
            }

            /* Add in program name */
            if (program_name) {
                w_calloc_expression_t(&config_ruleinfo->program_name, program_name_type);
                config_ruleinfo->program_name->negate = negate_program_name;

                if (!w_expression_compile(config_ruleinfo->program_name, program_name, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_program_name, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(program_name);
            }

            /* Add in user */
            if (user) {
                w_calloc_expression_t(&config_ruleinfo->user, user_type);
                config_ruleinfo->user->negate = negate_user;

                if (!w_expression_compile(config_ruleinfo->user, user, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_user, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(user);
            }

            /* Adding in srcgeoip */
            if(srcgeoip) {
                w_calloc_expression_t(&config_ruleinfo->srcgeoip, srcgeoip_type);
                config_ruleinfo->srcgeoip->negate = negate_srcgeoip;

                if (!w_expression_compile(config_ruleinfo->srcgeoip, srcgeoip, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_srcgeoip, config_ruleinfo->sigid);
                    return(-1);
                }

                os_free(srcgeoip);
            }

            /* Adding in dstgeoip */
            if(dstgeoip) {
                w_calloc_expression_t(&config_ruleinfo->dstgeoip, dstgeoip_type);
                config_ruleinfo->dstgeoip->negate = negate_dstgeoip;

                if (!w_expression_compile(config_ruleinfo->dstgeoip, dstgeoip, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_dstgeoip, config_ruleinfo->sigid);
                    return(-1);
                }

                free(dstgeoip);
                dstgeoip = NULL;
            }

            /* Add in URL */
            if (url) {
                w_calloc_expression_t(&config_ruleinfo->url, url_type);
                config_ruleinfo->url->negate = negate_url;

                if (!w_expression_compile(config_ruleinfo->url, url, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_url, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(url);
            }

            /* Add location */
            if (location) {
                w_calloc_expression_t(&config_ruleinfo->location, location_type);
                config_ruleinfo->location->negate = negate_location;

                if (!w_expression_compile(config_ruleinfo->location, location, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_location, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(location);
            }
            
            /* Add location */
            if (action) {
                w_calloc_expression_t(&config_ruleinfo->action, action_type);
                config_ruleinfo->action->negate = negate_action;

                if (!w_expression_compile(config_ruleinfo->action, action, 0)) {
                    merror(RL_REGEX_SYNTAX, xml_action, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(action);
            }

            /* Add matched_group */
            if (if_matched_group) {
                os_calloc(1, sizeof(OSMatch),
                            config_ruleinfo->if_matched_group);

                if (!OSMatch_Compile(if_matched_group,
                                        config_ruleinfo->if_matched_group,
                                        0)) {
                    merror(REGEX_COMPILE, if_matched_group,
                            config_ruleinfo->if_matched_group->error);
                    goto cleanup;
                }
                free(if_matched_group);
                if_matched_group = NULL;
            }

            /* Add matched_regex */
            if (if_matched_regex) {
                os_calloc(1, sizeof(OSRegex),
                            config_ruleinfo->if_matched_regex);
                if (!OSRegex_Compile(if_matched_regex,
                                        config_ruleinfo->if_matched_regex, 0)) {
                    merror(REGEX_COMPILE, if_matched_regex,
                            config_ruleinfo->if_matched_regex->error);
                    goto cleanup;
                }
                free(if_matched_regex);
                if_matched_regex = NULL;
            }

            /* Add protocol */
            if(protocol){
                w_calloc_expression_t(&config_ruleinfo->protocol, protocol_type);
                config_ruleinfo->protocol->negate = negate_protocol;

                if (!w_expression_compile(config_ruleinfo->protocol, protocol, 0)){
                    merror(RL_REGEX_SYNTAX, protocol, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(protocol);
            }

            /* Add system_name */
            if(system_name){
                w_calloc_expression_t(&config_ruleinfo->system_name, system_name_type);
                config_ruleinfo->system_name->negate = negate_system_name;

                if (!w_expression_compile(config_ruleinfo->system_name, system_name, 0)){
                    merror(RL_REGEX_SYNTAX, xml_system_name, config_ruleinfo->sigid);
                    goto cleanup;
                }

                os_free(system_name);
            }

            /* Add matched_group */
            if (if_matched_group) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->if_matched_group);

                if (!OSMatch_Compile(if_matched_group,
                                     config_ruleinfo->if_matched_group, 0)) {
                    merror(REGEX_COMPILE, if_matched_group, config_ruleinfo->if_matched_group->error);
                    retval = -1;
                    goto cleanup;
                }
                free(if_matched_group);
                if_matched_group = NULL;
            }

            /* Add matched_regex */
            if (if_matched_regex) {
                os_calloc(1, sizeof(OSRegex),
                          config_ruleinfo->if_matched_regex);
                if (!OSRegex_Compile(if_matched_regex,
                                     config_ruleinfo->if_matched_regex, 0)) {
                    merror(REGEX_COMPILE, if_matched_regex, config_ruleinfo->if_matched_regex->error);
                    retval = -1;
                    goto cleanup;
                }
                free(if_matched_regex);
                if_matched_regex = NULL;
            }

            /* Call the function provided */
            ruleact_function(config_ruleinfo, datadb);

            OS_ClearNode(rule_opt);
            rule_opt = NULL;

            j++; /* Next rule */

        } /* while(rule[j]) */
        OS_ClearNode(rule);
        rule = NULL;
        i++;

    } /* while (node[i]) */

cleanup:

    free(program_name);
    free(url);
    free(extra_data);
    free(if_matched_regex);
    free(if_matched_group);
    free(id);
    free(hostname);
    free(srcport);
    free(dstport);
    free(status);
    free(regex);
    free(match);
    free(rulepath);
    free(user);
    free(location);

    OS_ClearNode(rule_opt);
    OS_ClearNode(rule);

    /* Clean global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    if (retval != 0) {
        _OS_FreeRule(config_ruleinfo);
    }

    return retval;
}

/* Allocate memory for a rule */
static RuleInfo *_OS_AllocateRule()
{
    RuleInfo *ruleinfo_pt = NULL;

    /* Allocate memory for structure */
    ruleinfo_pt = (RuleInfo *)calloc(1, sizeof(RuleInfo));
    if (ruleinfo_pt == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Default values */
    ruleinfo_pt->level = -1;

    /* Default category is syslog */
    ruleinfo_pt->category = SYSLOG;

    ruleinfo_pt->ar = NULL;

    ruleinfo_pt->context = 0;

    /* Default sigid of -1 */
    ruleinfo_pt->sigid = -1;
    ruleinfo_pt->firedtimes = 0;
    ruleinfo_pt->maxsize = 0;
    ruleinfo_pt->frequency = 0;
    ruleinfo_pt->ignore_time = 0;
    ruleinfo_pt->timeframe = 0;
    ruleinfo_pt->time_ignored = 0;

    ruleinfo_pt->same_field = 0;
    ruleinfo_pt->different_field = 0;
    ruleinfo_pt->context_opts = 0;
    ruleinfo_pt->alert_opts = 0;
    ruleinfo_pt->ignore = 0;
    ruleinfo_pt->ckignore = 0;

    ruleinfo_pt->day_time = NULL;
    ruleinfo_pt->week_day = NULL;

    ruleinfo_pt->group = NULL;
    ruleinfo_pt->regex = NULL;
    ruleinfo_pt->match = NULL;
    ruleinfo_pt->decoded_as = 0;

    ruleinfo_pt->comment = NULL;
    ruleinfo_pt->info = NULL;
    ruleinfo_pt->cve = NULL;

    ruleinfo_pt->if_sid = NULL;
    ruleinfo_pt->if_group = NULL;
    ruleinfo_pt->if_level = NULL;

    ruleinfo_pt->if_matched_regex = NULL;
    ruleinfo_pt->if_matched_group = NULL;
    ruleinfo_pt->if_matched_sid = 0;

    ruleinfo_pt->user = NULL;
    ruleinfo_pt->srcip = NULL;
    ruleinfo_pt->srcport = NULL;
    ruleinfo_pt->dstip = NULL;
    ruleinfo_pt->dstport = NULL;
    ruleinfo_pt->url = NULL;
    ruleinfo_pt->id = NULL;
    ruleinfo_pt->status = NULL;
    ruleinfo_pt->hostname = NULL;
    ruleinfo_pt->program_name = NULL;
    ruleinfo_pt->action = NULL;
    ruleinfo_pt->location = NULL;

    ruleinfo_pt->same_fields = NULL;
    ruleinfo_pt->not_same_fields = NULL;

    /* Zero the list of previous matches */
    ruleinfo_pt->sid_prev_matched = NULL;
    ruleinfo_pt->group_prev_matched = NULL;

    ruleinfo_pt->sid_search = NULL;
    ruleinfo_pt->group_search = NULL;

    ruleinfo_pt->event_search = NULL;

    w_mutex_init(&ruleinfo_pt->mutex, NULL);

    return (ruleinfo_pt);
}

/* Reads the rules attributes and assign them */
static int _OS_GetRulesAttributes(char **attributes, char **values,
                                  RuleInfo *ruleinfo_pt)
{
    int k = 0;

    const char *xml_id = "id";
    const char *xml_level = "level";
    const char *xml_maxsize = "maxsize";
    const char *xml_timeframe = "timeframe";
    const char *xml_frequency = "frequency";
    const char *xml_accuracy = "accuracy";
    const char *xml_noalert = "noalert";
    const char *xml_ignore_time = "ignore";
    const char *xml_overwrite = "overwrite";

    /* Get attributes */
    while (attributes[k]) {
        if (!values[k]) {
            merror(RL_EMPTY_ATTR, attributes[k]);
            return (-1);
        }
        /* Get rule Id */
        else if (strcasecmp(attributes[k], xml_id) == 0) {
            if (OS_StrIsNum(values[k]) && (strlen(values[k]) <= 6 )) {
                ruleinfo_pt->sigid = atoi(values[k]);
            } else {
                merror(XML_VALUEERR, attributes[k], values[k]);
                return (-1);
            }
        }
        /* Get level */
        else if (strcasecmp(attributes[k], xml_level) == 0) {
            if (OS_StrIsNum(values[k]) && (strlen(values[k]) <= 3)) {
                ruleinfo_pt->level = atoi(values[k]);
            } else {
                merror(XML_VALUEERR, attributes[k], values[k]);
                return (-1);
            }
        }
        /* Get maxsize */
        else if (strcasecmp(attributes[k], xml_maxsize) == 0) {
            if (OS_StrIsNum(values[k]) && (strlen(values[k]) <= 4)) {
                ruleinfo_pt->maxsize = atoi(values[k]);

                /* Add EXTRAINFO options */
                if (ruleinfo_pt->maxsize > 0 &&
                        !(ruleinfo_pt->alert_opts & DO_EXTRAINFO)) {
                    ruleinfo_pt->alert_opts |= DO_EXTRAINFO;
                }
            } else {
                merror(XML_VALUEERR, attributes[k], values[k]);
                return (-1);
            }
        }
        /* Get timeframe */
        else if (strcasecmp(attributes[k], xml_timeframe) == 0) {
            if (OS_StrIsNum(values[k]) && (strlen(values[k]) <= 5)) {
                ruleinfo_pt->timeframe = atoi(values[k]);
            } else {
                merror(XML_VALUEERR, attributes[k], values[k]);
                return (-1);
            }
        }
        /* Get frequency */
        else if (strcasecmp(attributes[k], xml_frequency) == 0) {
            if (OS_StrIsNum(values[k]) && (strlen(values[k]) <= 4)) {
                ruleinfo_pt->frequency = atoi(values[k]);
            } else {
                merror(XML_VALUEERR, attributes[k], values[k]);
                return (-1);
            }
        }
        /* Rule accuracy */
        else if (strcasecmp(attributes[k], xml_accuracy) == 0) {
            merror("Use of 'accuracy' isn't supported. Ignoring.");
        }
        /* Rule ignore_time */
        else if (strcasecmp(attributes[k], xml_ignore_time) == 0) {
            if (OS_StrIsNum(values[k]) && (strlen(values[k]) <= 4)) {
                ruleinfo_pt->ignore_time = atoi(values[k]);
            } else {
                merror(XML_VALUEERR, attributes[k], values[k]);
                return (-1);
            }
        }
        /* Rule noalert */
        else if (strcasecmp(attributes[k], xml_noalert) == 0) {
            ruleinfo_pt->alert_opts |= NO_ALERT;
        } else if (strcasecmp(attributes[k], xml_overwrite) == 0) {
            if (strcmp(values[k], "yes") == 0) {
                ruleinfo_pt->alert_opts |= DO_OVERWRITE;
            } else if (strcmp(values[k], "no") == 0) {
            } else {
                merror(XML_VALUEERR, attributes[k], values[k]);
                return (-1);
            }
        } else {
            merror(XML_INVELEM, attributes[k]);
            return (-1);
        }
        k++;
    }
    return (0);
}

void _OS_FreeRule(RuleInfo *ruleinfo) {
    int i;

    if (!ruleinfo)
        return;

    os_free(ruleinfo->group);
    w_free_expression_t(&ruleinfo->match);
    w_free_expression_t(&ruleinfo->regex);
    os_free(ruleinfo->day_time);
    os_free(ruleinfo->week_day);
    w_free_expression_t(&ruleinfo->srcip);
    w_free_expression_t(&ruleinfo->dstip);
    w_free_expression_t(&ruleinfo->srcport);
    w_free_expression_t(&ruleinfo->dstport);
    w_free_expression_t(&ruleinfo->user);
    w_free_expression_t(&ruleinfo->url);
    w_free_expression_t(&ruleinfo->id);
    w_free_expression_t(&ruleinfo->status);
    w_free_expression_t(&ruleinfo->hostname);
    w_free_expression_t(&ruleinfo->program_name);
    w_free_expression_t(&ruleinfo->location);
    w_free_expression_t(&ruleinfo->extra_data);
    w_free_expression_t(&ruleinfo->action);
    os_free(ruleinfo->comment);
    os_free(ruleinfo->info);
    os_free(ruleinfo->cve);
    os_free(ruleinfo->if_sid);
    os_free(ruleinfo->if_level);
    os_free(ruleinfo->if_group);

    if (ruleinfo->same_fields) {
        for (i = 0; ruleinfo->same_fields[i] != NULL; i++) {
            os_free(ruleinfo->same_fields[i]);
        }
        os_free(ruleinfo->same_fields);
    }

    if (ruleinfo->not_same_fields) {
        for (i = 0; ruleinfo->not_same_fields[i] != NULL; i++) {
            os_free(ruleinfo->not_same_fields[i]);
        }
        os_free(ruleinfo->not_same_fields);
    }

    os_free(ruleinfo);
}

bool w_check_attr_negate(xml_node *node, int rule_id) {

    if (!node->attributes) {
        return false;
    }

    const char * xml_negate = "negate";
    const char * negate_value = w_get_attr_val_by_name(node, xml_negate);

    if (!negate_value) {
        return false;
    }

    if (strcasecmp(negate_value, "yes") == 0) {
        return true;
    } else if (strcasecmp(negate_value, "no") == 0) {
        return false;
    } else {
        mwarn(ANALYSISD_INV_VALUE_RULE, negate_value, xml_negate, rule_id);
    }

    return false;
}

bool w_check_attr_field_name(xml_node * node, FieldInfo ** field, int rule_id) {

    if (!node->attributes) {
        return false;
    }

    const char * xml_name = "name";
    const char * name_value = w_get_attr_val_by_name(node, xml_name);

    if (!name_value) {
        merror("Failure to read rule %d. No such attribute '%s' for field.", rule_id, xml_name);
        return false;
    }

    char *static_fields[18] = {"srcip", "dstip", "srcgeoip", "dstgeoip", "srcport", "dstport",
                               "user", "srcuser", "dstuser", "url", "id", "data", "extra_data",
                               "status", "protocol", "system_name", "action", NULL};

    // Avoid static fields
    for (int j = 0; static_fields[j]; j++) {
        if (strcasecmp(name_value, static_fields[j]) == 0) {
            merror("Failure to read rule %d. Field '%s' is static.", rule_id, name_value);
            return false;
        }
    }

    // Save in struct and return true if it's valid value
    os_calloc(1, sizeof(FieldInfo), *field);
    (*field)->name = os_LoadString((*field)->name, name_value);

    return true;
}

w_exp_type_t w_check_attr_type(xml_node * node, w_exp_type_t default_type, int rule_id) {

    if (!node || !node->attributes) {
        return default_type;
    }

    const char * xml_type = "type";
    const char * str_type = w_get_attr_val_by_name(node, xml_type);

    if (!str_type) { 
        return default_type;
    }

    const char * xml_osregex_type = OSREGEX_STR;
    const char * xml_osmatch_type = OSMATCH_STR;
    const char * xml_pcre2_type = PCRE2_STR;

    if (strcasecmp(str_type, xml_osregex_type) == 0) {
        return EXP_TYPE_OSREGEX;
    } else if (strcasecmp(str_type, xml_osmatch_type) == 0) {
        return EXP_TYPE_OSMATCH;
    } else if (strcasecmp(str_type, xml_pcre2_type) == 0) {
        return EXP_TYPE_PCRE2;
    } else {
        mwarn(ANALYSISD_INV_VALUE_RULE, str_type, xml_type, rule_id);
    }

    return default_type;
}
