/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "rules.h"
#include "config.h"
#include "eventinfo.h"
#include "compiled_rules/compiled_rules.h"
#include "analysisd.h"

/* Global definition */
RuleInfo *currently_rule;
int default_timeframe;

/* Change path for test rule */
#ifdef TESTRULE
#undef RULEPATH
#define RULEPATH "ruleset/rules/"
#endif


/* Prototypes */
static int getattributes(char **attributes,
                  char **values,
                  int *id, int *level,
                  int *maxsize, int *timeframe,
                  int *frequency, int *accuracy,
                  int *noalert, int *ignore_time, int *overwrite);
static int doesRuleExist(int sid, RuleNode *r_node);
static void Rule_AddAR(RuleInfo *config_rule);
static char *loadmemory(char *at, const char *str);
static void printRuleinfo(const RuleInfo *rule, int node);

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

/* Will initialize the rules list */
void Rules_OP_CreateRules()
{
    /* Initialize the rule list */
    OS_CreateRuleList();

    return;
}

/* Read the log rules */
int Rules_OP_ReadRules(const char *rulefile)
{
    OS_XML xml;
    XML_NODE node = NULL;
    XML_NODE rule = NULL;
    int retval = -1;

    /* XML variables */
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
    const char *xml_srcgeoip = "srcgeoip";
    const char *xml_srcport = "srcport";
    const char *xml_dstip = "dstip";
    const char *xml_dstgeoip = "dstgeoip";
    const char *xml_dstport = "dstport";
    const char *xml_user = "user";
    const char *xml_url = "url";
    const char *xml_id = "id";
    const char *xml_data = "data";
    const char *xml_extra_data = "extra_data";
    const char *xml_hostname = "hostname";
    const char *xml_program_name = "program_name";
    const char *xml_status = "status";
    const char *xml_protocol = "protocol";
    const char *xml_system_name = "system_name";
    const char *xml_action = "action";
    const char *xml_compiled = "compiled_rule";
    const char *xml_field = "field";
    const char *xml_location = "location";

    const char *xml_list = "list";
    const char *xml_list_lookup = "lookup";
    const char *xml_list_field = "field";
    const char *xml_list_cvalue = "check_value";
    const char *xml_match_key = "match_key";
    const char *xml_not_match_key = "not_match_key";
    const char *xml_match_key_value = "match_key_value";
    const char *xml_address_key = "address_match_key";
    const char *xml_not_address_key = "not_address_match_key";
    const char *xml_address_key_value = "address_match_key_value";

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
    char *regex = NULL;
    char *match = NULL;
    char *url = NULL;
    char *if_matched_regex = NULL;
    char *if_matched_group = NULL;
    char *user = NULL;
    char *id = NULL;
    char *srcport = NULL;
    char *dstport = NULL;
    char *srcgeoip = NULL;
    char *dstgeoip = NULL;
    char *protocol = NULL;
    char *system_name = NULL;

    char *status = NULL;
    char *hostname = NULL;
    char *data = NULL;
    char *extra_data = NULL;
    char *program_name = NULL;
    char *location = NULL;
    char *action = NULL;
    RuleInfo *config_ruleinfo = NULL;

    size_t i;
    default_timeframe = 360;

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

    i = 0;

    /* Read the XML */
    if (OS_ReadXML(rulepath, &xml) < 0) {
        merror(XML_ERROR, rulepath, xml.err, xml.err_line);
        goto cleanup;
    }
    mdebug2("Read xml for rule.");

    /* Apply any variable found */
    if (OS_ApplyVariables(&xml) != 0) {
        merror(XML_ERROR_VAR, rulepath, xml.err);
        goto cleanup;
    }
    mdebug2("XML Variables applied.");

    /* Check if the file is empty */
    if(FileSize(rulepath) == 0){
        retval = 0;
        goto cleanup;
    }

    /* Get the root elements */
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        merror(CONFIG_ERROR, rulepath);
        goto cleanup;
    }

    /* Zero the rule memory -- not used anymore */
    free(rulepath);
    rulepath = NULL;

    /* Get default time frame */
    default_timeframe = getDefine_Int("analysisd",
                                      "default_timeframe",
                                      60, 3600);

    /* Check if there is any invalid global option */
    while (node[i]) {
        if (node[i]->element) {
            if (strcasecmp(node[i]->element, xml_group) != 0) {
                merror("rules_op: Invalid root element \"%s\"."
                       "Only \"group\" is allowed", node[i]->element);
                goto cleanup;
            }
            if ((!node[i]->attributes) || (!node[i]->values) ||
                    (!node[i]->values[0]) || (!node[i]->attributes[0]) ||
                    (strcasecmp(node[i]->attributes[0], "name") != 0) ||
                    (node[i]->attributes[1])) {
                merror("rules_op: Invalid root element '%s'."
                       "Only the group name is allowed", node[i]->element);
                goto cleanup;
            }
        } else {
            merror(XML_READ_ERROR);
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
            merror("Group '%s' without any rule.",
                   node[i]->element);
            goto cleanup;
        }

        while (rule[j]) {
            config_ruleinfo = NULL;

            /* Check if the rule element is correct */
            if (!rule[j]->element) {
                goto cleanup;
            }

            if (strcasecmp(rule[j]->element, xml_rule) != 0) {
                merror("Invalid configuration. '%s' is not "
                       "a valid element.", rule[j]->element);
                goto cleanup;
            }

            /* Check for the attributes of the rule */
            if ((!rule[j]->attributes) || (!rule[j]->values)) {
                merror("Invalid rule '%d'. You must specify"
                       " an ID and a level at least.", j);
                goto cleanup;
            }

            /* Attribute block */
            {
                int id = -1, level = -1, maxsize = 0, timeframe = 0;
                int frequency = 0, accuracy = 1, noalert = 0, ignore_time = 0;
                int overwrite = 0;

                /* Get default timeframe */
                timeframe = default_timeframe;

                if (getattributes(rule[j]->attributes, rule[j]->values,
                                  &id, &level, &maxsize, &timeframe,
                                  &frequency, &accuracy, &noalert,
                                  &ignore_time, &overwrite) < 0) {
                    merror("Invalid attribute for rule.");
                    goto cleanup;
                }

                if ((id == -1) || (level == -1)) {
                    merror("No rule id or level specified for "
                           "rule '%d'.", j);
                    goto cleanup;
                }

                if (overwrite != 1 && doesRuleExist(id, NULL)) {
                    merror("Duplicate rule ID:%d", id);
                    goto cleanup;
                }

                /* Allocate memory and initialize structure */
                config_ruleinfo = zerorulemember(id, level, maxsize,
                                                 frequency, timeframe,
                                                 noalert, ignore_time, overwrite);

                /* If rule is 0, set it to level 99 to have high priority.
                 * Set it to 0 again later.
                 */
                if (config_ruleinfo->level == 0) {
                    config_ruleinfo->level = 99;
                }

                /* Each level now is going to be multiplied by 100.
                 * If the accuracy is set to 0 we don't multiply,
                 * so it will be at the end of the list. We will
                 * divide by 100 later.
                 */
                if (accuracy) {
                    config_ruleinfo->level *= 100;
                }

                if (config_ruleinfo->maxsize > 0) {
                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }
                }

            } /* end attributes/memory allocation block */

            /* Here we can assign the group name to the rule.
             * The level is correct so the rule is probably going to
             * be fine
             */
            os_strdup(node[i]->values[0], config_ruleinfo->group);
            os_strdup(rulefile,config_ruleinfo->file);

            /* Rule elements block */
            {
                int ifield = 0;
                int info_type = 0;
                int count_info_detail = 0;
                int mitre_size = 0;
                RuleInfoDetail *last_info_detail = NULL;

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

                regex = NULL;
                match = NULL;
                url = NULL;
                if_matched_regex = NULL;
                if_matched_group = NULL;
                user = NULL;
                id = NULL;
                srcport = NULL;
                dstport = NULL;
                srcgeoip = NULL;
                dstgeoip = NULL;
                system_name = NULL;
                protocol = NULL;

                status = NULL;
                hostname = NULL;
                data = NULL;
                extra_data = NULL;
                program_name = NULL;
                location = NULL;
                action = NULL;

                XML_NODE rule_opt = NULL;
                rule_opt =  OS_GetElementsbyNode(&xml, rule[j]);
                if (rule_opt == NULL) {
                    merror("Rule '%d' without any option. "
                           "It may lead to false positives and some "
                           "other problems for the system. Exiting.",
                           config_ruleinfo->sigid);
                    goto cleanup;
                }

                for (int k = 0; rule_opt[k]; k++) {

                    if ((!rule_opt[k]->element) || (!rule_opt[k]->content)) {
                        break;

                    } else if (strcasecmp(rule_opt[k]->element, xml_regex) == 0) {

                        regex =loadmemory(regex, rule_opt[k]->content);
                        negate_regex = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        regex_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSREGEX, config_ruleinfo->sigid);

                    } else if (strcasecmp(rule_opt[k]->element, xml_match) == 0) {

                        match = loadmemory(match, rule_opt[k]->content);
                        negate_match = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        match_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    } else if (strcasecmp(rule_opt[k]->element, xml_decoded) == 0) {
                        config_ruleinfo->decoded_as =
                            getDecoderfromlist(rule_opt[k]->content);

                        if (config_ruleinfo->decoded_as == 0) {
                            merror("Invalid decoder name: '%s'.",
                                   rule_opt[k]->content);
                            goto cleanup;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_cve) == 0) {
                        if (config_ruleinfo->info_details == NULL) {
                            config_ruleinfo->info_details = zeroinfodetails(RULEINFODETAIL_CVE,
                                                            rule_opt[k]->content);
                        } else {
                            for (last_info_detail = config_ruleinfo->info_details;
                                    last_info_detail->next != NULL;
                                    last_info_detail = last_info_detail->next) {
                                count_info_detail++;
                            }
                            /* Silently Drop info messages if their are more then MAX_RULEINFODETAIL */
                            if (count_info_detail <= MAX_RULEINFODETAIL) {
                                last_info_detail->next = zeroinfodetails(RULEINFODETAIL_CVE,
                                                         rule_opt[k]->content);
                            }
                        }

                        /* keep old methods for now */
                        config_ruleinfo->cve =
                            loadmemory(config_ruleinfo->cve,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element, xml_info) == 0) {

                        info_type = get_info_attributes(rule_opt[k]->attributes,
                                                        rule_opt[k]->values);
                        mdebug1("info_type = %d", info_type);

                        if (config_ruleinfo->info_details == NULL) {
                            config_ruleinfo->info_details = zeroinfodetails(info_type,
                                                            rule_opt[k]->content);
                        } else {
                            for (last_info_detail = config_ruleinfo->info_details;
                                    last_info_detail->next != NULL;
                                    last_info_detail = last_info_detail->next) {
                                count_info_detail++;
                            }
                            /* Silently Drop info messages if their are more then MAX_RULEINFODETAIL */
                            if (count_info_detail <= MAX_RULEINFODETAIL) {
                                last_info_detail->next = zeroinfodetails(info_type, rule_opt[k]->content);
                            }
                        }

                        /* keep old methods for now */
                        config_ruleinfo->info =
                            loadmemory(config_ruleinfo->info,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element, xml_day_time) == 0) {
                        config_ruleinfo->day_time =
                            OS_IsValidTime(rule_opt[k]->content);
                        if (!config_ruleinfo->day_time) {
                            merror(INVALID_CONFIG,
                                   rule_opt[k]->element,
                                   rule_opt[k]->content);
                            goto cleanup;
                        }

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_week_day) == 0) {
                        config_ruleinfo->week_day =
                            OS_IsValidDay(rule_opt[k]->content);

                        if (!config_ruleinfo->week_day) {
                            merror(INVALID_CONFIG,
                                   rule_opt[k]->element,
                                   rule_opt[k]->content);
                            goto cleanup;
                        }
                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_group) == 0) {
                        config_ruleinfo->group =
                            loadmemory(config_ruleinfo->group,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element, xml_comment) == 0) {
                        char *newline;

                        newline = strchr(rule_opt[k]->content, '\n');
                        if (newline) {
                            *newline = ' ';
                        }

                        config_ruleinfo->comment =
                            loadmemory(config_ruleinfo->comment,
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

                        user = loadmemory(user, rule_opt[k]->content);
                        negate_user = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        user_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element,xml_srcgeoip) == 0) {

                        srcgeoip = loadmemory(srcgeoip, rule_opt[k]->content);
                        negate_srcgeoip = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        srcgeoip_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element,xml_dstgeoip) == 0) {

                        dstgeoip = loadmemory(dstgeoip, rule_opt[k]->content);
                        negate_dstgeoip = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        dstgeoip_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_id) == 0) {

                        id = loadmemory(id, rule_opt[k]->content);
                        negate_id = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        id_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    } else if (strcasecmp(rule_opt[k]->element, xml_srcport) == 0) {

                        srcport = loadmemory(srcport, rule_opt[k]->content);
                        negate_srcport = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        srcport_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                            config_ruleinfo->alert_opts |= DO_PACKETINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_dstport) == 0) {

                        dstport = loadmemory(dstport, rule_opt[k]->content);
                        negate_dstport = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        dstport_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                            config_ruleinfo->alert_opts |= DO_PACKETINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_status) == 0) {

                        status = loadmemory(status, rule_opt[k]->content);
                        negate_status = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        status_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_hostname) == 0) {

                        hostname = loadmemory(hostname, rule_opt[k]->content);
                        negate_hostname = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        hostname_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_data) == 0) {

                        data = loadmemory(data, rule_opt[k]->content);
                        negate_data = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        data_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_extra_data) == 0) {

                        extra_data = loadmemory(extra_data, rule_opt[k]->content);
                        negate_extra_data = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        extra_data_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_program_name) == 0) {

                        program_name = loadmemory(program_name, rule_opt[k]->content);
                        negate_program_name = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        program_name_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    } else if (strcasecmp(rule_opt[k]->element, xml_action) == 0) {

                        action = loadmemory(action, rule_opt[k]->content);
                        negate_action = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        action_type = w_check_attr_type(rule_opt[k], EXP_TYPE_STRING, config_ruleinfo->sigid);

                    } else if(strcasecmp(rule_opt[k]->element, xml_system_name) == 0){

                        system_name = loadmemory(system_name, rule_opt[k]->content);
                        negate_system_name = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        system_name_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    } else if(strcasecmp(rule_opt[k]->element, xml_protocol) == 0){

                        protocol = loadmemory(protocol, rule_opt[k]->content);
                        negate_protocol = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        protocol_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    } else if (strcasecmp(rule_opt[k]->element, xml_location) == 0) {

                        location = loadmemory(location, rule_opt[k]->content);
                        negate_location = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        location_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    } else if (strcasecmp(rule_opt[k]->element, xml_field) == 0) {

                        if (!w_check_attr_field_name(rule_opt[k],
                                                     &config_ruleinfo->fields[ifield],
                                                     config_ruleinfo->sigid)) {
                            goto cleanup;
                        }

                        w_exp_type_t type;
                        type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSREGEX, config_ruleinfo->sigid);

                        bool negate = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);

                        w_calloc_expression_t(&config_ruleinfo->fields[ifield]->regex, type);
                        config_ruleinfo->fields[ifield]->regex->negate = negate;

                        if (!w_expression_compile(config_ruleinfo->fields[ifield]->regex, rule_opt[k]->content, 0)) {
                            merror(RL_REGEX_SYNTAX, config_ruleinfo->fields[ifield]->name, config_ruleinfo->sigid);
                            goto cleanup;
                        }

                        ifield++;

                    } else if (strcasecmp(rule_opt[k]->element, xml_list) == 0) {
                        mdebug1("-> %s == %s", rule_opt[k]->element, xml_list);
                        if (rule_opt[k]->attributes && rule_opt[k]->values && rule_opt[k]->content) {
                            int list_att_num = 0;
                            int rule_type = 0;
                            char *rule_dfield = NULL;
                            OSMatch *matcher = NULL;
                            int lookup_type = LR_STRING_MATCH;
                            while (rule_opt[k]->attributes[list_att_num]) {
                                if (strcasecmp(rule_opt[k]->attributes[list_att_num], xml_list_lookup) == 0) {
                                    if (strcasecmp(rule_opt[k]->values[list_att_num], xml_match_key) == 0) {
                                        lookup_type = LR_STRING_MATCH;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_not_match_key) == 0) {
                                        lookup_type = LR_STRING_NOT_MATCH;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_match_key_value) == 0) {
                                        lookup_type = LR_STRING_MATCH_VALUE;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_address_key) == 0) {
                                        lookup_type = LR_ADDRESS_MATCH;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_not_address_key) == 0) {
                                        lookup_type = LR_ADDRESS_NOT_MATCH;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_address_key_value) == 0) {
                                        lookup_type = LR_ADDRESS_MATCH_VALUE;
                                    } else {
                                        merror(INVALID_CONFIG,
                                               rule_opt[k]->element,
                                               rule_opt[k]->content);
                                        merror("List match lookup=\"%s\" is not valid.",
                                               rule_opt[k]->values[list_att_num]);
                                        goto cleanup;
                                    }
                                } else if (strcasecmp(rule_opt[k]->attributes[list_att_num], xml_list_field) == 0) {
                                    if (strcasecmp(rule_opt[k]->values[list_att_num], xml_srcip) == 0) {
                                        rule_type = RULE_SRCIP;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_srcport) == 0) {
                                        rule_type = RULE_SRCPORT;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_dstip) == 0) {
                                        rule_type = RULE_DSTIP;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_dstport) == 0) {
                                        rule_type = RULE_DSTPORT;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_user) == 0) {
                                        rule_type = RULE_USER;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_url) == 0) {
                                        rule_type = RULE_URL;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_id) == 0) {
                                        rule_type = RULE_ID;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_hostname) == 0) {
                                        rule_type = RULE_HOSTNAME;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_program_name) == 0) {
                                        rule_type = RULE_PROGRAM_NAME;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_status) == 0) {
                                        rule_type = RULE_STATUS;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_action) == 0) {
                                        rule_type = RULE_ACTION;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_protocol) == 0) {
                                        rule_type = RULE_PROTOCOL;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_system_name) == 0) {
                                        rule_type = RULE_SYSTEMNAME;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_data) == 0) {
                                        rule_type = RULE_DATA;
                                    } else if (strcasecmp(rule_opt[k]->values[list_att_num], xml_extra_data) == 0) {
                                        rule_type = RULE_EXTRA_DATA;
                                    } else {
                                        rule_type = RULE_DYNAMIC;

                                        // Trim whitespaces
                                        rule_dfield = rule_opt[k]->values[list_att_num];
                                        rule_dfield = &rule_dfield[strspn(rule_dfield, " ")];
                                        rule_dfield[strcspn(rule_dfield, " ")] = '\0';
                                    }
                                } else if (strcasecmp(rule_opt[k]->attributes[list_att_num], xml_list_cvalue) == 0) {
                                    os_calloc(1, sizeof(OSMatch), matcher);
                                    if (!OSMatch_Compile(rule_opt[k]->values[list_att_num], matcher, 0)) {
                                        merror(INVALID_CONFIG,
                                               rule_opt[k]->element,
                                               rule_opt[k]->content);
                                        merror(REGEX_COMPILE,
                                               rule_opt[k]->values[list_att_num],
                                               matcher->error);
                                        goto cleanup;
                                    }
                                } else {
                                    merror("List field=\"%s\" is not valid",
                                           rule_opt[k]->values[list_att_num]);
                                    merror(INVALID_CONFIG,
                                           rule_opt[k]->element, rule_opt[k]->content);
                                    goto cleanup;
                                }
                                list_att_num++;
                            }
                            if (rule_type == 0) {
                                merror("List requires the field=\"\" attribute");
                                merror(INVALID_CONFIG,
                                       rule_opt[k]->element, rule_opt[k]->content);
                                goto cleanup;
                            }

                            /* Wow it's all ready - this seems too complex to get to this point */
                            config_ruleinfo->lists = OS_AddListRule(config_ruleinfo->lists,
                                                                    lookup_type,
                                                                    rule_type,
                                                                    rule_dfield,
                                                                    rule_opt[k]->content,
                                                                    matcher);
                            if (config_ruleinfo->lists == NULL) {
                                merror("List error: Could not load %s", rule_opt[k]->content);
                                goto cleanup;
                            }
                        } else {
                            merror("List must have a correctly formatted field attribute");
                            merror(INVALID_CONFIG,
                                   rule_opt[k]->element,
                                   rule_opt[k]->content);
                            goto cleanup;
                        }
                        /* xml_list eval is done */

                    } else if (strcasecmp(rule_opt[k]->element, xml_url) == 0) {

                        url = loadmemory(url, rule_opt[k]->content);
                        negate_url = w_check_attr_negate(rule_opt[k], config_ruleinfo->sigid);
                        url_type = w_check_attr_type(rule_opt[k], EXP_TYPE_OSMATCH, config_ruleinfo->sigid);

                    } else if (strcasecmp(rule_opt[k]->element, xml_compiled) == 0) {
                        int it_id = 0;

                        while (compiled_rules_name[it_id]) {
                            if (strcmp(compiled_rules_name[it_id],
                                       rule_opt[k]->content) == 0) {
                                break;
                            }
                            it_id++;
                        }

                        /* Checking if the name is valid */
                        if (!compiled_rules_name[it_id]) {
                            merror("Compiled rule not found: '%s'",
                                   rule_opt[k]->content);
                            merror(INVALID_CONFIG,
                                   rule_opt[k]->element, rule_opt[k]->content);
                            goto cleanup;

                        }

                        config_ruleinfo->compiled_rule = (void *(*)(void *)) compiled_rules_list[it_id];
                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_category) == 0) {
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
                            goto cleanup;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_if_sid) == 0) {
                        config_ruleinfo->if_sid =
                            loadmemory(config_ruleinfo->if_sid,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element, xml_if_level) == 0) {
                        if (!OS_StrIsNum(rule_opt[k]->content)) {
                            merror(INVALID_CONFIG,
                                   "if_level",
                                   rule_opt[k]->content);
                            goto cleanup;
                        }

                        config_ruleinfo->if_level =
                            loadmemory(config_ruleinfo->if_level,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element, xml_if_group) == 0) {
                        config_ruleinfo->if_group =
                            loadmemory(config_ruleinfo->if_group,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_if_matched_regex) == 0) {
                        config_ruleinfo->context = 1;
                        if_matched_regex =
                            loadmemory(if_matched_regex,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_if_matched_group) == 0) {
                        config_ruleinfo->context = 1;
                        if_matched_group =
                            loadmemory(if_matched_group,
                                       rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_if_matched_sid) == 0) {
                        config_ruleinfo->context = 1;
                        if (!OS_StrIsNum(rule_opt[k]->content)) {
                            merror(INVALID_CONFIG,
                                   "if_matched_sid",
                                   rule_opt[k]->content);
                            goto cleanup;
                        }
                        config_ruleinfo->if_matched_sid =
                            atoi(rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_source_ip) == 0 ||
                               strcasecmp(rule_opt[k]->element,
                                          xml_same_srcip) == 0) {
                        config_ruleinfo->same_field |= FIELD_SRCIP;

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_dstip) == 0) {
                        config_ruleinfo->same_field |= FIELD_DSTIP;

                        if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                        }

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_src_port) == 0 ||
                               strcasecmp(rule_opt[k]->element,
                                          xml_same_srcport) == 0) {
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

                    } else if (strcmp(rule_opt[k]->element,
                                      xml_same_url) == 0) {
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

                    } else if (strcmp(rule_opt[k]->element,
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

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_notsame_field) == 0 ||
                               strcasecmp(rule_opt[k]->element,
                                          xml_different_field) == 0) {

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

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_options) == 0) {
                        if (strcmp("alert_by_email",
                                   rule_opt[k]->content) == 0) {
                            if (!(config_ruleinfo->alert_opts & DO_MAILALERT)) {
                                config_ruleinfo->alert_opts |= DO_MAILALERT;
                            }
                        } else if (strcmp("no_email_alert",
                                          rule_opt[k]->content) == 0) {
                            if (config_ruleinfo->alert_opts & DO_MAILALERT) {
                                config_ruleinfo->alert_opts &= 0xfff - DO_MAILALERT;
                            }
                        } else if (strcmp("log_alert",
                                          rule_opt[k]->content) == 0) {
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
                            merror(XML_VALUEERR, xml_options,
                                   rule_opt[k]->content);

                            merror("Invalid option '%s' for "
                                   "rule '%d'.", rule_opt[k]->element,
                                   config_ruleinfo->sigid);
                            goto cleanup;
                        }

                    } else if (strcasecmp(rule_opt[k]->element, xml_ignore) == 0) {
                        char **norder;
                        char **s_norder;
                        int i;

                        norder = OS_StrBreak(',', rule_opt[k]->content, Config.decoder_order_size);
                        if (norder == NULL) {
                            merror_exit(MEM_ERROR, errno, strerror(errno));
                        }

                        s_norder = norder;
                        os_calloc(Config.decoder_order_size, sizeof(char*), config_ruleinfo->ignore_fields);

                        for (i = 0; *norder; i++) {
                            char *word = &(*norder)[strspn(*norder, " ")];
                            word[strcspn(word, " ")] = '\0';

                            if (strlen(word) == 0)
                                merror_exit("Wrong ignore option: '%s'", rule_opt[k]->content);

                            if (!strcmp(word, "user")) {
                                config_ruleinfo->ignore |= FTS_DSTUSER;
                            } else if (!strcmp(word, "srcip")) {
                                config_ruleinfo->ignore |= FTS_SRCIP;
                            } else if (!strcmp(word, "dstip")) {
                                config_ruleinfo->ignore |= FTS_DSTIP;
                            } else if (!strcmp(word, "id")) {
                                config_ruleinfo->ignore |= FTS_ID;
                            } else if (!strcmp(word, "location")) {
                                config_ruleinfo->ignore |= FTS_LOCATION;
                            } else if (!strcmp(word, "data")) {
                                config_ruleinfo->ignore |= FTS_DATA;
                            } else if (!strcmp(word, "name")) {
                                config_ruleinfo->ignore |= FTS_NAME;
                            } else {
                                if (i >= Config.decoder_order_size)
                                    merror_exit("Too many dynamic fields for ignore.");

                                config_ruleinfo->ignore |= FTS_DYNAMIC;
                                config_ruleinfo->ignore_fields[i] = strdup(word);
                            }

                            free(*norder);
                            norder++;
                        }

                        free(s_norder);

                    } else if (strcasecmp(rule_opt[k]->element, xml_check_if_ignored) == 0) {
                        char **norder;
                        char **s_norder;
                        int i;

                        norder = OS_StrBreak(',', rule_opt[k]->content, Config.decoder_order_size);
                        if (norder == NULL) {
                            merror_exit(MEM_ERROR, errno, strerror(errno));
                        }

                        s_norder = norder;
                        os_calloc(Config.decoder_order_size, sizeof(char*), config_ruleinfo->ckignore_fields);

                        for (i = 0; *norder; i++) {
                            char *word = &(*norder)[strspn(*norder, " ")];
                            word[strcspn(word, " ")] = '\0';

                            if (strlen(word) == 0)
                                merror_exit("Wrong check_if_ignored option: '%s'", rule_opt[k]->content);


                            if (!strcmp(word, "user")) {
                                config_ruleinfo->ckignore |= FTS_DSTUSER;
                            } else if (!strcmp(word, "srcip")) {
                                config_ruleinfo->ckignore |= FTS_SRCIP;
                            } else if (!strcmp(word, "dstip")) {
                                config_ruleinfo->ckignore |= FTS_DSTIP;
                            } else if (!strcmp(word, "id")) {
                                config_ruleinfo->ckignore |= FTS_ID;
                            } else if (!strcmp(word, "location")) {
                                config_ruleinfo->ckignore |= FTS_LOCATION;
                            } else if (!strcmp(word, "data")) {
                                config_ruleinfo->ckignore |= FTS_DATA;
                            } else if (!strcmp(word, "name")) {
                                config_ruleinfo->ckignore |= FTS_NAME;
                            } else {
                                if (i >= Config.decoder_order_size)
                                    merror_exit("Too many dynamic fields for check_if_ignored.");

                                config_ruleinfo->ckignore |= FTS_DYNAMIC;
                                config_ruleinfo->ckignore_fields[i] = strdup(word);
                            }

                            free(*norder);
                            norder++;
                        }

                        free(s_norder);

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
                                        if (strcmp(config_ruleinfo->mitre_id[l], mitre_opt[ind]->content) == 0) {
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
                                free_strarray(config_ruleinfo->mitre_id);
                                OS_ClearNode(mitre_opt);
                                goto cleanup;
                            }
                        }
                        OS_ClearNode(mitre_opt);

                    } else {
                        merror("Invalid option '%s' for rule '%d'.", rule_opt[k]->element, config_ruleinfo->sigid);
                        goto cleanup;
                    }
                }

                /* Check for a valid description */
                if (!config_ruleinfo->comment) {
                    merror("No such description at rule '%d'.", config_ruleinfo->sigid);
                    goto cleanup;
                }

                /* Check for valid use of frequency */
                if ((config_ruleinfo->context_opts || config_ruleinfo->same_field ||
                    config_ruleinfo->different_field || config_ruleinfo->frequency) &&
                    !config_ruleinfo->context) {

                    merror("Invalid use of frequency/context options. "
                           "Missing if_matched on rule '%d'.",
                           config_ruleinfo->sigid);
                    goto cleanup;
                }

                /* If if_matched_group we must have a if_sid or if_group */
                if (if_matched_group) {
                    if (!config_ruleinfo->if_sid && !config_ruleinfo->if_group) {
                        os_strdup(if_matched_group,
                                  config_ruleinfo->if_group);
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

                OS_ClearNode(rule_opt);
            } /* end of elements block */

            /* Assign an active response to the rule */
            Rule_AddAR(config_ruleinfo);

            j++; /* next rule */

            /* Add the rule to the rules list.
             * Only the template rules are supposed
             * to be at the top level. All others
             * will be a "child" of someone.
             */
            if (config_ruleinfo->sigid < 10) {
                OS_AddRule(config_ruleinfo);
            } else if (config_ruleinfo->alert_opts & DO_OVERWRITE) {
                if (!OS_AddRuleInfo(NULL, config_ruleinfo,
                                    config_ruleinfo->sigid)) {
                    merror("Overwrite rule '%d' not found.",
                           config_ruleinfo->sigid);
                    goto cleanup;
                }
            } else {
                OS_AddChild(config_ruleinfo);
            }

            /* Clean what we do not need */
            if (config_ruleinfo->if_group) {
                free(config_ruleinfo->if_group);
                config_ruleinfo->if_group = NULL;
            }

            /* Set the event_search pointer */
            if (config_ruleinfo->if_matched_sid) {
                config_ruleinfo->event_search = (void *(*)(void *, void *, void *))
                    Search_LastSids;

                /* Mark rules that match this id */
                OS_MarkID(NULL, config_ruleinfo);
            }

            /* Mark the rules that match if_matched_group */
            else if (config_ruleinfo->if_matched_group) {
                /* Create list */
                config_ruleinfo->group_search = OSList_Create();
                if (!config_ruleinfo->group_search) {
                    merror_exit(MEM_ERROR, errno, strerror(errno));
                }

                /* Mark rules that match this group */
                OS_MarkGroup(NULL, config_ruleinfo);

                /* Set function pointer */
                config_ruleinfo->event_search = (void *(*)(void *, void *, void *))
                    Search_LastGroups;
            } else if (config_ruleinfo->context) {
                if ((config_ruleinfo->context == 1) &&
                        (config_ruleinfo->context_opts & FIELD_DODIFF)) {
                    config_ruleinfo->context = 0;
                } else {
                    config_ruleinfo->event_search = (void *(*)(void *, void *, void *))
                        Search_LastEvents;
                }
            }

        } /* while(rule[j]) */
        OS_ClearNode(rule);
        rule = NULL;
        i++;

    } /* while (node[i]) */

#ifdef DEBUG
    {
        RuleNode *dbg_node = OS_GetFirstRule();
        while (dbg_node) {
            if (dbg_node->child) {
                RuleNode *child_node = dbg_node->child;

                printf("** Child Node for %d **\n", dbg_node->ruleinfo->sigid);
                while (child_node) {
                    child_node = child_node->next;
                }
            }
            dbg_node = dbg_node->next;
        }
    }
#endif

    /* Done over here */
    retval = 0;

cleanup:

    os_free(regex);
    os_free(match);
    os_free(id);
    os_free(srcport);
    os_free(dstport);
    os_free(status);
    os_free(hostname);
    os_free(extra_data);
    os_free(program_name);
    os_free(location);
    os_free(user);
    os_free(srcgeoip);
    os_free(dstgeoip);
    os_free(url);
    os_free(if_matched_group);
    os_free(if_matched_regex);
    os_free(system_name);
    os_free(protocol);
    os_free(data);
    os_free(rulepath);
    os_free(action)
    OS_ClearNode(rule);

    if (retval) {
        free(config_ruleinfo);
    }

    /* Clean global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    return retval;
}

/* Allocate memory at "*at" and copy *str to it.
 * If *at already exist, realloc the memory and cat str on it.
 * Returns the new string
 */
static char *loadmemory(char *at, const char *str)
{
    if (at == NULL) {
        size_t strsize = 0;
        if ((strsize = strlen(str)) < OS_SIZE_2048) {
            at = (char *) calloc(strsize + 1, sizeof(char));
            if (at == NULL) {
                merror(MEM_ERROR, errno, strerror(errno));
                return (NULL);
            }
            strncpy(at, str, strsize);
            return (at);
        } else {
            merror(SIZE_ERROR, str);
            return (NULL);
        }
    } else {
        /* at is not null. Need to reallocate its memory and copy str to it */
        size_t strsize = strlen(str);
        size_t atsize = strlen(at);
        size_t finalsize = atsize + strsize + 1;

        if ((atsize > OS_SIZE_2048) || (strsize > OS_SIZE_2048)) {
            merror(SIZE_ERROR, str);
            return (NULL);
        }

        at = (char *) realloc(at, (finalsize) * sizeof(char));

        if (at == NULL) {
            merror(MEM_ERROR, errno, strerror(errno));
            return (NULL);
        }

        strncat(at, str, strsize);
        at[finalsize - 1] = '\0';

        return (at);
    }
    return (NULL);
}

RuleInfoDetail *zeroinfodetails(int type, const char *data)
{
    RuleInfoDetail *info_details_pt = NULL;

    info_details_pt = (RuleInfoDetail *)calloc(1, sizeof(RuleInfoDetail));

    if (info_details_pt == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    info_details_pt->type = type;
    os_strdup(data, info_details_pt->data);
    info_details_pt->next = NULL;

    return (info_details_pt);
}

RuleInfo *zerorulemember(int id, int level,
                         int maxsize, int frequency,
                         int timeframe, int noalert,
                         int ignore_time, int overwrite)
{
    RuleInfo *ruleinfo_pt = NULL;

    /* Allocate memory for structure */
    ruleinfo_pt = (RuleInfo *)calloc(1, sizeof(RuleInfo));

    if (ruleinfo_pt == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Default values */
    ruleinfo_pt->level = level;

    /* Default category is syslog */
    ruleinfo_pt->category = SYSLOG;

    ruleinfo_pt->ar = NULL;

    ruleinfo_pt->context = 0;

    ruleinfo_pt->sigid = id;
    ruleinfo_pt->firedtimes = 0;
    ruleinfo_pt->maxsize = maxsize;
    ruleinfo_pt->frequency = frequency;
    if (ruleinfo_pt->frequency > last_events_list->_max_freq) {
        last_events_list->_max_freq = ruleinfo_pt->frequency;
    }
    ruleinfo_pt->ignore_time = ignore_time;
    ruleinfo_pt->timeframe = timeframe;
    ruleinfo_pt->time_ignored = 0;

    ruleinfo_pt->same_field = 0;
    ruleinfo_pt->different_field = 0;
    ruleinfo_pt->context_opts = 0;
    ruleinfo_pt->alert_opts = 0;
    ruleinfo_pt->ignore = 0;
    ruleinfo_pt->ckignore = 0;
    ruleinfo_pt->ignore_fields = NULL;
    ruleinfo_pt->ckignore_fields = NULL;

    if (noalert) {
        ruleinfo_pt->alert_opts |= NO_ALERT;
    }
    if (Config.mailbylevel <= level) {
        ruleinfo_pt->alert_opts |= DO_MAILALERT;
    }
    if (Config.logbylevel <= level) {
        ruleinfo_pt->alert_opts |= DO_LOGALERT;
    }

    /* Overwrite a rule */
    if (overwrite) {
        ruleinfo_pt->alert_opts |= DO_OVERWRITE;
    }

    ruleinfo_pt->day_time = NULL;
    ruleinfo_pt->week_day = NULL;

    ruleinfo_pt->group = NULL;
    ruleinfo_pt->regex = NULL;
    ruleinfo_pt->match = NULL;
    ruleinfo_pt->decoded_as = 0;

    ruleinfo_pt->comment = NULL;
    ruleinfo_pt->info = NULL;
    ruleinfo_pt->cve = NULL;
    ruleinfo_pt->info_details = NULL;

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
    os_calloc(Config.decoder_order_size, sizeof(FieldInfo*), ruleinfo_pt->fields);

    ruleinfo_pt->same_fields = NULL;
    ruleinfo_pt->not_same_fields = NULL;

    /* Zeroing the list of previous matches */
    ruleinfo_pt->sid_prev_matched = NULL;
    ruleinfo_pt->group_prev_matched = NULL;

    ruleinfo_pt->sid_search = NULL;
    ruleinfo_pt->group_search = NULL;

    ruleinfo_pt->event_search = NULL;
    ruleinfo_pt->compiled_rule = NULL;
    ruleinfo_pt->lists = NULL;

    ruleinfo_pt->prev_rule = NULL;

    return (ruleinfo_pt);
}

int get_info_attributes(char **attributes, char **values)
{
    const char *xml_type = "type";
    int k = 0;

    if (!attributes) {
        return (RULEINFODETAIL_TEXT);
    }

    while (attributes[k]) {
        if (strcasecmp(attributes[k], xml_type) == 0) {
            if (!values[k]) {
                merror("rules_op: Element info attribute \"%s\" does not have a value",
                       attributes[k]);
                return (-1);
            } else if (strcmp(values[k], "text") == 0) {
                return (RULEINFODETAIL_TEXT);
            } else if (strcmp(values[k], "link") == 0) {
                return (RULEINFODETAIL_LINK);
            } else if (strcmp(values[k], "cve") == 0) {
                return (RULEINFODETAIL_CVE);
            } else if (strcmp(values[k], "osvdb") == 0) {
                return (RULEINFODETAIL_OSVDB);
            } else {
                merror("rules_op: Element info attribute \"%s\" has invalid value \"%s\"",
                       attributes[k], values[k]);
                return (-1);
            }
        } else {
            merror("rules_op: Element info has invalid attribute \"%s\"",
                   attributes[k]);
            return (-1);
        }
    }
    return (RULEINFODETAIL_TEXT);
}

/* Get the attributes */
static int getattributes(char **attributes, char **values,
                  int *id, int *level,
                  int *maxsize, int *timeframe,
                  int *frequency, int *accuracy,
                  int *noalert, int *ignore_time, int *overwrite)
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
            merror("rules_op: Attribute \"%s\" without value."
                   , attributes[k]);
            return (-1);
        }
        /* Get rule id */
        else if (strcasecmp(attributes[k], xml_id) == 0) {
            if (OS_StrIsNum(values[k]) && strlen(values[k]) <= 6) {
                sscanf(values[k], "%6d", id);
            } else {
                merror("rules_op: Invalid rule id: %s. "
                       "Must be integer (max 6 digits)" ,
                       values[k]);
                return (-1);
            }
        }
        /* Get level */
        else if (strcasecmp(attributes[k], xml_level) == 0) {
            if (OS_StrIsNum(values[k])) {
                *level = atoi(values[k]);
                if (*level < 0 || *level > 16) {
                    merror("rules_op: Invalid level: %d. Must be an integer between 0 and 16.", *level);
                    return (-1);
                }
            }
        }
        /* Get maxsize */
        else if (strcasecmp(attributes[k], xml_maxsize) == 0) {
            if (OS_StrIsNum(values[k])) {
                sscanf(values[k], "%4d", maxsize);
            } else {
                merror("rules_op: Invalid maxsize: %s. "
                       "Must be integer" ,
                       values[k]);
                return (-1);
            }
        }
        /* Get timeframe */
        else if (strcasecmp(attributes[k], xml_timeframe) == 0) {
            if (OS_StrIsNum(values[k])) {
                sscanf(values[k], "%5d", timeframe);
            } else {
                merror("rules_op: Invalid timeframe: %s. "
                       "Must be integer (max 5 digits)" ,
                       values[k]);
                return (-1);
            }
        }
        /* Get frequency */
        else if (strcasecmp(attributes[k], xml_frequency) == 0) {
            if (OS_StrIsNum(values[k])) {
                *frequency = atoi(values[k]);
                if (*frequency < 2 || *frequency > 9999) {
                    merror("rules_op: Invalid frequency: %d. Must be higher than 1 and lower than 10000.", *frequency);
                    return (-1);
                }
                *frequency = *frequency - 2;
            } else {
                merror("rules_op: Invalid frequency: %s. "
                       "Must be integer" ,
                       values[k]);
                return (-1);
            }
        }
        /* Rule accuracy */
        else if (strcasecmp(attributes[k], xml_accuracy) == 0) {
            if (OS_StrIsNum(values[k])) {
                sscanf(values[k], "%4d", accuracy);
            } else {
                merror("rules_op: Invalid accuracy: %s. "
                       "Must be integer" ,
                       values[k]);
                return (-1);
            }
        }
        /* Rule ignore_time */
        else if (strcasecmp(attributes[k], xml_ignore_time) == 0) {
            if (OS_StrIsNum(values[k])) {
                sscanf(values[k], "%6d", ignore_time);
            } else {
                merror("rules_op: Invalid ignore_time: %s. "
                       "Must be integer (max 6 digits)" ,
                       values[k]);
                return (-1);
            }
        }
        /* Rule noalert */
        else if (strcasecmp(attributes[k], xml_noalert) == 0) {
            *noalert = 1;
        } else if (strcasecmp(attributes[k], xml_overwrite) == 0) {
            if (strcmp(values[k], "yes") == 0) {
                *overwrite = 1;
            } else if (strcmp(values[k], "no") == 0) {
                *overwrite = 0;
            } else {
                merror("rules_op: Invalid overwrite: %s. "
                       "Can only by 'yes' or 'no'.", values[k]);
                return (-1);
            }
        } else {
            merror("rules_op: Invalid attribute \"%s\". "
                   "Only id, level, maxsize, accuracy, noalert, ignore, frequency and timeframe "
                   "are allowed.", attributes[k]);
            return (-1);
        }
        k++;
    }
    return (0);
}

/* Bind active responses to a rule */
static void Rule_AddAR(RuleInfo *rule_config)
{
    unsigned int rule_ar_size = 0;
    int mark_to_ar = 0;
    int rule_real_level = 0;

    OSListNode *my_ars_node;

    /* Set the correct levels
     * We play internally with the rules, to set
     * the priorities... Rules with 0 of accuracy,
     * receive a low level and go down in the list
     */
    if (rule_config->level == 9900) {
        rule_real_level = 0;
    }

    else if (rule_config->level >= 100) {
        rule_real_level = rule_config->level / 100;
    }

    /* No AR for ignored rules */
    if (rule_real_level == 0) {
        return;
    }

    /* No AR when options no_ar is set */
    if (rule_config->alert_opts & NO_AR) {
        return;
    }

    if (!active_responses) {
        return;
    }

    /* Loop on all AR */
    my_ars_node = OSList_GetFirstNode(active_responses);
    while (my_ars_node) {
        active_response *my_ar;


        my_ar = (active_response *)my_ars_node->data;
        mark_to_ar = 0;

        /* If level and group are specified, rules have to match both of them */
        if (my_ar->level && my_ar->rules_group){
            if (rule_real_level >= my_ar->level && OS_Regex(my_ar->rules_group, rule_config->group)){
                mark_to_ar = 1;
            }
        }else{
            /* Check if the level for the ar is higher */
            if (my_ar->level) {
                if (rule_real_level >= my_ar->level) {
                    mark_to_ar = 1;
                }
            }

            /* Check if group matches */
            if (my_ar->rules_group) {
                if (OS_Regex(my_ar->rules_group, rule_config->group)) {
                    mark_to_ar = 1;
                }
            }
        }

        /* Check if rule id matches */
        if (my_ar->rules_id) {
            int r_id = 0;
            char *str_pt = my_ar->rules_id;

            while (*str_pt != '\0') {
                /* We allow spaces in between */
                if (*str_pt == ' ') {
                    str_pt++;
                    continue;
                }

                /* If is digit, we get the value
                 * and search for the next digit
                 * available
                 */
                else if (isdigit((int)*str_pt)) {
                    r_id = atoi(str_pt);

                    /* mark to ar if id matches */
                    if (r_id == rule_config->sigid) {
                        mark_to_ar = 1;
                    }

                    str_pt = strchr(str_pt, ',');
                    if (str_pt) {
                        str_pt++;
                    } else {
                        break;
                    }
                }

                /* Check for duplicate commas */
                else if (*str_pt == ',') {
                    str_pt++;
                    continue;
                }

                else {
                    break;
                }
            }
        } /* eof of rules_id */

        /* Bind AR to the rule */
        if (mark_to_ar == 1) {
            rule_ar_size++;

            rule_config->ar = (active_response **) realloc(rule_config->ar,
                                      (rule_ar_size + 1)
                                      * sizeof(active_response *));
            if(!rule_config->ar){
                merror_exit(MEM_ERROR, errno, strerror(errno));
            }

            /* Always set the last node to NULL */
            rule_config->ar[rule_ar_size - 1] = my_ar;
            rule_config->ar[rule_ar_size] = NULL;
        }

        my_ars_node = OSList_GetNextNode(active_responses);
    }

    return;
}

static void printRuleinfo(const RuleInfo *rule, int node)
{
    mdebug1("%d : rule:%d, level %d, timeout: %d",
           node,
           rule->sigid,
           rule->level,
           rule->ignore_time);
}

/* Add rule to hash */
int AddHash_Rule(RuleNode *node)
{
    char id_key[15] = {'\0'};

    while (node) {
        snprintf(id_key, 14, "%d", node->ruleinfo->sigid);

        /* Add key to hash */
        /* Ignore if the key is already stored */
        if (!OSHash_Add(Config.g_rules_hash, id_key, node->ruleinfo)) {
            merror("At AddHash_Rule(): OSHash_Add() failed");
            break;
        }

        if (node->child) AddHash_Rule(node->child);

        node = node->next;
    }

    return (0);
}

int _setlevels(RuleNode *node, int nnode)
{
    int l_size = 0;
    while (node) {
        if (node->ruleinfo->level == 9900) {
            node->ruleinfo->level = 0;
        }

        if (node->ruleinfo->level >= 100) {
            node->ruleinfo->level /= 100;
        }

        l_size++;

        /* Rule information */
        printRuleinfo(node->ruleinfo, nnode);

        if (node->child) {
            int chl_size = 0;
            chl_size = _setlevels(node->child, nnode + 1);

            l_size += chl_size;
        }

        node = node->next;
    }

    return (l_size);
}

/* Test if a rule id exists
 * return 1 if exists, otherwise 0
 */
static int doesRuleExist(int sid, RuleNode *r_node)
{
    /* Start from the beginning of the list by default */
    if (!r_node) {
        r_node = OS_GetFirstRule();
    }

    while (r_node) {
        /* Check if the sigid matches */
        if (r_node->ruleinfo->sigid == sid) {
            return (1);
        }

        /* Check if the rule has a child */
        if (r_node->child) {
            /* Check recursively */
            if (doesRuleExist(sid, r_node->child)) {
                return (1);
            }
        }

        /* Go to the next rule */
        r_node = r_node->next;
    }

    return (0);
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
    (*field)->name = loadmemory((*field)->name, name_value);

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
