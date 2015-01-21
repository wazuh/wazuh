/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "rules.h"
#include "config.h"
#include "eventinfo.h"
#include "compiled_rules/compiled_rules.h"

/* Change path for test rule */
#ifdef TESTRULE
#undef RULEPATH
#define RULEPATH "rules/"
#endif

/* Prototypes */
int getattributes(char **attributes,
                  char **values,
                  int *id, int *level,
                  int *maxsize, int *timeframe,
                  int *frequency, int *accuracy,
                  int *noalert, int *ignore_time, int *overwrite);
int doesRuleExist(int sid, RuleNode *r_node);
void Rule_AddAR(RuleInfo *config_rule);
char *loadmemory(char *at, char *str);
int getDecoderfromlist(char *name);

/* Global variables */
extern int _max_freq;


/* Will initialize the rules list */
void Rules_OP_CreateRules()
{
    /* Initialize the rule list */
    OS_CreateRuleList();

    return;
}

/* Read the log rules */
int Rules_OP_ReadRules(char *rulefile)
{
    OS_XML xml;
    XML_NODE node = NULL;

    /* XML variables */
    /* These are the available options for the rule configuration */

    char *xml_group = "group";
    char *xml_rule = "rule";

    char *xml_regex = "regex";
    char *xml_match = "match";
    char *xml_decoded = "decoded_as";
    char *xml_category = "category";
    char *xml_cve = "cve";
    char *xml_info = "info";
    char *xml_day_time = "time";
    char *xml_week_day = "weekday";
    char *xml_comment = "description";
    char *xml_ignore = "ignore";
    char *xml_check_if_ignored = "check_if_ignored";

    char *xml_srcip = "srcip";
    char *xml_srcport = "srcport";
    char *xml_dstip = "dstip";
    char *xml_dstport = "dstport";
    char *xml_user = "user";
    char *xml_url = "url";
    char *xml_id = "id";
    char *xml_data = "extra_data";
    char *xml_hostname = "hostname";
    char *xml_program_name = "program_name";
    char *xml_status = "status";
    char *xml_action = "action";
    char *xml_compiled = "compiled_rule";

    char *xml_list = "list";
    char *xml_list_lookup = "lookup";
    char *xml_list_field = "field";
    char *xml_list_cvalue = "check_value";
    char *xml_match_key = "match_key";
    char *xml_not_match_key = "not_match_key";
    char *xml_match_key_value = "match_key_value";
    char *xml_address_key = "address_match_key";
    char *xml_not_address_key = "not_address_match_key";
    char *xml_address_key_value = "address_match_key_value";

    char *xml_if_sid = "if_sid";
    char *xml_if_group = "if_group";
    char *xml_if_level = "if_level";
    char *xml_fts = "if_fts";

    char *xml_if_matched_regex = "if_matched_regex";
    char *xml_if_matched_group = "if_matched_group";
    char *xml_if_matched_sid = "if_matched_sid";

    char *xml_same_source_ip = "same_source_ip";
    char *xml_same_src_port = "same_src_port";
    char *xml_same_dst_port = "same_dst_port";
    char *xml_same_user = "same_user";
    char *xml_same_location = "same_location";
    char *xml_same_id = "same_id";
    char *xml_dodiff = "check_diff";

    char *xml_different_url = "different_url";

    char *xml_notsame_source_ip = "not_same_source_ip";
    char *xml_notsame_user = "not_same_user";
    char *xml_notsame_agent = "not_same_agent";
    char *xml_notsame_id = "not_same_id";

    char *xml_options = "options";

    char *rulepath;

    int i;
    int default_timeframe = 360;

    /* If no directory in the rulefile, add the default */
    if ((strchr(rulefile, '/')) == NULL) {
        /* Build the rule file name + path */
        i = strlen(RULEPATH) + strlen(rulefile) + 2;
        rulepath = (char *)calloc(i, sizeof(char));
        if (!rulepath) {
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }
        snprintf(rulepath, i, "%s/%s", RULEPATH, rulefile);
    } else {
        os_strdup(rulefile, rulepath);
        debug1("%s is the rulefile", rulefile);
        debug1("Not modifing the rule path");
    }

    i = 0;

    /* Read the XML */
    if (OS_ReadXML(rulepath, &xml) < 0) {
        merror(XML_ERROR, ARGV0, rulepath, xml.err, xml.err_line);
        free(rulepath);
        return (-1);
    }
    debug2("%s: DEBUG: read xml for rule.", ARGV0);

    /* Apply any variable found */
    if (OS_ApplyVariables(&xml) != 0) {
        merror(XML_ERROR_VAR, ARGV0, rulepath, xml.err);
        return (-1);
    }
    debug2("%s: DEBUG: XML Variables applied.", ARGV0);

    /* Get the root elements */
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        merror(CONFIG_ERROR, ARGV0, rulepath);
        OS_ClearXML(&xml);
        return (-1);
    }

    /* Zero the rule memory -- not used anymore */
    free(rulepath);

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
                OS_ClearXML(&xml);
                return (-1);
            }
            if ((!node[i]->attributes) || (!node[i]->values) ||
                    (!node[i]->values[0]) || (!node[i]->attributes[0]) ||
                    (strcasecmp(node[i]->attributes[0], "name") != 0) ||
                    (node[i]->attributes[1])) {
                merror("rules_op: Invalid root element '%s'."
                       "Only the group name is allowed", node[i]->element);
                OS_ClearXML(&xml);
                return (-1);
            }
        } else {
            merror(XML_READ_ERROR, ARGV0);
            OS_ClearXML(&xml);
            return (-1);
        }
        i++;
    }

    /* Get the rules */
    i = 0;
    while (node[i]) {
        XML_NODE rule = NULL;

        int j = 0;

        /* Get all rules for a global group */
        rule = OS_GetElementsbyNode(&xml, node[i]);
        if (rule == NULL) {
            merror("%s: Group '%s' without any rule.",
                   ARGV0, node[i]->element);
            OS_ClearXML(&xml);
            return (-1);
        }

        while (rule[j]) {
            RuleInfo *config_ruleinfo = NULL;

            /* Check if the rule element is correct */
            if ((!rule[j]->element) ||
                    (strcasecmp(rule[j]->element, xml_rule) != 0)) {
                merror("%s: Invalid configuration. '%s' is not "
                       "a valid element.", ARGV0, rule[j]->element);
                OS_ClearXML(&xml);
                return (-1);
            }

            /* Check for the attributes of the rule */
            if ((!rule[j]->attributes) || (!rule[j]->values)) {
                merror("%s: Invalid rule '%d'. You must specify"
                       " an ID and a level at least.", ARGV0, j);
                OS_ClearXML(&xml);
                return (-1);
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
                    merror("%s: Invalid attribute for rule.", ARGV0);
                    OS_ClearXML(&xml);
                    return (-1);
                }

                if ((id == -1) || (level == -1)) {
                    merror("%s: No rule id or level specified for "
                           "rule '%d'.", ARGV0, j);
                    OS_ClearXML(&xml);
                    return (-1);
                }

                if (overwrite != 1 && doesRuleExist(id, NULL)) {
                    merror("%s: Duplicate rule ID:%d", ARGV0, id);
                    OS_ClearXML(&xml);
                    return (-1);
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

            /* Rule elements block */
            {
                int k = 0;
                int info_type = 0;
                int count_info_detail = 0;
                RuleInfoDetail *last_info_detail = NULL;
                char *regex = NULL;
                char *match = NULL;
                char *url = NULL;
                char *if_matched_regex = NULL;
                char *if_matched_group = NULL;
                char *user = NULL;
                char *id = NULL;
                char *srcport = NULL;
                char *dstport = NULL;
                char *status = NULL;
                char *hostname = NULL;
                char *extra_data = NULL;
                char *program_name = NULL;

                XML_NODE rule_opt = NULL;
                rule_opt =  OS_GetElementsbyNode(&xml, rule[j]);
                if (rule_opt == NULL) {
                    merror("%s: Rule '%d' without any option. "
                           "It may lead to false positives and some "
                           "other problems for the system. Exiting.",
                           ARGV0, config_ruleinfo->sigid);
                    OS_ClearXML(&xml);
                    return (-1);
                }

                while (rule_opt[k]) {
                    if ((!rule_opt[k]->element) || (!rule_opt[k]->content)) {
                        break;
                    } else if (strcasecmp(rule_opt[k]->element, xml_regex) == 0) {
                        regex =
                            loadmemory(regex,
                                       rule_opt[k]->content);
                    } else if (strcasecmp(rule_opt[k]->element, xml_match) == 0) {
                        match =
                            loadmemory(match,
                                       rule_opt[k]->content);
                    } else if (strcasecmp(rule_opt[k]->element, xml_decoded) == 0) {
                        config_ruleinfo->decoded_as =
                            getDecoderfromlist(rule_opt[k]->content);

                        if (config_ruleinfo->decoded_as == 0) {
                            merror("%s: Invalid decoder name: '%s'.",
                                   ARGV0, rule_opt[k]->content);
                            OS_ClearXML(&xml);
                            return (-1);
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
                        debug1("info_type = %d", info_type);

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
                            merror(INVALID_CONFIG, ARGV0,
                                   rule_opt[k]->element,
                                   rule_opt[k]->content);
                            return (-1);
                        }

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_week_day) == 0) {
                        config_ruleinfo->week_day =
                            OS_IsValidDay(rule_opt[k]->content);

                        if (!config_ruleinfo->week_day) {
                            merror(INVALID_CONFIG, ARGV0,
                                   rule_opt[k]->element,
                                   rule_opt[k]->content);
                            return (-1);
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
                        int ip_s = 0;

                        /* Getting size of source ip list */
                        while (config_ruleinfo->srcip &&
                                config_ruleinfo->srcip[ip_s]) {
                            ip_s++;
                        }

                        config_ruleinfo->srcip =
                            realloc(config_ruleinfo->srcip,
                                    (ip_s + 2) * sizeof(os_ip *));


                        /* Allocating memory for the individual entries */
                        os_calloc(1, sizeof(os_ip),
                                  config_ruleinfo->srcip[ip_s]);
                        config_ruleinfo->srcip[ip_s + 1] = NULL;


                        /* Checking if the ip is valid */
                        if (!OS_IsValidIP(rule_opt[k]->content,
                                          config_ruleinfo->srcip[ip_s])) {
                            merror(INVALID_IP, ARGV0, rule_opt[k]->content);
                            return (-1);
                        }

                        if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                            config_ruleinfo->alert_opts |= DO_PACKETINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_dstip) == 0) {
                        int ip_s = 0;

                        /* Getting size of source ip list */
                        while (config_ruleinfo->dstip &&
                                config_ruleinfo->dstip[ip_s]) {
                            ip_s++;
                        }

                        config_ruleinfo->dstip =
                            realloc(config_ruleinfo->dstip,
                                    (ip_s + 2) * sizeof(os_ip *));


                        /* Allocating memory for the individual entries */
                        os_calloc(1, sizeof(os_ip),
                                  config_ruleinfo->dstip[ip_s]);
                        config_ruleinfo->dstip[ip_s + 1] = NULL;


                        /* Checking if the ip is valid */
                        if (!OS_IsValidIP(rule_opt[k]->content,
                                          config_ruleinfo->dstip[ip_s])) {
                            merror(INVALID_IP, ARGV0, rule_opt[k]->content);
                            return (-1);
                        }

                        if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                            config_ruleinfo->alert_opts |= DO_PACKETINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_user) == 0) {
                        user =
                            loadmemory(user,
                                       rule_opt[k]->content);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_id) == 0) {
                        id =
                            loadmemory(id,
                                       rule_opt[k]->content);
                    } else if (strcasecmp(rule_opt[k]->element, xml_srcport) == 0) {
                        srcport =
                            loadmemory(srcport,
                                       rule_opt[k]->content);
                        if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                            config_ruleinfo->alert_opts |= DO_PACKETINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_dstport) == 0) {
                        dstport =
                            loadmemory(dstport,
                                       rule_opt[k]->content);

                        if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                            config_ruleinfo->alert_opts |= DO_PACKETINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_status) == 0) {
                        status =
                            loadmemory(status,
                                       rule_opt[k]->content);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_hostname) == 0) {
                        hostname =
                            loadmemory(hostname,
                                       rule_opt[k]->content);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_data) == 0) {
                        extra_data =
                            loadmemory(extra_data,
                                       rule_opt[k]->content);

                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_program_name) == 0) {
                        program_name =
                            loadmemory(program_name,
                                       rule_opt[k]->content);
                    } else if (strcasecmp(rule_opt[k]->element, xml_action) == 0) {
                        config_ruleinfo->action =
                            loadmemory(config_ruleinfo->action,
                                       rule_opt[k]->content);
                    } else if (strcasecmp(rule_opt[k]->element, xml_list) == 0) {
                        debug1("-> %s == %s", rule_opt[k]->element, xml_list);
                        if (rule_opt[k]->attributes && rule_opt[k]->values && rule_opt[k]->content) {
                            int list_att_num = 0;
                            int rule_type = 0;
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
                                        merror(INVALID_CONFIG, ARGV0,
                                               rule_opt[k]->element,
                                               rule_opt[k]->content);
                                        merror("%s: List match lookup=\"%s\" is not valid.",
                                               ARGV0, rule_opt[k]->values[list_att_num]);
                                        return (-1);
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
                                    } else {
                                        merror(INVALID_CONFIG, ARGV0,
                                               rule_opt[k]->element,
                                               rule_opt[k]->content);
                                        merror("%s: List match field=\"%s\" is not valid.",
                                               ARGV0, rule_opt[k]->values[list_att_num]);
                                        return (-1);
                                    }
                                } else if (strcasecmp(rule_opt[k]->attributes[list_att_num], xml_list_cvalue) == 0) {
                                    os_calloc(1, sizeof(OSMatch), matcher);
                                    if (!OSMatch_Compile(rule_opt[k]->values[list_att_num], matcher, 0)) {
                                        merror(INVALID_CONFIG, ARGV0,
                                               rule_opt[k]->element,
                                               rule_opt[k]->content);
                                        merror(REGEX_COMPILE,
                                               ARGV0,
                                               rule_opt[k]->values[list_att_num],
                                               matcher->error);
                                        return (-1);
                                    }
                                } else {
                                    merror("%s:List feild=\"%s\" is not valid", ARGV0,
                                           rule_opt[k]->values[list_att_num]);
                                    merror(INVALID_CONFIG, ARGV0,
                                           rule_opt[k]->element, rule_opt[k]->content);
                                    return (-1);
                                }
                                list_att_num++;
                            }
                            if (rule_type == 0) {
                                merror("%s:List requires the field=\"\" Attrubute", ARGV0);
                                merror(INVALID_CONFIG, ARGV0,
                                       rule_opt[k]->element, rule_opt[k]->content);
                                return (-1);
                            }

                            /* Wow it's all ready - this seems too complex to get to this point */
                            config_ruleinfo->lists = OS_AddListRule(config_ruleinfo->lists,
                                                                    lookup_type,
                                                                    rule_type,
                                                                    rule_opt[k]->content,
                                                                    matcher);
                            if (config_ruleinfo->lists == NULL) {
                                merror("%s: List error: Could not load %s", ARGV0, rule_opt[k]->content);
                                return (-1);
                            }
                        } else {
                            merror("%s:List must have a correctly formatted feild attribute",
                                   ARGV0);
                            merror(INVALID_CONFIG,
                                   ARGV0,
                                   rule_opt[k]->element,
                                   rule_opt[k]->content);
                            return (-1);
                        }
                        /* xml_list eval is done */
                    } else if (strcasecmp(rule_opt[k]->element, xml_url) == 0) {
                        url =
                            loadmemory(url,
                                       rule_opt[k]->content);
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
                            merror("%s: ERROR: Compiled rule not found: '%s'",
                                   ARGV0, rule_opt[k]->content);
                            merror(INVALID_CONFIG, ARGV0,
                                   rule_opt[k]->element, rule_opt[k]->content);
                            return (-1);

                        }

                        config_ruleinfo->compiled_rule = compiled_rules_list[it_id];
                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }
                    }

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
                            merror(INVALID_CAT, ARGV0, rule_opt[k]->content);
                            return (-1);
                        }
                    } else if (strcasecmp(rule_opt[k]->element, xml_if_sid) == 0) {
                        config_ruleinfo->if_sid =
                            loadmemory(config_ruleinfo->if_sid,
                                       rule_opt[k]->content);
                    } else if (strcasecmp(rule_opt[k]->element, xml_if_level) == 0) {
                        if (!OS_StrIsNum(rule_opt[k]->content)) {
                            merror(INVALID_CONFIG, ARGV0,
                                   "if_level",
                                   rule_opt[k]->content);
                            return (-1);
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
                            merror(INVALID_CONFIG, ARGV0,
                                   "if_matched_sid",
                                   rule_opt[k]->content);
                            return (-1);
                        }
                        config_ruleinfo->if_matched_sid =
                            atoi(rule_opt[k]->content);

                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_source_ip) == 0) {
                        config_ruleinfo->context_opts |= SAME_SRCIP;
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_src_port) == 0) {
                        config_ruleinfo->context_opts |= SAME_SRCPORT;

                        if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_dodiff) == 0) {
                        config_ruleinfo->context = 1;
                        config_ruleinfo->context_opts |= SAME_DODIFF;
                        if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_dst_port) == 0) {
                        config_ruleinfo->context_opts |= SAME_DSTPORT;

                        if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_notsame_source_ip) == 0) {
                        config_ruleinfo->context_opts &= NOT_SAME_SRCIP;
                    } else if (strcmp(rule_opt[k]->element, xml_same_id) == 0) {
                        config_ruleinfo->context_opts |= SAME_ID;
                    } else if (strcmp(rule_opt[k]->element,
                                      xml_different_url) == 0) {
                        config_ruleinfo->context_opts |= DIFFERENT_URL;

                        if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                        }
                    } else if (strcmp(rule_opt[k]->element, xml_notsame_id) == 0) {
                        config_ruleinfo->context_opts &= NOT_SAME_ID;
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_fts) == 0) {
                        config_ruleinfo->alert_opts |= DO_FTS;
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_user) == 0) {
                        config_ruleinfo->context_opts |= SAME_USER;

                        if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_notsame_user) == 0) {
                        config_ruleinfo->context_opts &= NOT_SAME_USER;
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_same_location) == 0) {
                        config_ruleinfo->context_opts |= SAME_LOCATION;
                        if (!(config_ruleinfo->alert_opts & SAME_EXTRAINFO)) {
                            config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_notsame_agent) == 0) {
                        config_ruleinfo->context_opts &= NOT_SAME_AGENT;
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
                        } else {
                            merror(XML_VALUEERR, ARGV0, xml_options,
                                   rule_opt[k]->content);

                            merror("%s: Invalid option '%s' for "
                                   "rule '%d'.", ARGV0, rule_opt[k]->element,
                                   config_ruleinfo->sigid);
                            OS_ClearXML(&xml);
                            return (-1);
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_ignore) == 0) {
                        if (strstr(rule_opt[k]->content, "user") != NULL) {
                            config_ruleinfo->ignore |= FTS_DSTUSER;
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
                            merror("%s: Wrong ignore option: '%s'",
                                   ARGV0,
                                   rule_opt[k]->content);
                            return (-1);
                        }
                    } else if (strcasecmp(rule_opt[k]->element,
                                          xml_check_if_ignored) == 0) {
                        if (strstr(rule_opt[k]->content, "user") != NULL) {
                            config_ruleinfo->ckignore |= FTS_DSTUSER;
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
                            config_ruleinfo->ignore |= FTS_DATA;
                        }
                        if (strstr(rule_opt[k]->content, "name") != NULL) {
                            config_ruleinfo->ckignore |= FTS_NAME;

                        }
                        if (!config_ruleinfo->ckignore) {
                            merror("%s: Wrong check_if_ignored option: '%s'",
                                   ARGV0,
                                   rule_opt[k]->content);
                            return (-1);
                        }
                    } else {
                        merror("%s: Invalid option '%s' for "
                               "rule '%d'.", ARGV0, rule_opt[k]->element,
                               config_ruleinfo->sigid);
                        OS_ClearXML(&xml);
                        return (-1);
                    }
                    k++;
                }

                /* Check for valid use of frequency */
                if ((config_ruleinfo->context_opts ||
                        config_ruleinfo->frequency) &&
                        !config_ruleinfo->context) {
                    merror("%s: Invalid use of frequency/context options. "
                           "Missing if_matched on rule '%d'.",
                           ARGV0, config_ruleinfo->sigid);
                    OS_ClearXML(&xml);
                    return (-1);
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
                    os_calloc(1, sizeof(OSRegex), config_ruleinfo->regex);
                    if (!OSRegex_Compile(regex, config_ruleinfo->regex, 0)) {
                        merror(REGEX_COMPILE, ARGV0, regex,
                               config_ruleinfo->regex->error);
                        return (-1);
                    }
                    free(regex);
                    regex = NULL;
                }

                /* Add in match */
                if (match) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->match);
                    if (!OSMatch_Compile(match, config_ruleinfo->match, 0)) {
                        merror(REGEX_COMPILE, ARGV0, match,
                               config_ruleinfo->match->error);
                        return (-1);
                    }
                    free(match);
                    match = NULL;
                }

                /* Add in id */
                if (id) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->id);
                    if (!OSMatch_Compile(id, config_ruleinfo->id, 0)) {
                        merror(REGEX_COMPILE, ARGV0, id,
                               config_ruleinfo->id->error);
                        return (-1);
                    }
                    free(id);
                    id = NULL;
                }

                /* Add srcport */
                if (srcport) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->srcport);
                    if (!OSMatch_Compile(srcport, config_ruleinfo->srcport, 0)) {
                        merror(REGEX_COMPILE, ARGV0, srcport,
                               config_ruleinfo->id->error);
                        return (-1);
                    }
                    free(srcport);
                    srcport = NULL;
                }

                /* Add dstport */
                if (dstport) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->dstport);
                    if (!OSMatch_Compile(dstport, config_ruleinfo->dstport, 0)) {
                        merror(REGEX_COMPILE, ARGV0, dstport,
                               config_ruleinfo->id->error);
                        return (-1);
                    }
                    free(dstport);
                    dstport = NULL;
                }

                /* Add in status */
                if (status) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->status);
                    if (!OSMatch_Compile(status, config_ruleinfo->status, 0)) {
                        merror(REGEX_COMPILE, ARGV0, status,
                               config_ruleinfo->status->error);
                        return (-1);
                    }
                    free(status);
                    status = NULL;
                }

                /* Add in hostname */
                if (hostname) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->hostname);
                    if (!OSMatch_Compile(hostname, config_ruleinfo->hostname, 0)) {
                        merror(REGEX_COMPILE, ARGV0, hostname,
                               config_ruleinfo->hostname->error);
                        return (-1);
                    }
                    free(hostname);
                    hostname = NULL;
                }

                /* Add extra data */
                if (extra_data) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->extra_data);
                    if (!OSMatch_Compile(extra_data,
                                         config_ruleinfo->extra_data, 0)) {
                        merror(REGEX_COMPILE, ARGV0, extra_data,
                               config_ruleinfo->extra_data->error);
                        return (-1);
                    }
                    free(extra_data);
                    extra_data = NULL;
                }

                /* Add in program name */
                if (program_name) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->program_name);
                    if (!OSMatch_Compile(program_name,
                                         config_ruleinfo->program_name, 0)) {
                        merror(REGEX_COMPILE, ARGV0, program_name,
                               config_ruleinfo->program_name->error);
                        return (-1);
                    }
                    free(program_name);
                    program_name = NULL;
                }

                /* Add in user */
                if (user) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->user);
                    if (!OSMatch_Compile(user, config_ruleinfo->user, 0)) {
                        merror(REGEX_COMPILE, ARGV0, user,
                               config_ruleinfo->user->error);
                        return (-1);
                    }
                    free(user);
                    user = NULL;
                }

                /* Add in URL */
                if (url) {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->url);
                    if (!OSMatch_Compile(url, config_ruleinfo->url, 0)) {
                        merror(REGEX_COMPILE, ARGV0, url,
                               config_ruleinfo->url->error);
                        return (-1);
                    }
                    free(url);
                    url = NULL;
                }

                /* Add matched_group */
                if (if_matched_group) {
                    os_calloc(1, sizeof(OSMatch),
                              config_ruleinfo->if_matched_group);

                    if (!OSMatch_Compile(if_matched_group,
                                         config_ruleinfo->if_matched_group,
                                         0)) {
                        merror(REGEX_COMPILE, ARGV0, if_matched_group,
                               config_ruleinfo->if_matched_group->error);
                        return (-1);
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
                        merror(REGEX_COMPILE, ARGV0, if_matched_regex,
                               config_ruleinfo->if_matched_regex->error);
                        return (-1);
                    }
                    free(if_matched_regex);
                    if_matched_regex = NULL;
                }
            } /* end of elements block */

            /* Assign an active response to the rule */
            Rule_AddAR(config_ruleinfo);

            j++; /* next rule */

            /* Create the last_events if necessary */
            if (config_ruleinfo->context) {
                int ii = 0;
                os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *),
                          config_ruleinfo->last_events);

                /* Zero each entry */
                for (; ii <= MAX_LAST_EVENTS; ii++) {
                    config_ruleinfo->last_events[ii] = NULL;
                }
            }

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
                    merror("%s: Overwrite rule '%d' not found.",
                           ARGV0, config_ruleinfo->sigid);
                    OS_ClearXML(&xml);
                    return (-1);
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
                config_ruleinfo->event_search =
                    (void *)Search_LastSids;

                /* Mark rules that match this id */
                OS_MarkID(NULL, config_ruleinfo);
            }

            /* Mark the rules that match if_matched_group */
            else if (config_ruleinfo->if_matched_group) {
                /* Create list */
                config_ruleinfo->group_search = OSList_Create();
                if (!config_ruleinfo->group_search) {
                    ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
                }

                /* Mark rules that match this group */
                OS_MarkGroup(NULL, config_ruleinfo);

                /* Set function pointer */
                config_ruleinfo->event_search =
                    (void *)Search_LastGroups;
            } else if (config_ruleinfo->context) {
                if ((config_ruleinfo->context == 1) &&
                        (config_ruleinfo->context_opts & SAME_DODIFF)) {
                    config_ruleinfo->context = 0;
                } else {
                    config_ruleinfo->event_search =
                        (void *)Search_LastEvents;
                }
            }

        } /* while(rule[j]) */
        OS_ClearNode(rule);
        i++;

    } /* while (node[i]) */

    /* Clean global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

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
    return (0);
}

/* Allocate memory at "*at" and copy *str to it.
 * If *at already exist, realloc the memory and cat str on it.
 * Returns the new string
 */
char *loadmemory(char *at, char *str)
{
    if (at == NULL) {
        int strsize = 0;
        if ((strsize = strlen(str)) < OS_SIZE_2048) {
            at = calloc(strsize + 1, sizeof(char));
            if (at == NULL) {
                merror(MEM_ERROR, ARGV0, errno, strerror(errno));
                return (NULL);
            }
            strncpy(at, str, strsize);
            return (at);
        } else {
            merror(SIZE_ERROR, ARGV0, str);
            return (NULL);
        }
    } else {
        /* at is not null. Need to reallocate its memory and copy str to it */
        int strsize = strlen(str);
        int atsize = strlen(at);
        int finalsize = atsize + strsize + 1;

        if ((atsize > OS_SIZE_2048) || (strsize > OS_SIZE_2048)) {
            merror(SIZE_ERROR, ARGV0, str);
            return (NULL);
        }

        at = realloc(at, (finalsize) * sizeof(char));

        if (at == NULL) {
            merror(MEM_ERROR, ARGV0, errno, strerror(errno));
            return (NULL);
        }

        strncat(at, str, strsize);
        at[finalsize - 1] = '\0';

        return (at);
    }
    return (NULL);
}

RuleInfoDetail *zeroinfodetails(int type, char *data)
{
    RuleInfoDetail *info_details_pt = NULL;

    info_details_pt = (RuleInfoDetail *)calloc(1, sizeof(RuleInfoDetail));

    if (info_details_pt == NULL) {
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
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
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
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
    if (ruleinfo_pt->frequency > _max_freq) {
        _max_freq = ruleinfo_pt->frequency;
    }
    ruleinfo_pt->ignore_time = ignore_time;
    ruleinfo_pt->timeframe = timeframe;
    ruleinfo_pt->time_ignored = 0;

    ruleinfo_pt->context_opts = 0;
    ruleinfo_pt->alert_opts = 0;
    ruleinfo_pt->ignore = 0;
    ruleinfo_pt->ckignore = 0;

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

    /* Zero last matched events */
    ruleinfo_pt->__frequency = 0;
    ruleinfo_pt->last_events = NULL;

    /* Zeroing the list of previous matches */
    ruleinfo_pt->sid_prev_matched = NULL;
    ruleinfo_pt->group_prev_matched = NULL;

    ruleinfo_pt->sid_search = NULL;
    ruleinfo_pt->group_search = NULL;

    ruleinfo_pt->event_search = NULL;
    ruleinfo_pt->compiled_rule = NULL;
    ruleinfo_pt->lists = NULL;

    return (ruleinfo_pt);
}

int get_info_attributes(char **attributes, char **values)
{
    char *xml_type = "type";
    int k = 0;

    if (!attributes) {
        return (RULEINFODETAIL_TEXT);
    }

    while (attributes[k]) {
        if (!values[k]) {
            merror("rules_op: Entry info type \"%s\" does not have a value",
                   attributes[k]);
            return (-1);
        } else if (strcasecmp(attributes[k], xml_type) == 0) {
            if (strcmp(values[k], "text") == 0) {
                return (RULEINFODETAIL_TEXT);
            } else if (strcmp(values[k], "link") == 0) {
                return (RULEINFODETAIL_LINK);
            } else if (strcmp(values[k], "cve") == 0) {
                return (RULEINFODETAIL_CVE);
            } else if (strcmp(values[k], "osvdb") == 0) {
                return (RULEINFODETAIL_OSVDB);
            }
        }
    }
    return (RULEINFODETAIL_TEXT);
}

/* Get the attributes */
int getattributes(char **attributes, char **values,
                  int *id, int *level,
                  int *maxsize, int *timeframe,
                  int *frequency, int *accuracy,
                  int *noalert, int *ignore_time, int *overwrite)
{
    int k = 0;

    char *xml_id = "id";
    char *xml_level = "level";
    char *xml_maxsize = "maxsize";
    char *xml_timeframe = "timeframe";
    char *xml_frequency = "frequency";
    char *xml_accuracy = "accuracy";
    char *xml_noalert = "noalert";
    char *xml_ignore_time = "ignore";
    char *xml_overwrite = "overwrite";

    /* Get attributes */
    while (attributes[k]) {
        if (!values[k]) {
            merror("rules_op: Attribute \"%s\" without value."
                   , attributes[k]);
            return (-1);
        }
        /* Get rule id */
        else if (strcasecmp(attributes[k], xml_id) == 0) {
            if (OS_StrIsNum(values[k])) {
                sscanf(values[k], "%6d", id);
            } else {
                merror("rules_op: Invalid rule id: %s. "
                       "Must be integer" ,
                       values[k]);
                return (-1);
            }
        }
        /* Get level */
        else if (strcasecmp(attributes[k], xml_level) == 0) {
            if (OS_StrIsNum(values[k])) {
                sscanf(values[k], "%4d", level);
            } else {
                merror("rules_op: Invalid level: %s. "
                       "Must be integer" ,
                       values[k]);
                return (-1);
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
                       "Must be integer" ,
                       values[k]);
                return (-1);
            }
        }
        /* Get frequency */
        else if (strcasecmp(attributes[k], xml_frequency) == 0) {
            if (OS_StrIsNum(values[k])) {
                sscanf(values[k], "%4d", frequency);
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
                       "Must be integer" ,
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
                   "Only id, level, maxsize, accuracy, noalert and timeframe "
                   "are allowed.", attributes[k]);
            return (-1);
        }
        k++;
    }
    return (0);
}

/* Bind active responses to a rule */
void Rule_AddAR(RuleInfo *rule_config)
{
    int rule_ar_size = 0;
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

            rule_config->ar = realloc(rule_config->ar,
                                      (rule_ar_size + 1)
                                      * sizeof(active_response *));

            /* Always set the last node to NULL */
            rule_config->ar[rule_ar_size - 1] = my_ar;
            rule_config->ar[rule_ar_size] = NULL;
        }

        my_ars_node = OSList_GetNextNode(active_responses);
    }

    return;
}

void printRuleinfo(RuleInfo *rule, int node)
{
    debug1("%d : rule:%d, level %d, timeout: %d",
           node,
           rule->sigid,
           rule->level,
           rule->ignore_time);
}

/* Add rule to hash */
int AddHash_Rule(RuleNode *node)
{
    while (node) {
        char _id_key[15];
        char *id_key;

        snprintf(_id_key, 14, "%d", node->ruleinfo->sigid);
        os_strdup(_id_key, id_key);


        /* Add key to hash */
        OSHash_Add(Config.g_rules_hash, id_key, node->ruleinfo);
        if (node->child) {
            AddHash_Rule(node->child);
        }

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
int doesRuleExist(int sid, RuleNode *r_node)
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

