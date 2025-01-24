/* Copyright (C) 2015, Wazuh Inc.
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


/* Read the log rules */
int OS_ReadXMLRules(const char *rulefile,
                    void *(*ruleact_function)(RuleInfo *rule_1, void *data_1),
                    void *data)
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
         *extra_data = NULL, *program_name = NULL, *location = NULL;

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
    const char *xml_mitre_tactic_id = "tacticID";
    const char *xml_mitre_technique_id = "techniqueID";

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
            int mitre_size_deprecated = 0;
            bool mitre_deprecated = false;
            bool mitre_new_format = false;

            config_ruleinfo = NULL;

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
                    regex =
                        os_LoadString(regex,
                                      rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element, xml_match) == 0) {
                    match =
                        os_LoadString(match,
                                      rule_opt[k]->content);
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
                        merror(INVALID_DAY, rule_opt[k]->content);
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
                    size_t ip_s = 0;

                    /* Get size of source IP list */
                    while (config_ruleinfo->srcip &&
                            config_ruleinfo->srcip[ip_s]) {
                        ip_s++;
                    }

                    config_ruleinfo->srcip = (os_ip **)
                                             realloc(config_ruleinfo->srcip,
                                                     (ip_s + 2) * sizeof(os_ip *));

                    if(config_ruleinfo->srcip == NULL) {
                        merror_exit(MEM_ERROR, errno, strerror(errno));
                    }

                    /* Allocate memory for the individual entries */
                    os_calloc(1, sizeof(os_ip),
                              config_ruleinfo->srcip[ip_s]);
                    config_ruleinfo->srcip[ip_s + 1] = NULL;

                    /* Check if the IP is valid */
                    if (!OS_IsValidIP(rule_opt[k]->content,
                                      config_ruleinfo->srcip[ip_s])) {
                        merror(INVALID_IP, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element, xml_dstip) == 0) {
                    size_t ip_s = 0;

                    /* Get size of destination IP list */
                    while (config_ruleinfo->dstip &&
                            config_ruleinfo->dstip[ip_s]) {
                        ip_s++;
                    }

                    config_ruleinfo->dstip = (os_ip **)
                                             realloc(config_ruleinfo->dstip,
                                                     (ip_s + 2) * sizeof(os_ip *));
                    if(!config_ruleinfo->dstip) {
                        merror_exit(MEM_ERROR, errno, strerror(errno));
                    }

                    /* Allocate memory for the individual entries */
                    os_calloc(1, sizeof(os_ip),
                              config_ruleinfo->dstip[ip_s]);
                    config_ruleinfo->dstip[ip_s + 1] = NULL;

                    /* Checking if the IP is valid */
                    if (!OS_IsValidIP(rule_opt[k]->content,
                                      config_ruleinfo->dstip[ip_s])) {
                        merror(INVALID_IP, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element, xml_user) == 0) {
                    user = os_LoadString(user, rule_opt[k]->content);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element, xml_id) == 0) {
                    id = os_LoadString(id, rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element, xml_srcport) == 0) {
                    srcport = os_LoadString(srcport, rule_opt[k]->content);

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element, xml_dstport) == 0) {
                    dstport = os_LoadString(dstport, rule_opt[k]->content);

                    if (!(config_ruleinfo->alert_opts & DO_PACKETINFO)) {
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element, xml_status) == 0) {
                    status = os_LoadString(status, rule_opt[k]->content);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element, xml_hostname) == 0) {
                    hostname = os_LoadString(hostname, rule_opt[k]->content);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element, xml_extra_data) == 0) {
                    extra_data = os_LoadString(extra_data, rule_opt[k]->content);

                    if (!(config_ruleinfo->alert_opts & DO_EXTRAINFO)) {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_program_name) == 0) {
                    program_name = os_LoadString(program_name,
                                                 rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_location) == 0) {
                    location = os_LoadString(location,
                                                 rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element, xml_action) == 0) {
                    config_ruleinfo->action =
                        os_LoadString(config_ruleinfo->action,
                                      rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element, xml_url) == 0) {
                    url = os_LoadString(url, rule_opt[k]->content);
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
                    config_ruleinfo->if_sid =
                        os_LoadString(config_ruleinfo->if_sid,
                                      rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element, xml_if_level) == 0) {
                    if (!OS_StrIsNum(rule_opt[k]->content)) {
                        merror(INVALID_CONFIG, xml_if_level, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }

                    config_ruleinfo->if_level =
                        os_LoadString(config_ruleinfo->if_level,
                                      rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element, xml_if_group) == 0) {
                    config_ruleinfo->if_group =
                        os_LoadString(config_ruleinfo->if_group,
                                      rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_if_matched_regex) == 0) {
                    config_ruleinfo->context = 1;
                    if_matched_regex =
                        os_LoadString(if_matched_regex,
                                      rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_if_matched_group) == 0) {
                    config_ruleinfo->context = 1;
                    if_matched_group =
                        os_LoadString(if_matched_group,
                                      rule_opt[k]->content);
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_if_matched_sid) == 0) {
                    config_ruleinfo->context = 1;
                    if (!OS_StrIsNum(rule_opt[k]->content)) {
                        merror(INVALID_CONFIG, rule_opt[k]->element, rule_opt[k]->content);
                        retval = -1;
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
                    } else if (strcmp("no_previous_output", rule_opt[k]->content) == 0) {
                        config_ruleinfo->alert_opts |= NO_PREVIOUS_OUTPUT;
                    } else {
                        merror(XML_VALUEERR, xml_options, rule_opt[k]->content);

                        merror(INVALID_ELEMENT, rule_opt[k]->element, rule_opt[k]->content);
                        retval = -1;
                        goto cleanup;
                    }
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_ignore) == 0) {
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
                } else if (strcasecmp(rule_opt[k]->element,
                                      xml_check_if_ignored) == 0) {
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

                    char *tactic_id = NULL;
                    char *technique_id = NULL;
                    bool id_flag = FALSE;
                    bool id_tactic_flag = FALSE;
                    bool id_technique_flag = FALSE;
                    bool failure = FALSE;
                    int id_tactic_n = 0;
                    int id_technique_n = 0;
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
                            failure = TRUE;
                            break;
                        } else if (strcasecmp(mitre_opt[ind]->element, xml_mitre_id) == 0) {
                            if (strlen(mitre_opt[ind]->content) == 0) {
                                mwarn("No Mitre Technique ID found for rule '%d'",
                                    config_ruleinfo->sigid);
                                failure = TRUE;
                            } else {
                                id_flag = TRUE;
                            }
                        } else if (strcasecmp(mitre_opt[ind]->element, xml_mitre_tactic_id) == 0) {
                            if (strlen(mitre_opt[ind]->content) == 0) {
                                mwarn("No Mitre Tactic ID found for rule '%d'",
                                    config_ruleinfo->sigid);
                                failure = TRUE;
                            } else {
                                id_tactic_flag = TRUE;
                                id_tactic_n++;
                            }
                        } else if (strcasecmp(mitre_opt[ind]->element, xml_mitre_technique_id) == 0) {
                            if (strlen(mitre_opt[ind]->content) == 0) {
                                mwarn("No Mitre Technique ID found for rule '%d'",
                                    config_ruleinfo->sigid);
                                failure = TRUE;
                            } else {
                                id_technique_flag = TRUE;
                                id_technique_n++;
                            }
                        } else {
                            mwarn("Invalid option '%s' for rule '%d'", mitre_opt[ind]->element,
                                config_ruleinfo->sigid);
                            failure = TRUE;
                        }
                    }

                    if(failure == FALSE) {
                        if(id_flag == TRUE) {
                            if(id_tactic_flag == TRUE || id_technique_flag == TRUE) {
                                mwarn("Rule '%d' combined old and new Mitre formats in the same block. The Mitre block will be discarded.",
                                        config_ruleinfo->sigid);
                                failure = TRUE;
                            } else {
                                if (mitre_new_format == TRUE) {
                                    mwarn("Rule '%d' combined old and new Mitre formats, the old Mitre Technique format will be discarded.",
                                        config_ruleinfo->sigid);
                                    free_strarray(config_ruleinfo->mitre_id);
                                    config_ruleinfo->mitre_id = NULL;
                                    failure = TRUE;
                                } else {
                                    mitre_deprecated = TRUE;
                                    mdebug1("You are using a deprecated Mitre format in rule '%d'",
                                        config_ruleinfo->sigid);
                                }
                            }
                        } else {
                            if(id_tactic_flag == TRUE && id_technique_flag == TRUE){
                                if(id_tactic_n > 1 || id_technique_n > 1) {
                                    mwarn("In rule '%d' is not allowed to join more than one Mitre techniqueID or tacticID in the same block. The Mitre block will be discarded.",
                                        config_ruleinfo->sigid);
                                    failure = TRUE;
                                } else {
                                    mitre_new_format = TRUE;
                                    if (mitre_deprecated == TRUE) {
                                        mwarn("Rule '%d' combined old and new Mitre formats, the old Mitre Technique format will be discarded.",
                                            config_ruleinfo->sigid);
                                        free_strarray(config_ruleinfo->mitre_id);
                                        config_ruleinfo->mitre_id = NULL;
                                        mitre_deprecated = FALSE;
                                    }
                                }
                            }
                            else if(id_tactic_flag == FALSE && id_technique_flag == TRUE) {
                                mwarn("Mitre tacticID should be defined in rule '%d'",
                                    config_ruleinfo->sigid);
                                failure = TRUE;
                            }
                            else if(id_tactic_flag == TRUE && id_technique_flag == FALSE) {
                                mwarn("Mitre techniqueID should be defined in rule '%d'",
                                    config_ruleinfo->sigid);
                                failure = TRUE;
                            }
                        }
                    }

                    if(failure == FALSE) {
                        for (ind = 0; mitre_opt[ind] != NULL; ind++) {
                            if (strcasecmp(mitre_opt[ind]->element, xml_mitre_id) == 0) {
                                bool inarray = FALSE;
                                for (l = 0; l < mitre_size_deprecated; l++) {
                                    if (strcmp(config_ruleinfo->mitre_id[l], mitre_opt[ind]->content) == 0) {
                                        inarray = TRUE;
                                    }
                                }
                                if (!inarray) {
                                    os_realloc(config_ruleinfo->mitre_id, (mitre_size_deprecated + 2) * sizeof(char *),
                                            config_ruleinfo->mitre_id);
                                    os_strdup(mitre_opt[ind]->content, config_ruleinfo->mitre_id[mitre_size_deprecated]);
                                    config_ruleinfo->mitre_id[mitre_size_deprecated + 1] = NULL;
                                    mitre_size_deprecated++;
                                }
                            } else if (strcasecmp(mitre_opt[ind]->element, xml_mitre_tactic_id) == 0) {
                                os_strdup(mitre_opt[ind]->content, tactic_id);

                            } else if (strcasecmp(mitre_opt[ind]->element, xml_mitre_technique_id) == 0) {
                                os_strdup(mitre_opt[ind]->content, technique_id);
                            }
                        }
                        if(tactic_id && technique_id) {
                            bool inarray = FALSE;
                            for (l = 0; l < mitre_size; l++) {
                                if (strcmp(config_ruleinfo->mitre_technique_id[l], technique_id) == 0 &&
                                    strcmp(config_ruleinfo->mitre_tactic_id[l], tactic_id) == 0) {
                                    inarray = TRUE;
                                }
                            }
                            if (!inarray) {
                                os_realloc(config_ruleinfo->mitre_tactic_id, (mitre_size + 2) * sizeof(char *),
                                        config_ruleinfo->mitre_tactic_id);
                                os_strdup(tactic_id, config_ruleinfo->mitre_tactic_id[mitre_size]);
                                    config_ruleinfo->mitre_tactic_id[mitre_size + 1] = NULL;

                                os_realloc(config_ruleinfo->mitre_technique_id, (mitre_size + 2) * sizeof(char *),
                                            config_ruleinfo->mitre_technique_id);
                                os_strdup(technique_id, config_ruleinfo->mitre_technique_id[mitre_size]);
                                    config_ruleinfo->mitre_technique_id[mitre_size + 1] = NULL;
                                mitre_size++;
                            }
                        }
                        os_free(tactic_id);
                        os_free(technique_id);
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
                    config_ruleinfo->different_field ||
                    config_ruleinfo->frequency) &&
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
                os_calloc(1, sizeof(OSRegex), config_ruleinfo->regex);
                if (!OSRegex_Compile(regex, config_ruleinfo->regex, 0)) {
                    merror(REGEX_COMPILE, regex, config_ruleinfo->regex->error);
                    retval = -1;
                    goto cleanup;
                }
                free(regex);
                regex = NULL;
            }

            /* Add match */
            if (match) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->match);
                if (!OSMatch_Compile(match, config_ruleinfo->match, 0)) {
                    merror(REGEX_COMPILE, match, config_ruleinfo->match->error);
                    retval = -1;
                    goto cleanup;
                }
                free(match);
                match = NULL;
            }

            /* Add id */
            if (id) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->id);
                if (!OSMatch_Compile(id, config_ruleinfo->id, 0)) {
                    merror(REGEX_COMPILE, id, config_ruleinfo->id->error);
                    retval = -1;
                    goto cleanup;
                }
                free(id);
                id = NULL;
            }

            /* Add srcport */
            if (srcport) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->srcport);
                if (!OSMatch_Compile(srcport, config_ruleinfo->srcport, 0)) {
                    merror(REGEX_COMPILE, srcport, config_ruleinfo->id->error);
                    retval = -1;
                    goto cleanup;
                }
                free(srcport);
                srcport = NULL;
            }

            /* Add dstport */
            if (dstport) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->dstport);
                if (!OSMatch_Compile(dstport, config_ruleinfo->dstport, 0)) {
                    merror(REGEX_COMPILE, dstport, config_ruleinfo->id->error);
                    retval = -1;
                    goto cleanup;
                }
                free(dstport);
                dstport = NULL;
            }

            /* Add status */
            if (status) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->status);
                if (!OSMatch_Compile(status, config_ruleinfo->status, 0)) {
                    merror(REGEX_COMPILE, status, config_ruleinfo->status->error);
                    retval = -1;
                    goto cleanup;
                }
                free(status);
                status = NULL;
            }

            /* Add hostname */
            if (hostname) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->hostname);
                if (!OSMatch_Compile(hostname, config_ruleinfo->hostname, 0)) {
                    merror(REGEX_COMPILE, hostname, config_ruleinfo->hostname->error);
                    retval = -1;
                    goto cleanup;
                }
                free(hostname);
                hostname = NULL;
            }

            /* Add extra data */
            if (extra_data) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->extra_data);
                if (!OSMatch_Compile(extra_data,
                                     config_ruleinfo->extra_data, 0)) {
                    merror(REGEX_COMPILE, extra_data, config_ruleinfo->extra_data->error);
                    retval = -1;
                    goto cleanup;
                }
                free(extra_data);
                extra_data = NULL;
            }

            /* Add in program name */
            if (program_name) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->program_name);
                if (!OSMatch_Compile(program_name,
                                     config_ruleinfo->program_name, 0)) {
                    merror(REGEX_COMPILE, program_name, config_ruleinfo->program_name->error);
                    retval = -1;
                    goto cleanup;
                }
                free(program_name);
                program_name = NULL;
            }

            /* Add user */
            if (user) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->user);
                if (!OSMatch_Compile(user, config_ruleinfo->user, 0)) {
                    merror(REGEX_COMPILE, user, config_ruleinfo->user->error);
                    retval = -1;
                    goto cleanup;
                }
                free(user);
                user = NULL;
            }

            /* Add URL */
            if (url) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->url);
                if (!OSMatch_Compile(url, config_ruleinfo->url, 0)) {
                    merror(REGEX_COMPILE, url, config_ruleinfo->url->error);
                    retval = -1;
                    goto cleanup;
                }
                free(url);
                url = NULL;
            }

            /* Add location */
            if (location) {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->location);
                if (!OSMatch_Compile(location, config_ruleinfo->location, 0)) {
                    merror(REGEX_COMPILE, location, config_ruleinfo->location->error);
                    retval = -1;
                    goto cleanup;
                }
                free(location);
                location = NULL;
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
            ruleact_function(config_ruleinfo, data);

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
            if (strcmp(values[k], "0") == 0) {
                ruleinfo_pt->alert_opts &= ~NO_ALERT;
            } else if (strcmp(values[k], "1") == 0) {
                ruleinfo_pt->alert_opts |= NO_ALERT;
            } else {
                mwarn("Invalid value for attribute '%s'", xml_noalert);
            }
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

    free(ruleinfo->group);
    free(ruleinfo->match);
    free(ruleinfo->regex);
    free(ruleinfo->day_time);
    free(ruleinfo->week_day);

    if (ruleinfo->srcip) {
        for (i = 0; ruleinfo->srcip[i]; i++) {
            w_free_os_ip(ruleinfo->srcip[i]);
        }

        free(ruleinfo->srcip);
    }

    if (ruleinfo->dstip) {
        for (i = 0; ruleinfo->dstip[i]; i++) {
            w_free_os_ip(ruleinfo->dstip[i]);
        }

        free(ruleinfo->dstip);
    }

    free(ruleinfo->srcport);
    free(ruleinfo->dstport);
    free(ruleinfo->user);
    free(ruleinfo->url);
    free(ruleinfo->id);
    free(ruleinfo->status);
    free(ruleinfo->hostname);
    free(ruleinfo->program_name);
    free(ruleinfo->location);
    free(ruleinfo->extra_data);
    free(ruleinfo->action);
    free(ruleinfo->comment);
    free(ruleinfo->info);
    free(ruleinfo->cve);
    free(ruleinfo->if_sid);
    free(ruleinfo->if_level);
    free(ruleinfo->if_group);

    if (ruleinfo->same_fields) {
        for (i = 0; ruleinfo->same_fields[i] != NULL; i++) {
            free(ruleinfo->same_fields[i]);
        }
        free(ruleinfo->same_fields);
    }

    if (ruleinfo->not_same_fields) {
        for (i = 0; ruleinfo->not_same_fields[i] != NULL; i++) {
            free(ruleinfo->not_same_fields[i]);
        }
        free(ruleinfo->not_same_fields);
    }

    free(ruleinfo);
}
