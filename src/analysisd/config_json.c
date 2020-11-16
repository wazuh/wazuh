/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifndef CONFIG_JSON_H
#define CONFIG_JSON_H

#include "config.h"


// Reads a linked list and fills a JSON array of objects.
void _getDecodersListJSON(OSDecoderNode *list, cJSON *array) {

    OSDecoderNode *node = NULL;
    int i;

    for (node=list;node->next;node = node->next) {
        cJSON *decoder = cJSON_CreateObject();

        cJSON_AddNumberToObject(decoder,"id",node->osdecoder->id);
        if (node->osdecoder->name) cJSON_AddStringToObject(decoder,"name",node->osdecoder->name);
        if (node->osdecoder->parent) cJSON_AddStringToObject(decoder,"parent",node->osdecoder->parent);
        if (node->osdecoder->ftscomment) cJSON_AddStringToObject(decoder,"ftscomment",node->osdecoder->ftscomment);
        if (Config.decoder_order_size && node->osdecoder->order) {
            cJSON *_list = cJSON_CreateArray();
            for (i=0;i<Config.decoder_order_size;i++) {
                if (!node->osdecoder->order[i]) {
                    continue;
                }
                else if (node->osdecoder->order[i] == DstUser_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("dstuser"));
                }
                else if (node->osdecoder->order[i] == SrcUser_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("srcuser"));
                }
                else if (node->osdecoder->order[i] == SrcIP_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("srcip"));
                }
                else if (node->osdecoder->order[i] == DstIP_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("dstip"));
                }
                else if (node->osdecoder->order[i] == SrcPort_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("srcport"));
                }
                else if (node->osdecoder->order[i] == DstPort_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("dstport"));
                }
                else if (node->osdecoder->order[i] == Protocol_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("protocol"));
                }
                else if (node->osdecoder->order[i] == Action_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("action"));
                }
                else if (node->osdecoder->order[i] == ID_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("id"));
                }
                else if (node->osdecoder->order[i] == Url_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("url"));
                }
                else if (node->osdecoder->order[i] == Data_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("data"));
                }
                else if (node->osdecoder->order[i] == Extra_Data_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("extra_data"));
                }
                else if (node->osdecoder->order[i] == Status_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("status"));
                }
                else if (node->osdecoder->order[i] == SystemName_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString("system_name"));
                }
                else if (node->osdecoder->order[i] == DynamicField_FP) {
                    cJSON_AddItemToArray(_list,cJSON_CreateString(node->osdecoder->fields[i]));
                }
            }
            cJSON_AddItemToObject(decoder,"order",_list);
        }

        if (node->child) {
            cJSON *children = cJSON_CreateArray();
            _getDecodersListJSON(node->child,children);
            cJSON_AddItemToObject(decoder,"children",children);
        }

        if (node->osdecoder->use_own_name) cJSON_AddStringToObject(decoder,"use_own_name","true"); else cJSON_AddStringToObject(decoder,"use_own_name","false");

        if (node->osdecoder->accumulate) cJSON_AddStringToObject(decoder,"accumulate","yes"); else cJSON_AddStringToObject(decoder,"accumulate","no");

        if (node->osdecoder->prematch) {
            cJSON * prematch = cJSON_CreateObject();
            cJSON_AddStringToObject(prematch, "pattern", w_expression_get_regex_pattern(node->osdecoder->prematch));
            cJSON_AddStringToObject(prematch, "type", w_expression_get_regex_type(node->osdecoder->prematch));
            cJSON_AddItemToObject(decoder, "prematch", prematch);
        }

        if (node->osdecoder->prematch_offset & AFTER_PARENT) cJSON_AddStringToObject(decoder,"prematch_offset","after_parent");

        if (node->osdecoder->regex) {
            cJSON * regex = cJSON_CreateObject();
            cJSON_AddStringToObject(regex, "pattern", w_expression_get_regex_pattern(node->osdecoder->regex));
            cJSON_AddStringToObject(regex, "type", w_expression_get_regex_type(node->osdecoder->regex));
            cJSON_AddItemToObject(decoder, "regex", regex);
        }

        if (node->osdecoder->regex_offset & AFTER_PARENT) cJSON_AddStringToObject(decoder,"regex_offset","after_parent");
        else if (node->osdecoder->regex_offset & AFTER_PREVREGEX) cJSON_AddStringToObject(decoder,"regex_offset","after_regex");
        else if (node->osdecoder->regex_offset & AFTER_PREMATCH) cJSON_AddStringToObject(decoder,"regex_offset","after_prematch");

        if (node->osdecoder->program_name) {
            cJSON * program_name = cJSON_CreateObject();
            cJSON_AddStringToObject(program_name, "pattern", w_expression_get_regex_pattern(node->osdecoder->program_name));
            cJSON_AddStringToObject(program_name, "type", w_expression_get_regex_type(node->osdecoder->program_name));
            cJSON_AddItemToObject(decoder, "program_name", program_name);
        }

        if (node->osdecoder->fts) {
            cJSON *_list = cJSON_CreateArray();
            if (node->osdecoder->fts & FTS_DSTUSER) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("dstuser"));
            } else if (node->osdecoder->fts & FTS_DSTUSER) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("user"));
            } else if (node->osdecoder->fts & FTS_SRCUSER) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("srcuser"));
            } else if (node->osdecoder->fts & FTS_SRCIP) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("srcip"));
            } else if (node->osdecoder->fts & FTS_DSTIP) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("dstip"));
            } else if (node->osdecoder->fts & FTS_ID) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("id"));
            } else if (node->osdecoder->fts & FTS_LOCATION) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("location"));
            } else if (node->osdecoder->fts & FTS_DATA) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("data"));
            } else if (node->osdecoder->fts & FTS_DATA) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("extra_data"));
            } else if (node->osdecoder->fts & FTS_SYSTEMNAME) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("system_name"));
            } else if (node->osdecoder->fts & FTS_NAME) {
                cJSON_AddItemToArray(_list,cJSON_CreateString("name"));
            } else if (node->osdecoder->fts & FTS_DYNAMIC) {
                cJSON_AddItemToArray(_list,cJSON_CreateString(node->osdecoder->fts_fields));
            }
            cJSON_AddItemToObject(decoder,"fts",_list);
        }

        if (node->osdecoder->type) {
            if (node->osdecoder->type == FIREWALL) {
                cJSON_AddStringToObject(decoder,"type","firewall");
            } else if (node->osdecoder->type == IDS) {
                cJSON_AddStringToObject(decoder,"type","ids");
            } else if (node->osdecoder->type == WEBLOG) {
                cJSON_AddStringToObject(decoder,"type","web-log");
            } else if (node->osdecoder->type == SYSLOG) {
                cJSON_AddStringToObject(decoder,"type","syslog");
            } else if (node->osdecoder->type == SQUID) {
                cJSON_AddStringToObject(decoder,"type","squid");
            } else if (node->osdecoder->type == DECODER_WINDOWS) {
                cJSON_AddStringToObject(decoder,"type","windows");
            } else if (node->osdecoder->type == HOST_INFO) {
                cJSON_AddStringToObject(decoder,"type","host-information");
            } else if (node->osdecoder->type == OSSEC_RL) {
                cJSON_AddStringToObject(decoder,"type","ossec");
            }
        }

        if (node->osdecoder->plugindecoder) {
            if ((void *)node->osdecoder->plugindecoder == PF_Decoder_Exec) {
                cJSON_AddStringToObject(decoder,"plugin_decoder","PF_Decoder");
            } else if ((void *)node->osdecoder->plugindecoder == SymantecWS_Decoder_Exec) {
                cJSON_AddStringToObject(decoder,"plugin_decoder","SymantecWS_Decoder");
            } else if ((void *)node->osdecoder->plugindecoder == SonicWall_Decoder_Exec) {
                cJSON_AddStringToObject(decoder,"plugin_decoder","SonicWall_Decoder");
            } else if ((void *)node->osdecoder->plugindecoder == OSSECAlert_Decoder_Exec) {
                cJSON_AddStringToObject(decoder,"plugin_decoder","OSSECAlert_Decoder");
            } else if ((void *)node->osdecoder->plugindecoder == JSON_Decoder_Exec) {
                cJSON_AddStringToObject(decoder,"plugin_decoder","JSON_Decoder");
            }
        }

        cJSON_AddItemToArray(array,decoder);
    }
}


void _getRulesListJSON(RuleNode *list, cJSON *array) {

    RuleNode *node = NULL;
    u_int32_t same;
    u_int32_t different;
    int i;

    const char * same_fields[] = {
        "same_srcip",
        "same_id",
        "same_dstip",
        "same_srcport",
        "same_dstport",
        "same_srcuser",
        "same_user",
        "same_protocol",
        "same_action",
        "same_url",
        "same_data",
        "same_extra_data",
        "same_status",
        "same_system_name",
        "same_srcgeoip",
        "same_dstgeoip",
        "same_location"
    };

    const char * different_fields[] = {
        "different_srcip",
        "different_id",
        "different_dstip",
        "different_srcport",
        "different_dstport",
        "different_srcuser",
        "different_user",
        "different_protocol",
        "different_action",
        "different_url",
        "different_data",
        "different_extra_data",
        "different_status",
        "different_system_name",
        "different_srcgeoip",
        "different_dstgeoip",
        "different_location"
    };

    for (node=list;node->next;node = node->next) {
        cJSON *rule = cJSON_CreateObject();

        if (node->child) {
            cJSON *children = cJSON_CreateArray();
            _getRulesListJSON(node->child,children);
            cJSON_AddItemToObject(rule,"children",children);
        }

        cJSON_AddNumberToObject(rule,"sigid",node->ruleinfo->sigid);
        cJSON_AddNumberToObject(rule,"level",node->ruleinfo->level);
        cJSON_AddNumberToObject(rule,"maxsize",node->ruleinfo->maxsize);
        cJSON_AddNumberToObject(rule,"frequency",node->ruleinfo->event_search ? node->ruleinfo->frequency + 2 : node->ruleinfo->frequency);
        cJSON_AddNumberToObject(rule,"timeframe",node->ruleinfo->timeframe);
        cJSON_AddNumberToObject(rule,"ignore_time",node->ruleinfo->ignore_time);
        cJSON_AddNumberToObject(rule,"decoded_as",node->ruleinfo->decoded_as);
        cJSON_AddNumberToObject(rule,"if_matched_sid",node->ruleinfo->if_matched_sid);

        if (node->ruleinfo->group) cJSON_AddStringToObject(rule,"group",node->ruleinfo->group);

        if (node->ruleinfo->regex) {
            cJSON * regex = cJSON_CreateObject();
            cJSON_AddStringToObject(regex, "pattern", w_expression_get_regex_pattern(node->ruleinfo->regex));
            cJSON_AddStringToObject(regex, "type", w_expression_get_regex_type(node->ruleinfo->regex));
            cJSON_AddBoolToObject(regex, "negate", node->ruleinfo->regex->negate);
            cJSON_AddItemToObject(rule, "regex", regex);
        }

        if (node->ruleinfo->match) {
            cJSON * match = cJSON_CreateObject();
            cJSON_AddStringToObject(match, "pattern", node->ruleinfo->match->match->raw);
            cJSON_AddBoolToObject(match, "negate", node->ruleinfo->match->negate);
            cJSON_AddItemToObject(rule, "match", match);
        }

        if (node->ruleinfo->srcgeoip) {
            cJSON * srcgeoip = cJSON_CreateObject();
            cJSON_AddStringToObject(srcgeoip, "pattern", w_expression_get_regex_pattern(node->ruleinfo->srcgeoip));
            cJSON_AddStringToObject(srcgeoip, "type", w_expression_get_regex_type(node->ruleinfo->srcgeoip));
            cJSON_AddBoolToObject(srcgeoip, "negate", node->ruleinfo->srcgeoip->negate);
            cJSON_AddItemToObject(rule, "srcgeoip", srcgeoip);
        }

        if (node->ruleinfo->dstgeoip) {
            cJSON * dstgeoip = cJSON_CreateObject();
            cJSON_AddStringToObject(dstgeoip, "pattern", w_expression_get_regex_pattern(node->ruleinfo->dstgeoip));
            cJSON_AddStringToObject(dstgeoip, "type", w_expression_get_regex_type(node->ruleinfo->dstgeoip));
            cJSON_AddBoolToObject(dstgeoip, "negate", node->ruleinfo->dstgeoip->negate);
            cJSON_AddItemToObject(rule, "dstgeoip", dstgeoip);
        }

        if (node->ruleinfo->srcport) {
            cJSON * srcport = cJSON_CreateObject();
            cJSON_AddStringToObject(srcport, "pattern", w_expression_get_regex_pattern(node->ruleinfo->srcport));
            cJSON_AddStringToObject(srcport, "type", w_expression_get_regex_type(node->ruleinfo->srcport));
            cJSON_AddBoolToObject(srcport, "negate", node->ruleinfo->srcport->negate);
            cJSON_AddItemToObject(rule, "srcport", srcport);
        }

        if (node->ruleinfo->dstport) {
            cJSON * dstport = cJSON_CreateObject();
            cJSON_AddStringToObject(dstport, "pattern", w_expression_get_regex_pattern(node->ruleinfo->dstport));
            cJSON_AddStringToObject(dstport, "type", w_expression_get_regex_type(node->ruleinfo->dstport));
            cJSON_AddBoolToObject(dstport, "negate", node->ruleinfo->dstport->negate);
            cJSON_AddItemToObject(rule, "dstport", dstport);
        }

        if (node->ruleinfo->user) {
            cJSON * user = cJSON_CreateObject();
            cJSON_AddStringToObject(user, "pattern", w_expression_get_regex_pattern(node->ruleinfo->user));
            cJSON_AddStringToObject(user, "type", w_expression_get_regex_type(node->ruleinfo->user));
            cJSON_AddBoolToObject(user, "negate", node->ruleinfo->user->negate);
            cJSON_AddItemToObject(rule, "user", user);
        }

        if (node->ruleinfo->url) {
            cJSON * url = cJSON_CreateObject();
            cJSON_AddStringToObject(url, "pattern", w_expression_get_regex_pattern(node->ruleinfo->url));
            cJSON_AddStringToObject(url, "type", w_expression_get_regex_type(node->ruleinfo->url));
            cJSON_AddBoolToObject(url, "negate", node->ruleinfo->url->negate);
            cJSON_AddItemToObject(rule, "url", url);
        }

        if (node->ruleinfo->id) {
            cJSON * id = cJSON_CreateObject();
            cJSON_AddStringToObject(id, "pattern", w_expression_get_regex_pattern(node->ruleinfo->id));
            cJSON_AddStringToObject(id, "type", w_expression_get_regex_type(node->ruleinfo->id));
            cJSON_AddBoolToObject(id, "negate", node->ruleinfo->id->negate);
            cJSON_AddItemToObject(rule, "id", id);
        }

        if (node->ruleinfo->system_name) {
            cJSON * system_name = cJSON_CreateObject();
            cJSON_AddStringToObject(system_name, "pattern", w_expression_get_regex_pattern(node->ruleinfo->system_name));
            cJSON_AddStringToObject(system_name, "type", w_expression_get_regex_type(node->ruleinfo->system_name));
            cJSON_AddBoolToObject(system_name, "negate", node->ruleinfo->system_name->negate);
            cJSON_AddItemToObject(rule, "system_name", system_name);
        }

        if (node->ruleinfo->protocol) {
            cJSON * protocol = cJSON_CreateObject();
            cJSON_AddStringToObject(protocol, "pattern", w_expression_get_regex_pattern(node->ruleinfo->protocol));
            cJSON_AddStringToObject(protocol, "type", w_expression_get_regex_type(node->ruleinfo->protocol));
            cJSON_AddBoolToObject(protocol, "negate", node->ruleinfo->protocol->negate);
            cJSON_AddItemToObject(rule, "protocol", protocol);
        }

        if (node->ruleinfo->data) {
            cJSON * data = cJSON_CreateObject();
            cJSON_AddStringToObject(data, "pattern", w_expression_get_regex_pattern(node->ruleinfo->data));
            cJSON_AddStringToObject(data, "type", w_expression_get_regex_type(node->ruleinfo->data));
            cJSON_AddBoolToObject(data, "negate", node->ruleinfo->data->negate);
            cJSON_AddItemToObject(rule, "data", data);
        }
        if (node->ruleinfo->status) {
            cJSON * status = cJSON_CreateObject();
            cJSON_AddStringToObject(status, "pattern", w_expression_get_regex_pattern(node->ruleinfo->status));
            cJSON_AddStringToObject(status, "type", w_expression_get_regex_type(node->ruleinfo->status));
            cJSON_AddBoolToObject(status, "negate", node->ruleinfo->status->negate);
            cJSON_AddItemToObject(rule, "status", status);
        }

        if (node->ruleinfo->hostname) {
            cJSON * hostname = cJSON_CreateObject();
            cJSON_AddStringToObject(hostname, "pattern", w_expression_get_regex_pattern(node->ruleinfo->hostname));
            cJSON_AddStringToObject(hostname, "type", w_expression_get_regex_type(node->ruleinfo->hostname));
            cJSON_AddBoolToObject(hostname, "negate", node->ruleinfo->hostname->negate);
            cJSON_AddItemToObject(rule, "hostname", hostname);
        }

        if (node->ruleinfo->program_name) {
            cJSON * program_name = cJSON_CreateObject();
            cJSON_AddStringToObject(program_name, "pattern", w_expression_get_regex_pattern(node->ruleinfo->program_name));
            cJSON_AddStringToObject(program_name, "type", w_expression_get_regex_type(node->ruleinfo->program_name));
            cJSON_AddBoolToObject(program_name, "negate", node->ruleinfo->program_name->negate);
            cJSON_AddItemToObject(rule, "program_name", program_name);
        }

        if (node->ruleinfo->extra_data) {
            cJSON * extra_data = cJSON_CreateObject();
            cJSON_AddStringToObject(extra_data, "pattern", w_expression_get_regex_pattern(node->ruleinfo->extra_data));
            cJSON_AddStringToObject(extra_data, "type", w_expression_get_regex_type(node->ruleinfo->extra_data));
            cJSON_AddBoolToObject(extra_data, "negate", node->ruleinfo->extra_data->negate);
            cJSON_AddItemToObject(rule, "extra_data", extra_data);
        }

        if (node->ruleinfo->location) {
            cJSON * location = cJSON_CreateObject();
            cJSON_AddStringToObject(location, "pattern", w_expression_get_regex_pattern(node->ruleinfo->location));
            cJSON_AddStringToObject(location, "type", w_expression_get_regex_type(node->ruleinfo->location));
            cJSON_AddBoolToObject(location, "negate", node->ruleinfo->location->negate);
            cJSON_AddItemToObject(rule, "location", location);
        }

        if (node->ruleinfo->action) {
            cJSON * action = cJSON_CreateObject();
            cJSON_AddStringToObject(action, "pattern", w_expression_get_regex_pattern(node->ruleinfo->action));
            cJSON_AddStringToObject(action, "type", w_expression_get_regex_type(node->ruleinfo->action));
            cJSON_AddBoolToObject(action, "negate", node->ruleinfo->action->negate);
            cJSON_AddItemToObject(rule, "action", action);
        }

        if (node->ruleinfo->comment) cJSON_AddStringToObject(rule,"comment",node->ruleinfo->comment);
        if (node->ruleinfo->info) cJSON_AddStringToObject(rule,"info",node->ruleinfo->info);
        if (node->ruleinfo->cve) cJSON_AddStringToObject(rule,"cve",node->ruleinfo->cve);
        if (node->ruleinfo->if_sid) cJSON_AddStringToObject(rule,"if_sid",node->ruleinfo->if_sid);
        if (node->ruleinfo->if_level) cJSON_AddStringToObject(rule,"if_group",node->ruleinfo->if_group);
        if (node->ruleinfo->if_group) cJSON_AddStringToObject(rule,"if_group",node->ruleinfo->if_group);
        if (node->ruleinfo->if_matched_regex) cJSON_AddStringToObject(rule,"if_matched_regex",node->ruleinfo->if_matched_regex->raw);
        if (node->ruleinfo->if_matched_group) cJSON_AddStringToObject(rule,"if_matched_group",node->ruleinfo->if_matched_group->raw);
        if (node->ruleinfo->file) cJSON_AddStringToObject(rule,"rule_file",node->ruleinfo->file);

        if (node->ruleinfo->category == FIREWALL) {
            cJSON_AddStringToObject(rule,"category","firewall");
        } else if (node->ruleinfo->category == IDS) {
            cJSON_AddStringToObject(rule,"category","ids");
        } else if (node->ruleinfo->category == SYSLOG) {
            cJSON_AddStringToObject(rule,"category","syslog");
        } else if (node->ruleinfo->category == WEBLOG) {
            cJSON_AddStringToObject(rule,"category","web-log");
        } else if (node->ruleinfo->category == SQUID) {
            cJSON_AddStringToObject(rule,"category","squid");
        } else if (node->ruleinfo->category == DECODER_WINDOWS) {
            cJSON_AddStringToObject(rule,"category","windows");
        } else if (node->ruleinfo->category == OSSEC_RL) {
            cJSON_AddStringToObject(rule,"category","ossec");
        }

        if (node->ruleinfo->fields && node->ruleinfo->fields[0]) {

            cJSON * _list = cJSON_CreateArray();
            for (i = 0; node->ruleinfo->fields[i]; i++) {
                cJSON * field = cJSON_CreateObject();

                cJSON_AddStringToObject(field, "name", node->ruleinfo->fields[i]->name);
                cJSON_AddStringToObject(field, "pattern", w_expression_get_regex_pattern(node->ruleinfo->fields[i]->regex));
                cJSON_AddStringToObject(field, "type", w_expression_get_regex_type(node->ruleinfo->fields[i]->regex));
                cJSON_AddBoolToObject(field, "negate", node->ruleinfo->fields[i]->regex->negate);

                cJSON_AddItemToArray(_list, field);
            }

            cJSON_AddItemToObject(rule, "field", _list);
        }

        if (node->ruleinfo->srcip && node->ruleinfo->srcip->ips[0]) {

            cJSON * _list = cJSON_CreateArray();
            for (i = 0; node->ruleinfo->srcip->ips[i]; i++) {
                cJSON * ip = cJSON_CreateObject();

                cJSON_AddStringToObject(ip, "ip", node->ruleinfo->srcip->ips[i]->ip);
                cJSON_AddBoolToObject(ip, "negate", node->ruleinfo->srcip->negate);

                cJSON_AddItemToArray(_list, ip);
            }

            cJSON_AddItemToObject(rule, "srcip", _list);
        }

        if (node->ruleinfo->dstip && node->ruleinfo->dstip->ips[0]) {

            cJSON * _list = cJSON_CreateArray();
            for (i = 0; node->ruleinfo->dstip->ips[i]; i++) {
                cJSON * ip = cJSON_CreateObject();

                cJSON_AddStringToObject(ip, "ip", node->ruleinfo->dstip->ips[i]->ip);
                cJSON_AddBoolToObject(ip, "negate", node->ruleinfo->dstip->negate);

                cJSON_AddItemToArray(_list, ip);
            }
            cJSON_AddItemToObject(rule, "dstip", _list);
        }

        if (same = node->ruleinfo->same_field, same) {
            for (i = 0; same != 0; i++) {
                if ((same & 1) == 1) {
                    cJSON_AddStringToObject(rule, same_fields[i], "");
                }
                same >>= 1;
            }
        }

        if (different = node->ruleinfo->same_field, different) {
            for (i = 0; different != 0; i++) {
                if ((different & 1) == 1) {
                    cJSON_AddStringToObject(rule, different_fields[i], "");
                }
                different >>= 1;
            }
        }

        cJSON_AddItemToArray(array,rule);
    }
}

#endif /* CONFIG_JSON_H */
