/* Copyright (C) 2015-2019, Wazuh Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifndef _CONFIG_JSON__H
#define _CONFIG_JSON__H

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

        if (node->osdecoder->prematch) cJSON_AddStringToObject(decoder,"prematch",node->osdecoder->prematch->raw);
        if (node->osdecoder->prematch_offset & AFTER_PARENT) cJSON_AddStringToObject(decoder,"prematch_offset","after_parent");

        if (node->osdecoder->regex) cJSON_AddStringToObject(decoder,"regex",node->osdecoder->regex->raw);
        if (node->osdecoder->regex_offset & AFTER_PARENT) cJSON_AddStringToObject(decoder,"regex_offset","after_parent");
        else if (node->osdecoder->regex_offset & AFTER_PREVREGEX) cJSON_AddStringToObject(decoder,"regex_offset","after_regex");
        else if (node->osdecoder->regex_offset & AFTER_PREMATCH) cJSON_AddStringToObject(decoder,"regex_offset","after_prematch");

        if (node->osdecoder->program_name) cJSON_AddStringToObject(decoder,"program_name",node->osdecoder->program_name->raw);

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
    int i;

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
        cJSON_AddNumberToObject(rule,"frequency",node->ruleinfo->frequency);
        cJSON_AddNumberToObject(rule,"timeframe",node->ruleinfo->timeframe);
        cJSON_AddNumberToObject(rule,"ignore_time",node->ruleinfo->ignore_time);
        cJSON_AddNumberToObject(rule,"decoded_as",node->ruleinfo->decoded_as);
        cJSON_AddNumberToObject(rule,"if_matched_sid",node->ruleinfo->if_matched_sid);
        if (node->ruleinfo->group) cJSON_AddStringToObject(rule,"group",node->ruleinfo->group);
        if (node->ruleinfo->regex) cJSON_AddStringToObject(rule,"regex",node->ruleinfo->regex->raw);
        if (node->ruleinfo->match) cJSON_AddStringToObject(rule,"match",node->ruleinfo->match->raw);
        if (node->ruleinfo->srcgeoip) cJSON_AddStringToObject(rule,"srcgeoip",node->ruleinfo->srcgeoip->raw);
        if (node->ruleinfo->dstgeoip) cJSON_AddStringToObject(rule,"dstgeoip",node->ruleinfo->dstgeoip->raw);
        if (node->ruleinfo->srcport) cJSON_AddStringToObject(rule,"srcport",node->ruleinfo->srcport->raw);
        if (node->ruleinfo->dstport) cJSON_AddStringToObject(rule,"dstport",node->ruleinfo->dstport->raw);
        if (node->ruleinfo->user) cJSON_AddStringToObject(rule,"user",node->ruleinfo->user->raw);
        if (node->ruleinfo->url) cJSON_AddStringToObject(rule,"url",node->ruleinfo->url->raw);
        if (node->ruleinfo->id) cJSON_AddStringToObject(rule,"id",node->ruleinfo->id->raw);
        if (node->ruleinfo->status) cJSON_AddStringToObject(rule,"status",node->ruleinfo->status->raw);
        if (node->ruleinfo->hostname) cJSON_AddStringToObject(rule,"hostname",node->ruleinfo->hostname->raw);
        if (node->ruleinfo->program_name) cJSON_AddStringToObject(rule,"program_name",node->ruleinfo->program_name->raw);
        if (node->ruleinfo->extra_data) cJSON_AddStringToObject(rule,"extra_data",node->ruleinfo->extra_data->raw);
        if (node->ruleinfo->action) cJSON_AddStringToObject(rule,"action",node->ruleinfo->action);
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
            cJSON *_list = cJSON_CreateArray();
            for (i=0;node->ruleinfo->fields[i];i++) {
                cJSON_AddItemToArray(_list,cJSON_CreateString(node->ruleinfo->fields[i]->name));
            }
            cJSON_AddItemToObject(rule,"field",_list);
        }
        if (node->ruleinfo->srcip && node->ruleinfo->srcip[0]) {
            cJSON *_list = cJSON_CreateArray();
            for (i=0;node->ruleinfo->srcip[i];i++) {
                cJSON_AddItemToArray(_list,cJSON_CreateString(node->ruleinfo->srcip[i]->ip));
            }
            cJSON_AddItemToObject(rule,"srcip",_list);
        }
        if (node->ruleinfo->dstip && node->ruleinfo->dstip[0]) {
            cJSON *_list = cJSON_CreateArray();
            for (i=0;node->ruleinfo->dstip[i];i++) {
                cJSON_AddItemToArray(_list,cJSON_CreateString(node->ruleinfo->dstip[i]->ip));
            }
            cJSON_AddItemToObject(rule,"dstip",_list);
        }

        cJSON_AddItemToArray(array,rule);
    }
}

#endif
