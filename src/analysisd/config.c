/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Functions to handle the configuration files */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "analysisd.h"
#include "config.h"

long int __crt_ftell; /* Global ftell pointer */
_Config Config;       /* Global Config structure */
OSList *active_responses;
OSList *ar_commands;
OSDecoderNode *osdecodernode_forpname;
OSDecoderNode *osdecodernode_nopname;

int GlobalConf(const char *cfgfile)
{
    int modules = 0;

    /* Default values */
    Config.logall = 0;
    Config.logall_json = 0;
    Config.stats = 4;
    Config.integrity = 8;
    Config.rootcheck = 8;
    Config.hostinfo = 8;
    Config.prelude = 0;
    Config.zeromq_output = 0;
    Config.zeromq_output_uri = NULL;
    Config.zeromq_output_server_cert = NULL;
    Config.zeromq_output_client_cert = NULL;
    Config.jsonout_output = 0;
    Config.alerts_log = 1;
    Config.memorysize = 8192;
    Config.mailnotify = -1;
    Config.keeplogdate = 0;
    Config.syscheck_alert_new = 0;
    Config.syscheck_auto_ignore = 1;
    Config.ar = 0;

    Config.syscheck_ignore = NULL;
    Config.white_list = NULL;
    Config.hostname_white_list = NULL;

    /* Default actions -- only log above level 1 */
    Config.mailbylevel = 7;
    Config.logbylevel  = 1;

    Config.custom_alert_output = 0;
    Config.custom_alert_output_format = NULL;

    Config.includes = NULL;
    Config.lists = NULL;
    Config.decoders = NULL;
    Config.label_cache_maxage = 0;
    Config.show_hidden_labels = 0;

    Config.cluster_name = NULL;
    Config.node_name = NULL;
    Config.hide_cluster_info = 1;
    Config.rotate_interval = 0;
    Config.min_rotate_interval = 0;
    Config.max_output_size = 0;
    Config.queue_size = 131072;

    os_calloc(1, sizeof(wlabel_t), Config.labels);

    modules |= CGLOBAL;
    modules |= CRULES;
    modules |= CALERTS;
    modules |= CCLUSTER;

    /* Read config */
    if (ReadConfig(modules, cfgfile, &Config, NULL) < 0 ||
        ReadConfig(CLABELS, cfgfile, &Config.labels, NULL) < 0) {
        return (OS_INVALID);
    }

    Config.min_rotate_interval = getDefine_Int("analysisd", "min_rotate_interval", 10, 86400);

    /* Minimum memory size */
    if (Config.memorysize < 2048) {
        Config.memorysize = 2048;
    }

    if (Config.rotate_interval && (Config.rotate_interval < Config.min_rotate_interval || Config.rotate_interval > 86400)) {
        merror("Rotate interval setting must be between %d seconds and one day.", Config.min_rotate_interval);
        return (OS_INVALID);
    }

    if (Config.max_output_size && (Config.max_output_size < 1000000 || Config.max_output_size > 1099511627776)) {
        merror("Maximum output size must be between 1 MiB and 1 TiB.");
        return (OS_INVALID);
    }

    if (Config.queue_size < 1) {
        merror("Queue size is invalid. Review configuration.");
        return OS_INVALID;
    }

    if (Config.queue_size > 262144) {
        mwarn("Queue size is very high. The application may run out of memory.");
    }

    return (0);
}


cJSON *getGlobalConfig(void) {

    unsigned int i;
    cJSON *root = cJSON_CreateObject();
    cJSON *global = cJSON_CreateObject();

    if (Config.mailnotify) cJSON_AddStringToObject(global,"email_notification","yes"); else cJSON_AddStringToObject(global,"email_notification","no");
    if (Config.logall) cJSON_AddStringToObject(global,"logall","yes"); else cJSON_AddStringToObject(global,"logall","no");
    if (Config.logall_json) cJSON_AddStringToObject(global,"logall_json","yes"); else cJSON_AddStringToObject(global,"logall_json","no");
    cJSON_AddNumberToObject(global,"integrity_checking",Config.integrity);
    cJSON_AddNumberToObject(global,"rootkit_detection",Config.rootcheck);
    cJSON_AddNumberToObject(global,"host_information",Config.hostinfo);
    if (Config.prelude) cJSON_AddStringToObject(global,"prelude_output","yes"); else cJSON_AddStringToObject(global,"prelude_output","no");
    if (Config.prelude_profile) cJSON_AddStringToObject(global,"prelude_profile",Config.prelude_profile);
    if (Config.prelude) cJSON_AddNumberToObject(global,"prelude_log_level",Config.hostinfo);
    if (Config.geoipdb_file) cJSON_AddStringToObject(global,"geoipdb",Config.geoipdb_file);
    if (Config.zeromq_output) cJSON_AddStringToObject(global,"zeromq_output","yes"); else cJSON_AddStringToObject(global,"zeromq_output","no");
    if (Config.zeromq_output_uri) cJSON_AddStringToObject(global,"zeromq_uri",Config.zeromq_output_uri);
    if (Config.zeromq_output_server_cert) cJSON_AddStringToObject(global,"zeromq_server_cert",Config.zeromq_output_server_cert);
    if (Config.zeromq_output_client_cert) cJSON_AddStringToObject(global,"zeromq_client_cert",Config.zeromq_output_client_cert);
    if (Config.jsonout_output) cJSON_AddStringToObject(global,"jsonout_output","yes"); else cJSON_AddStringToObject(global,"jsonout_output","no");
    if (Config.alerts_log) cJSON_AddStringToObject(global,"alerts_log","yes"); else cJSON_AddStringToObject(global,"alerts_log","no");
    cJSON_AddNumberToObject(global,"stats",Config.stats);
    cJSON_AddNumberToObject(global,"memory_size",Config.memorysize);
    if (Config.white_list) {
        cJSON *ip_list = cJSON_CreateArray();
        for (i=0;Config.white_list[i] && Config.white_list[i]->ip;i++) {
            cJSON_AddItemToArray(ip_list,cJSON_CreateString(Config.white_list[i]->ip));
        }
        OSMatch **wl;
        wl = Config.hostname_white_list;
        while (*wl) {
            char **tmp_pts = (*wl)->patterns;
            while (*tmp_pts) {
                cJSON_AddItemToArray(ip_list,cJSON_CreateString(*tmp_pts));
                tmp_pts++;
            }
            wl++;
        }
        cJSON_AddItemToObject(global,"white_list",ip_list);
    }
    if (Config.custom_alert_output) cJSON_AddStringToObject(global,"custom_alert_output",Config.custom_alert_output_format);
    cJSON_AddNumberToObject(global,"rotate_interval",Config.rotate_interval);
    cJSON_AddNumberToObject(global,"max_output_size",Config.max_output_size);

#ifdef LIBGEOIP_ENABLED
    if (Config.geoip_db_path) cJSON_AddStringToObject(global,"geoip_db_path",Config.geoip_db_path);
    if (Config.geoip6_db_path) cJSON_AddStringToObject(global,"geoip6_db_path",Config.geoip6_db_path);
#endif

    cJSON_AddItemToObject(root,"global",global);

    return root;
}


cJSON *getARManagerConfig(void) {

    if (!active_responses) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    OSListNode *node = OSList_GetFirstNode(active_responses);
    cJSON *ar_list = cJSON_CreateArray();
    while (node && node->data) {
        active_response *data = node->data;
        cJSON *ar = cJSON_CreateObject();
        if (data->command) cJSON_AddStringToObject(ar,"command",data->command);
        if (data->agent_id) cJSON_AddStringToObject(ar,"agent_id",data->agent_id);
        if (data->rules_id) cJSON_AddStringToObject(ar,"rules_id",data->rules_id);
        if (data->rules_group) cJSON_AddStringToObject(ar,"rules_group",data->rules_group);
        cJSON_AddNumberToObject(ar,"timeout",data->timeout);
        cJSON_AddNumberToObject(ar,"level",data->level);
        if (data->location & AS_ONLY) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("AS_ONLY"));
        else if (data->location & REMOTE_AGENT) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("REMOTE_AGENT"));
        else if (data->location & SPECIFIC_AGENT) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("SPECIFIC_AGENT"));
        else if (data->location & ALL_AGENTS) cJSON_AddItemToObject(ar,"location",cJSON_CreateString("ALL_AGENTS"));
        cJSON_AddItemToArray(ar_list,ar);
        node = node->next;
    }
    cJSON_AddItemToObject(root,"active-response",ar_list);

    return root;
}


cJSON *getARCommandsConfig(void) {

    if (!ar_commands) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    OSListNode *node = OSList_GetFirstNode(ar_commands);
    cJSON *ar_list = cJSON_CreateArray();
    while (node && node->data) {
        ar_command *data = node->data;
        cJSON *ar = cJSON_CreateObject();
        if (data->name) cJSON_AddStringToObject(ar,"name",data->name);
        if (data->executable) cJSON_AddStringToObject(ar,"executable",data->executable);
        cJSON_AddNumberToObject(ar,"timeout_allowed",data->timeout_allowed);
        if (data->expect & USERNAME) cJSON_AddItemToObject(ar,"expect",cJSON_CreateString("username"));
        else if (data->expect & SRCIP) cJSON_AddItemToObject(ar,"expect",cJSON_CreateString("srcip"));
        else if (data->expect & FILENAME) cJSON_AddItemToObject(ar,"expect",cJSON_CreateString("filename"));
        cJSON_AddItemToArray(ar_list,ar);
        node = node->next;
    }
    cJSON_AddItemToObject(root,"command",ar_list);

    return root;
}


cJSON *getAlertsConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *alerts = cJSON_CreateObject();

    cJSON_AddNumberToObject(alerts,"email_alert_level",Config.mailbylevel);
    cJSON_AddNumberToObject(alerts,"log_alert_level",Config.logbylevel);
#ifdef LIBGEOIP_ENABLED
    if (Config.loggeoip) cJSON_AddStringToObject(alerts,"use_geoip","yes"); else cJSON_AddStringToObject(alerts,"use_geoip","no");
#endif

    cJSON_AddItemToObject(root,"alerts",alerts);

    return root;
}


cJSON *getDecodersConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();

    if (osdecodernode_forpname) {
        _getDecodersListJSON(osdecodernode_forpname, list);
        _getDecodersListJSON(osdecodernode_nopname, list);
    }

    cJSON_AddItemToObject(root,"decoders",list);

    return root;
}


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

        if (node->osdecoder->program_name) {
            cJSON *_list = cJSON_CreateArray();
            for (i=0;node->osdecoder->program_name->patterns[i];i++) {
                cJSON_AddItemToArray(_list,cJSON_CreateString(node->osdecoder->program_name->patterns[i]));
            }
            cJSON_AddItemToObject(decoder,"program_name",_list);
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
