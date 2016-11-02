/* Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "to_json.h"
#include "json_extended.h"
#include "shared.h"
#include "rules.h"
#include "cJSON.h"
#include "config.h"

/* Convert Eventinfo to json */
char* Eventinfo_to_jsonstr(const Eventinfo* lf)
{
    cJSON* root;
    cJSON* rule;
    cJSON* file_diff;
    char* out;
    int i;

    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());

    if(lf->generated_rule){
        if(lf->generated_rule->level) {
            cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);
        }
        if(lf->comment) {
            cJSON_AddStringToObject(rule, "comment", lf->comment);
        }
        if(lf->generated_rule->sigid) {
            cJSON_AddNumberToObject(rule, "sidid", lf->generated_rule->sigid);
        }
        if(lf->generated_rule->cve) {
            cJSON_AddStringToObject(rule, "cve", lf->generated_rule->cve);
        }
        if(lf->generated_rule->info) {
            cJSON_AddStringToObject(rule, "info", lf->generated_rule->info);
        }
        if(lf->generated_rule->frequency){
            cJSON_AddNumberToObject(rule, "frequency", lf->generated_rule->frequency);
        }
        if(lf->generated_rule->firedtimes){
            cJSON_AddNumberToObject(rule, "firedtimes", lf->generated_rule->firedtimes);
        }
    }

    if(lf->protocol) {
        cJSON_AddStringToObject(root, "protocol", lf->protocol);
    }
    if(lf->action) {
        cJSON_AddStringToObject(root, "action", lf->action);
    }
    if(lf->srcip) {
        cJSON_AddStringToObject(root, "srcip", lf->srcip);
    }
    #ifdef LIBGEOIP_ENABLED
    if (lf->srcgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "srcgeoip", lf->srcgeoip);
    }
    #endif
    if (lf->srcport) {
        cJSON_AddStringToObject(root, "srcport", lf->srcport);
    }
    if(lf->srcuser) {
        cJSON_AddStringToObject(root, "srcuser", lf->srcuser);
    }
    if(lf->dstip) {
        cJSON_AddStringToObject(root, "dstip", lf->dstip);
    }
    #ifdef LIBGEOIP_ENABLED
    if (lf->dstgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "dstgeoip", lf->dstgeoip);
    }
    #endif
    if (lf->dstport) {
        cJSON_AddStringToObject(root, "dstport", lf->dstport);
    }
    if(lf->dstuser) {
        cJSON_AddStringToObject(root, "dstuser", lf->dstuser);
    }
    if(lf->full_log) {
        cJSON_AddStringToObject(root, "full_log", lf->full_log);
    }
    if (lf->agent_id) {
        cJSON_AddStringToObject(root, "AgentID", lf->agent_id);
    }

    if(lf->filename) {
        file_diff = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "SyscheckFile", file_diff);
        cJSON_AddStringToObject(file_diff, "path", lf->filename);

        if (lf->size_before) {
            cJSON_AddStringToObject(file_diff, "size_before", lf->size_before);
        }
        if (lf->size_after) {
            cJSON_AddStringToObject(file_diff, "size_after", lf->size_after);
        }
        if (lf->perm_before) {
            char perm[7];
            snprintf(perm, 7, "%6o", lf->perm_before);
            cJSON_AddStringToObject(file_diff, "perm_before", perm);
        }
        if (lf->perm_after) {
            char perm[7];
            snprintf(perm, 7, "%6o", lf->perm_after);
            cJSON_AddStringToObject(file_diff, "perm_after", perm);
        }
        if (lf->owner_before) {
            cJSON_AddStringToObject(file_diff, "owner_before", lf->owner_before);
        }
        if (lf->owner_after) {
            cJSON_AddStringToObject(file_diff, "owner_after", lf->owner_after);
        }
        if (lf->gowner_before) {
            cJSON_AddStringToObject(file_diff, "gowner_before", lf->gowner_before);
        }
        if (lf->gowner_after) {
            cJSON_AddStringToObject(file_diff, "gowner_after", lf->gowner_after);
        }
        if (lf->md5_before) {
            cJSON_AddStringToObject(file_diff, "md5_before", lf->md5_before);
        }
        if (lf->md5_after) {
            cJSON_AddStringToObject(file_diff, "md5_after", lf->md5_after);
        }
        if (lf->sha1_before) {
            cJSON_AddStringToObject(file_diff, "sha1_before", lf->sha1_before);
        }
        if (lf->sha1_after) {
            cJSON_AddStringToObject(file_diff, "sha1_after", lf->sha1_after);
        }
        if (lf->uname_before) {
            cJSON_AddStringToObject(file_diff, "uname_before", lf->uname_before);
        }
        if (lf->uname_after) {
            cJSON_AddStringToObject(file_diff, "uname_after", lf->uname_after);
        }
        if (lf->gname_before) {
            cJSON_AddStringToObject(file_diff, "gname_before", lf->gname_before);
        }
        if (lf->gname_after) {
            cJSON_AddStringToObject(file_diff, "gname_after", lf->gname_after);
        }
        if (lf->mtime_before) {
            char mtime[20];
            strftime(mtime, 20, "%FT%T", localtime(&lf->mtime_before));
            cJSON_AddStringToObject(file_diff, "mtime_before", mtime);
        }
        if (lf->mtime_after) {
            char mtime[20];
            strftime(mtime, 20, "%FT%T", localtime(&lf->mtime_after));
            cJSON_AddStringToObject(file_diff, "mtime_after", mtime);
        }
        if (lf->inode_before) {
            cJSON_AddNumberToObject(file_diff, "inode_before", lf->inode_before);
        }
        if (lf->inode_after) {
            cJSON_AddNumberToObject(file_diff, "inode_after", lf->inode_after);
        }
        if (lf->diff) {
            cJSON_AddStringToObject(file_diff, "diff", lf->diff);
        }

        switch (lf->event_type) {
        case FIM_ADDED:
            cJSON_AddStringToObject(file_diff, "event", "added");
            break;
        case FIM_MODIFIED:
            cJSON_AddStringToObject(file_diff, "event", "modified");
            break;
        case FIM_READDED:
            cJSON_AddStringToObject(file_diff, "event", "readded");
            break;
        case FIM_DELETED:
            cJSON_AddStringToObject(file_diff, "event", "deleted");
            break;
        default: ;
        }
    }

    if(lf->program_name)
        cJSON_AddStringToObject(root, "program_name", lf->program_name);

    if(lf->id)
        cJSON_AddStringToObject(root, "id", lf->id);

    if(lf->status)
        cJSON_AddStringToObject(root, "status", lf->status);

    if(lf->command)
        cJSON_AddStringToObject(root, "command", lf->command);

    if(lf->url)
        cJSON_AddStringToObject(root, "url", lf->url);

    if(lf->data)
        cJSON_AddStringToObject(root, "data", lf->data);

    if(lf->systemname)
        cJSON_AddStringToObject(root, "systemname", lf->systemname);

    // DecoderInfo
    if(lf->decoder_info) {

        cJSON* decoder;

        // Dynamic fields, except for syscheck events
        if (lf->fields && !lf->filename) {
            for (i = 0; i < lf->nfields; i++) {
                W_JSON_AddField(root, lf->fields[i].key, lf->fields[i].value);
            }
        }

        cJSON_AddItemToObject(root, "decoder", decoder = cJSON_CreateObject());

        if(lf->decoder_info->fts)
            cJSON_AddNumberToObject(decoder, "fts", lf->decoder_info->fts);

        if(lf->decoder_info->accumulate)
            cJSON_AddNumberToObject(decoder, "accumulate", lf->decoder_info->accumulate);

        if(lf->decoder_info->parent)
            cJSON_AddStringToObject(decoder, "parent", lf->decoder_info->parent);

        if(lf->decoder_info->name)
            cJSON_AddStringToObject(decoder, "name", lf->decoder_info->name);

        if(lf->decoder_info->ftscomment)
            cJSON_AddStringToObject(decoder, "ftscomment", lf->decoder_info->ftscomment);
    }

    if (lf->previous)
        cJSON_AddStringToObject(root, "previous_log", lf->previous);

    W_ParseJSON(root, lf);
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}
/* Convert Archiveinfo to json */
char* Archiveinfo_to_jsonstr(const Eventinfo* lf)
{
    cJSON* root;
    char* out;
    int i;

    root = cJSON_CreateObject();

    if(lf->program_name)
        cJSON_AddStringToObject(root, "program_name", lf->program_name);

    if(lf->log)
        cJSON_AddStringToObject(root, "log", lf->log);

    if(lf->srcip)
        cJSON_AddStringToObject(root, "srcip", lf->srcip);

    #ifdef LIBGEOIP_ENABLED
    if (lf->srcgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "srcgeoip", lf->srcgeoip);
    }
    #endif

    if(lf->dstip)
        cJSON_AddStringToObject(root, "dstip", lf->dstip);

    #ifdef LIBGEOIP_ENABLED
    if (lf->dstgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "dstgeoip", lf->dstgeoip);
    }
    #endif

    if(lf->srcport)
        cJSON_AddStringToObject(root, "srcport", lf->srcport);

    if(lf->dstport)
        cJSON_AddStringToObject(root, "dstport", lf->dstport);

    if(lf->protocol)
        cJSON_AddStringToObject(root, "protocol", lf->protocol);

    if(lf->action)
        cJSON_AddStringToObject(root, "action", lf->action);

    if(lf->srcuser)
        cJSON_AddStringToObject(root, "srcuser", lf->srcuser);

    if(lf->dstuser)
        cJSON_AddStringToObject(root, "dstuser", lf->dstuser);

    if(lf->id)
        cJSON_AddStringToObject(root, "id", lf->id);

    if(lf->status)
        cJSON_AddStringToObject(root, "status", lf->status);

    if(lf->command)
        cJSON_AddStringToObject(root, "command", lf->command);

    if(lf->url)
        cJSON_AddStringToObject(root, "url", lf->url);

    if(lf->data)
        cJSON_AddStringToObject(root, "data", lf->data);

    if(lf->systemname)
        cJSON_AddStringToObject(root, "systemname", lf->systemname);

    if(lf->filename) {
        cJSON *file_diff = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "SyscheckFile", file_diff);
        cJSON_AddStringToObject(file_diff, "path", lf->filename);

        if (lf->size_before) {
            cJSON_AddStringToObject(file_diff, "size_before", lf->size_before);
        }
        if (lf->size_after) {
            cJSON_AddStringToObject(file_diff, "size_after", lf->size_after);
        }
        if (lf->perm_before) {
            char perm[7];
            snprintf(perm, 7, "%6o", lf->perm_before);
            cJSON_AddStringToObject(file_diff, "perm_before", perm);
        }
        if (lf->perm_after) {
            char perm[7];
            snprintf(perm, 7, "%6o", lf->perm_after);
            cJSON_AddStringToObject(file_diff, "perm_after", perm);
        }
        if (lf->owner_before) {
            cJSON_AddStringToObject(file_diff, "owner_before", lf->owner_before);
        }
        if (lf->owner_after) {
            cJSON_AddStringToObject(file_diff, "owner_after", lf->owner_after);
        }
        if (lf->gowner_before) {
            cJSON_AddStringToObject(file_diff, "gowner_before", lf->gowner_before);
        }
        if (lf->gowner_after) {
            cJSON_AddStringToObject(file_diff, "gowner_after", lf->gowner_after);
        }
        if (lf->md5_before) {
            cJSON_AddStringToObject(file_diff, "md5_before", lf->md5_before);
        }
        if (lf->md5_after) {
            cJSON_AddStringToObject(file_diff, "md5_after", lf->md5_after);
        }
        if (lf->sha1_before) {
            cJSON_AddStringToObject(file_diff, "sha1_before", lf->sha1_before);
        }
        if (lf->sha1_after) {
            cJSON_AddStringToObject(file_diff, "sha1_after", lf->sha1_after);
        }
        if (lf->uname_before) {
            cJSON_AddStringToObject(file_diff, "uname_before", lf->uname_before);
        }
        if (lf->uname_after) {
            cJSON_AddStringToObject(file_diff, "uname_after", lf->uname_after);
        }
        if (lf->gname_before) {
            cJSON_AddStringToObject(file_diff, "gname_before", lf->gname_before);
        }
        if (lf->gname_after) {
            cJSON_AddStringToObject(file_diff, "gname_after", lf->gname_after);
        }
        if (lf->mtime_before) {
            char mtime[20];
            strftime(mtime, 20, "%FT%T", localtime(&lf->mtime_before));
            cJSON_AddStringToObject(file_diff, "mtime_before", mtime);
        }
        if (lf->mtime_after) {
            char mtime[20];
            strftime(mtime, 20, "%FT%T", localtime(&lf->mtime_after));
            cJSON_AddStringToObject(file_diff, "mtime_after", mtime);
        }
        if (lf->inode_before) {
            cJSON_AddNumberToObject(file_diff, "inode_before", lf->inode_before);
        }
        if (lf->inode_after) {
            cJSON_AddNumberToObject(file_diff, "inode_after", lf->inode_after);
        }
        if (lf->diff) {
            cJSON_AddStringToObject(file_diff, "diff", lf->diff);
        }

        switch (lf->event_type) {
        case FIM_ADDED:
            cJSON_AddStringToObject(file_diff, "event", "added");
            break;
        case FIM_MODIFIED:
            cJSON_AddStringToObject(file_diff, "event", "modified");
            break;
        case FIM_READDED:
            cJSON_AddStringToObject(file_diff, "event", "readded");
            break;
        case FIM_DELETED:
            cJSON_AddStringToObject(file_diff, "event", "deleted");
            break;
        default: ;
        }
    }

    // RuleInfo
    if(lf->generated_rule) {
        cJSON* rule;

        cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());

        if(lf->generated_rule->level)
            cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);

        if(lf->comment)
            cJSON_AddStringToObject(rule, "comment", lf->comment);

        if(lf->generated_rule->sigid)
            cJSON_AddNumberToObject(rule, "sidid", lf->generated_rule->sigid);

        if(lf->generated_rule->cve)
            cJSON_AddStringToObject(rule, "cve", lf->generated_rule->cve);

        if(lf->generated_rule->info)
            cJSON_AddStringToObject(rule, "info", lf->generated_rule->info);

        if(lf->generated_rule->frequency)
            cJSON_AddNumberToObject(rule, "frequency", lf->generated_rule->frequency);

        if(lf->generated_rule->firedtimes)
            cJSON_AddNumberToObject(rule, "firedtimes", lf->generated_rule->firedtimes);

        if(lf->generated_rule->group) {
            W_JSON_ParseGroups(root, lf, 1);
        }

        if(lf->full_log && W_isRootcheck(root, 1)) {
            W_JSON_ParseRootcheck(root, lf, 1);
        }
    }
    // DecoderInfo
    if(lf->decoder_info) {

        cJSON* decoder;

        // Dynamic fields, except for syscheck events
        if (lf->fields && !lf->filename) {
            for (i = 0; i < lf->nfields; i++) {
                W_JSON_AddField(root, lf->fields[i].key, lf->fields[i].value);
            }
        }

        cJSON_AddItemToObject(root, "decoder", decoder = cJSON_CreateObject());

        if(lf->decoder_info->fts)
            cJSON_AddNumberToObject(decoder, "fts", lf->decoder_info->fts);

        if(lf->decoder_info->accumulate)
            cJSON_AddNumberToObject(decoder, "accumulate", lf->decoder_info->accumulate);

        if(lf->decoder_info->parent)
            cJSON_AddStringToObject(decoder, "parent", lf->decoder_info->parent);

        if(lf->decoder_info->name)
            cJSON_AddStringToObject(decoder, "name", lf->decoder_info->name);

        if(lf->decoder_info->ftscomment)
            cJSON_AddStringToObject(decoder, "ftscomment", lf->decoder_info->ftscomment);
    }

    if (lf->previous)
        cJSON_AddStringToObject(root, "previous_log", lf->previous);

    if(lf->full_log)
        cJSON_AddStringToObject(root, "full_log", lf->full_log);

    if(lf->year && lf->mon[0] && lf->day && lf->hour[0])
        W_JSON_ParseTimestamp(root, lf);

    if(lf->hostname) {
        W_JSON_ParseHostname(root, lf->hostname);
        W_JSON_ParseAgentIP(root, lf);
    }

    if (lf->agent_id) {
        cJSON_AddStringToObject(root, "AgentID", lf->agent_id);
    }

    if(lf->location)
        W_JSON_ParseLocation(root, lf, 0);

    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}
