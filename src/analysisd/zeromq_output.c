
#ifdef ZEROMQ_OUTPUT

#include "shared.h"
#include "eventinfo.h"
#include "shared.h"
#include "rules.h"
#include "czmq.h"
#include "cJSON.h"
#include "zeromq_output.h"




static zctx_t *zeromq_context;
static void *zeromq_pubsocket; 


void zeromq_output_start(char *uri, int argc, char **argv) {

    int rc;

    debug1("%s: DEBUG: New ZeroMQ Context", ARGV0);
    zeromq_context = zctx_new();
    if (zeromq_context == NULL) {
        merror("%s: Unable to initialize ZeroMQ library", ARGV0);
        return;
    }

    debug1("%s: DEBUG: New ZeroMQ Socket: ZMQ_PUB", ARGV0);
    zeromq_pubsocket = zsocket_new(zeromq_context, ZMQ_PUB);
    if (zeromq_pubsocket == NULL) {
        merror("%s: Unable to initialize ZeroMQ Socket", ARGV0);
        return;
    }

    debug1("%s: DEBUG: Listening on ZeroMQ Socket: %s", ARGV0, uri);
    rc = zsocket_bind(zeromq_pubsocket, uri);
    if (rc) {
        merror("%s: Unable to bind the ZeroMQ Socket: %s.", ARGV0, uri);
        return;
    }


}

void zeromq_output_end() {
    zsocket_destroy(zeromq_context, zeromq_pubsocket);
    zctx_destroy(&zeromq_context);
}


void zeromq_output_event(Eventinfo *lf){
    char *json_alert = Eventinfo_to_jsonstr(lf);
    zmsg_t *msg = zmsg_new();
    zmsg_addstr(msg, "ossec.alerts");
    zmsg_addstr(msg, json_alert);
    zmsg_send(&msg, zeromq_pubsocket);
    free(json_alert);
}

/* Convert Eventinfo to json */
char *Eventinfo_to_jsonstr(Eventinfo *lf) {
    cJSON *root;
    cJSON *rule;
    cJSON *file_diff; 
    char *out;
    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "rule", rule=cJSON_CreateObject());

    cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);

    if (lf->generated_rule->comment) cJSON_AddStringToObject(rule, "comment", lf->generated_rule->comment);
    if (lf->generated_rule->sigid) cJSON_AddNumberToObject(rule, "sidid", lf->generated_rule->sigid);
    if (lf->generated_rule->cve) cJSON_AddStringToObject(rule, "cve", lf->generated_rule->cve);
    if (lf->generated_rule->cve) cJSON_AddStringToObject(rule, "info", lf->generated_rule->info);


    if (lf->action) cJSON_AddStringToObject(root, "action", lf->action);
    if (lf->srcip) cJSON_AddStringToObject(root, "srcip", lf->srcip);
    if (lf->srcport) cJSON_AddStringToObject(root, "srcport", lf->srcport);
    if (lf->srcuser) cJSON_AddStringToObject(root, "srcuser", lf->srcuser);
    if (lf->dstip) cJSON_AddStringToObject(root, "dstip", lf->dstip);
    if (lf->dstport) cJSON_AddStringToObject(root, "dstport", lf->dstport);
    if (lf->dstuser) cJSON_AddStringToObject(root, "dstuser", lf->dstuser);
    if (lf->location) cJSON_AddStringToObject(root, "location", lf->location);
    if (lf->full_log) cJSON_AddStringToObject(root, "full_log", lf->full_log);
    if (lf->filename) {
        cJSON_AddItemToObject(root, "file", file_diff=cJSON_CreateObject());

        if (lf->md5_before && lf->md5_after && !strcmp(lf->md5_before, lf->md5_after)) {
            cJSON_AddStringToObject(file_diff,"md5_before", lf->md5_before);
            cJSON_AddStringToObject(file_diff,"md5_after", lf->md5_after);
        } 
        if (lf->sha1_before && lf->sha1_after && !strcmp(lf->sha1_before, lf->sha1_after)) {
            cJSON_AddStringToObject(file_diff,"sha1_before", lf->sha1_before);
            cJSON_AddStringToObject(file_diff,"sha1_after", lf->sha1_after);
        } 
        if (lf->owner_before && lf->owner_after && !strcmp(lf->owner_before, lf->owner_after)) {
            cJSON_AddStringToObject(file_diff,"owner_before", lf->owner_before);
            cJSON_AddStringToObject(file_diff,"owner_after", lf->owner_after);
        
        }
        if (lf->gowner_before && lf->gowner_after && !strcmp(lf->gowner_before, lf->gowner_after)) {
            cJSON_AddStringToObject(file_diff,"gowner_before", lf->gowner_before);
            cJSON_AddStringToObject(file_diff,"gowner_after", lf->gowner_after);
        }
        if (lf->perm_before && lf->perm_after && lf->perm_before != lf->perm_after) {
            cJSON_AddNumberToObject(file_diff, "perm_before", lf->perm_before);
            cJSON_AddNumberToObject(file_diff, "perm_after", lf->perm_after);
        }
    }
    out=cJSON_Print(root);
    cJSON_Delete(root);
    return out; 
}








#endif
