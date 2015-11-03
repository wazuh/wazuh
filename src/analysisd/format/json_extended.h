/* Copyright (C) 2015 Wazuh Inc
 * All rights reserved.
 * 
 */
 
#ifndef __JSON_EXTENDED_H__
#define __JSON_EXTENDED_H__

#include "eventinfo.h"
#include "cJSON.h"
#include <regex.h>

#define MAX_MATCHES 10

// Main function, call the others parsers.
void W_ParseJSON(cJSON *root, const Eventinfo *lf);
// Parse hostname
void W_JSON_ParseHostname(cJSON *root, char *hostname);
// Parse Timestamp
void W_JSON_ParseTimestamp(cJSON *root, const Eventinfo *lf);
// Parse AgentIP
void W_JSON_ParseAgentIP(cJSON *root, const Eventinfo *lf);
// Parse Location
void W_JSON_ParseLocation(cJSON *root, const Eventinfo *lf, int archives);
// Parse Groups
void W_JSON_ParseGroups(cJSON *root, const Eventinfo *lf, int nested);
// Parse Groups Compliance 
void W_JSON_ParseGroupsCompliance(cJSON *root, int nested);
// Parse Rootcheck compliance
void W_JSON_ParseRootcheck(cJSON *root, const Eventinfo *lf, int nested);
// Detecting if an alert comes from rootcheck
int W_isRootcheck(cJSON *root, int nested);
// Aux functions
int str_cut(char *str, int begin, int len);
int compile_regex (regex_t * r, const char * regex_text);
int match_regex (regex_t * r, const char * to_match, char * results[MAX_MATCHES]);
void trim(char * s);
void removeChar( char * string, char letter );
#endif
