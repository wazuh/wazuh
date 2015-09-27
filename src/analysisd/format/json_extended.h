/* Copyright (C) 2015 Wazuh Inc
 * All rights reserved.
 * 
 */

#ifndef __JSON_EXTENDED_H__
#define __JSON_EXTENDED_H__

#include "eventinfo.h"
#include "cJSON.h"
#include <regex.h>

int str_cut(char *str, int begin, int len);
int compile_regex (regex_t * r, const char * regex_text);
int match_regex (regex_t * r, const char * to_match, char results[2][100], int totalResults);
// Main function, call the others parsers.
void W_ParseJSON(cJSON *root, const Eventinfo *lf);
// Parse hostname
void W_JSON_ParseHostname(cJSON *root, char *hostname);
// Parse Timestamp
void W_JSON_ParseTimestamp(cJSON *root, const Eventinfo *lf);
// Parse AgentIP
void W_JSON_ParseAgentIP(cJSON *root, const Eventinfo *lf);
// Parse Location
void W_JSON_ParseLocation(cJSON *root, const Eventinfo *lf);
// Parse Groups
void W_JSON_ParseGroups(cJSON *root, const Eventinfo *lf);
// Parse PCI DSS
void W_JSON_ParsePCIDSS(cJSON *root);
// Parse CIS
void W_JSON_ParseCIS(cJSON *root);
// Parse ROOTCHECK PCI DSS
void W_JSON_ParseRootcheckPCIDSS(cJSON *root, const Eventinfo *lf);
// Parse ROOTCHECK CIS
void W_JSON_ParseRootcheckCIS(cJSON *root, const Eventinfo *lf);

#endif
