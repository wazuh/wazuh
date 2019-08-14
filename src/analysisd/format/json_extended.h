/* Copyright (C) 2015-2019, Wazuh Inc.
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
void W_JSON_ParseHostname(cJSON *root, const Eventinfo *lf);
// Add Timestamp
void W_JSON_AddTimestamp(cJSON *root, const Eventinfo *lf);
// Parse AgentIP
void W_JSON_ParseAgentIP(cJSON *root, const Eventinfo *lf);
// Parse Location
void W_JSON_ParseLocation(cJSON *root, const Eventinfo *lf, int archives);
// Parse agentless devices (this may delete agent item)
void W_JSON_ParseAgentless(cJSON* root, const Eventinfo* lf);
// Parse Groups
void W_JSON_ParseGroups(cJSON *root, const Eventinfo *lf);
// Parse Groups Compliance
void W_JSON_ParseGroupsCompliance(cJSON *root);
// Parse Rootcheck compliance
void W_JSON_ParseRootcheck(cJSON *root, const Eventinfo *lf);
// Parse labels
void W_JSON_ParseLabels(cJSON *root, const Eventinfo *lf);
// Detecting if an alert comes from rootcheck
int W_isRootcheck(cJSON *root);
// Parsing PCI Compliance groups
int add_groupPCI(cJSON *rule, char * group, int firstPCI);
// Parsing CIS Compliance groups
int add_groupCIS(cJSON *rule, char * group, int firstCIS);
// Parsing GDPR Compliance groups
int add_groupGDPR(cJSON* rule, char* group, int firstGDPR);
// Parsing GPG13 Compliance groups
int add_groupGPG13(cJSON* rule, char* group, int firstGPG13);
// Aux functions
int str_cut(char *str, int begin, int len);
regex_t * compile_regex (const char * regex_text);
int match_regex (regex_t * r, const char * to_match, char * results[MAX_MATCHES]);
void trim(char * s);
int startsWith(const char *pre, const char *str);
#endif
