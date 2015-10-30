/* Copyright (C) 2015 Wazuh Inc
 * All rights reserved.
 * 
 */

#include "json_extended.h"
#include <stddef.h>

void W_ParseJSON(cJSON *root, const Eventinfo *lf){
	 // Parse hostname & Parse AGENTIP
	 if(lf->hostname){
		 W_JSON_ParseHostname(root, lf->hostname);
		 W_JSON_ParseAgentIP(root, lf);
	 }
	 // Parse timestamp
	 if(lf->year && lf->mon && lf->day && lf->hour){ 
		 W_JSON_ParseTimestamp(root, lf);
	 }
	 // Parse Location
	if (lf->location) {
       W_JSON_ParseLocation(root,lf);
    }
	// Parse groups && Parse PCIDSS && Parse CIS
	if (lf->generated_rule->group) {
       W_JSON_ParseGroups(root,lf);
	   W_JSON_ParsePCIDSS(root);
	   W_JSON_ParseCIS(root);
    }
	// Parse CIS and PCIDSS rules from rootcheck .txt benchmarks
	if (lf->full_log) {
		W_JSON_ParseRootcheckCIS(root,lf);
		W_JSON_ParseRootcheckPCIDSS(root,lf);
	}
	// TODO: Where did the alert came from? rootcheck or analysid? Maybe we don't need to search por pci or cis twice.

	
 }
  // Getting PCI field from rootcheck rules benchmarks .txt
  void W_JSON_ParseRootcheckPCIDSS(cJSON *root, const Eventinfo *lf){
	regex_t r;
	cJSON *groups;
	cJSON *rule;
	cJSON *pci;
	
	const char * regex_text;
	const char * find_text;
	char results[2][100];
	int matches;
	char fullog[strlen(lf->full_log)];
	char buffer[25];
	// Getting groups object JSON
	rule = cJSON_GetObjectItem(root,"rule");
	groups = cJSON_GetObjectItem(rule,"groups");
	// Getting full log string
	strcpy(fullog, lf->full_log);
	// Searching regex
	regex_text = "PCI - ([[:digit:]]+[.[:digit:]]*) -";
	find_text = fullog;
	compile_regex(& r, regex_text);
	
	matches = match_regex(& r, find_text, results, 1);
	if(matches == -1){
		cJSON_AddItemToObject(rule,"PCI_DSS", pci = cJSON_CreateArray());
		memset(buffer, '\0', sizeof(buffer));
		strncpy(buffer, results[0], 20);		
		cJSON_AddItemToArray(groups, cJSON_CreateString("pci_dss"));
		cJSON_AddItemToArray(pci, cJSON_CreateString(buffer));
	}
	regfree (& r);
}

 // Getting CIS field from rootcheck rules benchmarks .txt
  void W_JSON_ParseRootcheckCIS(cJSON *root, const Eventinfo *lf){
	regex_t r;
	cJSON *groups;
	cJSON *rule;
	cJSON *cis;
	
	const char * regex_text;
	const char * find_text;
	char results[2][100];
	int matches;
	char fullog[strlen(lf->full_log)];
	char buffer[150];
	// Getting groups object JSON
	rule = cJSON_GetObjectItem(root,"rule");
	groups = cJSON_GetObjectItem(rule,"groups"); 
	// Getting full log string
	strcpy(fullog, lf->full_log);
	// Searching regex
	regex_text = "CIS - ([[:alnum:]]+[ [:alnum:]]*) - ([[:digit:]]+[.[:digit:]]*) -";
	find_text = fullog;
	compile_regex(& r, regex_text);
	
	matches = match_regex(& r, find_text, results, 2);
	if(matches == -1){
		cJSON_AddItemToArray(groups, cJSON_CreateString("cis"));
		cJSON_AddItemToObject(rule,"CIS", cis = cJSON_CreateArray());
		memset(buffer, '\0', sizeof(buffer));
		strncpy(buffer, results[1], 20);
		strncat(buffer, " ", 20);
		strncat(buffer, results[0], 20);
		cJSON_AddItemToArray(cis, cJSON_CreateString(buffer));
	}
	regfree (& r);
}
 
 
 // Getting CIS field from rule groups
 void W_JSON_ParseCIS(cJSON *root){
	cJSON *groups;
	cJSON *group;
	cJSON *rule;
	cJSON *cis;
	cis = cJSON_CreateArray();
	int i;
	regex_t r;
	const char * regex_text;
	int totalGroups;
	char results[2][100];
	int matches;
	char buffer[150];
	int foundCIS = 0;
	// Getting groups object JSON
	rule = cJSON_GetObjectItem(root,"rule");
	groups = cJSON_GetObjectItem(rule,"groups");
	// Counting total groups
	totalGroups = cJSON_GetArraySize(groups);
	// Set regex! CAUTION !=!=!=!=!=!=!=! Start with '"' because JSON PRINT function give the string like that
	regex_text = "^\"cis_([[:alnum:]]+[ [:alnum:]]*)_([[:digit:]]+[.[:digit:]]*)";
	compile_regex(& r, regex_text);
	for(i = 0; i < totalGroups; i++){
		group = cJSON_GetArrayItem(groups,i);
		matches = match_regex(& r, cJSON_Print(group), results, 2);
		if(matches == -1){
			if(foundCIS == 0){
				foundCIS = 1;
				cJSON_AddItemToArray(groups, cJSON_CreateString("cis"));
				cJSON_AddItemToObject(rule,"CIS", cis);
			}			
			memset(buffer, '\0', sizeof(buffer));
			strncpy(buffer, results[1], 20);
			strncat(buffer, " ", 20);
			strncat(buffer, results[0], 20);
			cJSON_AddItemToArray(cis, cJSON_CreateString(buffer));
			
		}
	}
	// Delete old groups
	int counter = 0;
	while(counter < cJSON_GetArraySize(groups)){
		group = cJSON_GetArrayItem(groups,counter);
		matches = match_regex(& r, cJSON_Print(group), results, 2);
		if(matches == -1){
			cJSON_DeleteItemFromArray(groups,counter);
			counter--;
		}
		counter++;
	}
	regfree (& r); 
 }
 
 // Getting PCI DSS field from rule groups
 void W_JSON_ParsePCIDSS(cJSON *root){
	cJSON *groups;
	cJSON *group;
	cJSON *rule;
	cJSON *pci;
	pci = cJSON_CreateArray();
	int i;
	regex_t r;
	const char * regex_text;
	int totalGroups;
	int foundPCI = 0;
	char results[2][100];
	int matches;
	char buffer[15];
	// Getting groups object JSON
	rule = cJSON_GetObjectItem(root,"rule");
	groups = cJSON_GetObjectItem(rule,"groups");
	// Counting total groups
	totalGroups = cJSON_GetArraySize(groups);
	// Set regex! CAUTION !=!=!=!=!=!=!=! Start with '"' because JSON PRINT function give the string like that
	regex_text = "^\"pci_dss_([[:digit:]]+[.[:digit:]]*)";
	compile_regex(& r, regex_text);
	
	for(i = 0; i < totalGroups; i++){
		group = cJSON_GetArrayItem(groups,i);
		matches = match_regex(& r, cJSON_Print(group), results, 1);
		if(matches == -1){
			//cJSON_DeleteItemFromArray(groups,i);
			if(foundPCI == 0){
				foundPCI = 1;
				cJSON_AddItemToObject(rule,"PCI_DSS", pci);
				cJSON_AddItemToArray(groups, cJSON_CreateString("pci_dss"));
			}
			memset(buffer, '\0', sizeof(buffer));
			strncpy(buffer, results[0], 10);
			cJSON_AddItemToArray(pci, cJSON_CreateString(buffer));
			
		}
	}
		// Delete old groups
	int counter = 0;
	while(counter < cJSON_GetArraySize(groups)){
		group = cJSON_GetArrayItem(groups,counter);
		matches = match_regex(& r, cJSON_Print(group), results, 1);
		if(matches == -1){
			cJSON_DeleteItemFromArray(groups,counter);
			counter--;
		}
		counter++;
	}
	regfree (& r); 
 }
 
// STRTOK every "-" delimiter to get differents groups to our json array.
 void W_JSON_ParseGroups(cJSON *root, const Eventinfo *lf){
	cJSON *groups;
	cJSON *rule;
	rule = cJSON_GetObjectItem(root,"rule");
	cJSON_AddItemToObject(rule,"groups", groups = cJSON_CreateArray());
	
	char buffer[strlen(lf->generated_rule->group)];
	strcpy(buffer, lf->generated_rule->group);	
	char delim[2];
	delim[0] = ',';
	delim[1] = 0;
	char* token = strtok(buffer, delim);
	while (token)
	{
		cJSON_AddItemToArray(groups, cJSON_CreateString(strdup(token)));
		token = strtok(0, delim);
	}
	free(token); 	 
 }
 
// If hostname being with "(" means that alerts came from an agent, so we will remove the brakets
// ** TODO ** Regex instead str_cut
void W_JSON_ParseHostname(cJSON *root, char *hostname){
	if(hostname[0] == '('){
		char *e;
		char string[strlen(hostname)];
		strcpy(string,hostname);
		int index;
		e = strchr(string, ')');
		index = (int)(e - string);
		str_cut(string, index, -1);
		str_cut(string, 0, 1);
		cJSON_AddStringToObject(root, "hostname", string);
	}else{
		cJSON_AddStringToObject(root, "hostname", hostname); 
	}  
 }
// Parse timestamp  
 void W_JSON_ParseTimestamp(cJSON *root, const Eventinfo *lf){
	char *dateTimestamp = malloc(21);
	sprintf(dateTimestamp, "%d %s %02d %s", lf->year, lf->mon, lf->day, lf->hour);
	cJSON_AddStringToObject(root, "timestamp", dateTimestamp);
	free (dateTimestamp);
 }
 
// The IP of an agent usually comes in "hostname" field, we will extract it.
// ** TODO ** Regex instead str_cut
 void W_JSON_ParseAgentIP(cJSON *root, const Eventinfo *lf){
    if(lf->hostname[0] == '('){
       char *e;
       char string[strlen(lf->hostname)];
       strcpy(string,lf->hostname);
       int index;
       e = strchr(string, ')');
       index = (int)(e - string);
       str_cut(string, 0, index);
       str_cut(string, 0, 2);
       e = strchr(string, '-');
       index = (int)(e - string);
       str_cut(string, index, -1);
       cJSON_AddStringToObject(root, "agentip", string);
    }
	 
 }
 // The file location usually comes with more information about the alert (like hostname or ip) we will extract just the "/var/folder/file.log".
 void W_JSON_ParseLocation(cJSON *root, const Eventinfo *lf){
  if(lf->location[0] == '('){
	 char *e;
	 char string[strlen(lf->location)];
	 strcpy(string,lf->location);
	 int index;
	 e = strchr(string, '>');
	 index = (int)(e - string);
	 str_cut(string, 0, index);
	 str_cut(string, 0, 1);
	 cJSON_AddStringToObject(root, "location", string);
  }else{
	 cJSON_AddStringToObject(root, "location", lf->location);
  } 	 
	 
 }
 
#define MAX_ERROR_MSG 0x1000
// Regex compilator 
int compile_regex (regex_t * r, const char * regex_text)
{
    int status = regcomp (r, regex_text, REG_EXTENDED|REG_NEWLINE);
    if (status != 0) {
	char error_message[MAX_ERROR_MSG];
	regerror (status, r, error_message, MAX_ERROR_MSG);
        printf ("Regex error compiling '%s': %s\n",
                 regex_text, error_message);
        return 1;
    }
    return 0;
}

/*
  Match the string in "to_match" against the compiled regular
  expression in "r".
 */
// Reglex matcher to extract some strings from differentes LF fields.
// Results is static array because for now we don't need anymore fields.
int match_regex (regex_t * r, const char * to_match, char results[2][100], int totalResults)
{
    const char * p = to_match;
	// 4 is max of matches to found.
    const int n_matches = 4;
    regmatch_t m[n_matches];
    while (1) {
        int i = 0;
        int nomatch = regexec (r, p, n_matches, m, 0);
        if (nomatch) {
            printf ("No more matches.\n");
            return nomatch;
        }
        for (i = 0; i < totalResults+1; i++) {
            int start;
            int finish;
            if (m[i].rm_so == -1) {
                break;
            }
            start = m[i].rm_so + (p - to_match);
            finish = m[i].rm_eo + (p - to_match);
            if (i == 0) {
               // printf ("$& is ");
            }
            else {
                sprintf (results[i-1], "%.*s", (finish - start),to_match + start);
                if(i==totalResults)
                    return -1;
            }
            
        }
        p += m[0].rm_eo;
    }
    return 0;
}

int str_cut(char *str, int begin, int len)
{
    int l = strlen(str);

    if (len < 0) len = l - begin;
    if (begin + len > l) len = l - begin;
    memmove(str + begin, str + begin + len, l - len + 1);

    return len;
}
