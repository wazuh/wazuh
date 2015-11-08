/* Copyright (C) 2015 Wazuh Inc
 * All rights reserved.
 * 
 */

#include "json_extended.h"
#include <stddef.h>

#define MAX_MATCHES 10
#define MAX_STRING 1024

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
       W_JSON_ParseLocation(root,lf,0);
    }
	// Parse groups && Parse PCIDSS && Parse CIS
	if (lf->generated_rule->group) {
       W_JSON_ParseGroups(root,lf,1);
       W_JSON_ParseGroupsCompliance(root,1);
    }
	// Parse CIS and PCIDSS rules from rootcheck .txt benchmarks
	if (lf->full_log && W_isRootcheck(root,1)) {
       W_JSON_ParseRootcheck(root,lf,1);
	}
		
 }

// Detect if the alert is coming from rootcheck controls.
int W_isRootcheck(cJSON *root, int nested){
	cJSON *groups;
	cJSON *group;
	cJSON *rule;
	int totalGroups,i;

	if(!nested)
		rule = root;
	else
		rule = cJSON_GetObjectItem(root,"rule");

	groups = cJSON_GetObjectItem(rule,"groups");
	totalGroups = cJSON_GetArraySize(groups);
	for(i = 0; i < totalGroups; i++){
		group = cJSON_GetArrayItem(groups,i);
		if(strcmp(cJSON_Print(group),"\"rootcheck\"") == 0){
			return 1;
		}
	}
	return 0;
}

// Getting security compliance field from rootcheck rules benchmarks .txt
 void W_JSON_ParseRootcheck(cJSON *root, const Eventinfo *lf, int nested){
	regex_t r;
	cJSON *groups;
	cJSON *rule;
	cJSON *compliance;
	const char * regex_text;
	const char * find_text;
	char* token;
	char* token2;
	char *results[MAX_MATCHES];
	int matches,i,j;
	const char delim[2] = ":";
	const char delim2[2] = ",";
	char fullog[MAX_STRING];

	 
	// Getting groups object JSON
	if(!nested)
		rule = root;
	else
		rule = cJSON_GetObjectItem(root,"rule");

	groups = cJSON_GetObjectItem(rule,"groups");
	 
	// Getting full log string
	strncpy(fullog, lf->full_log,MAX_STRING);
	// Searching regex
	regex_text = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
	find_text = fullog;
	compile_regex(& r, regex_text);
	matches = match_regex(& r, find_text, results);
	 
	if(matches > 0){
		for (i = 0; i < matches; i++) {
			token = strtok(results[i], delim);
			 
			trim(token);
			cJSON_AddItemToObject(rule,token, compliance = cJSON_CreateArray());
			for(j = 0; token[j]; j++){
				token[j] = tolower(token[j]);
			}
			 
			cJSON_AddItemToArray(groups, cJSON_CreateString(token));
			if(token){		 
				token = strtok(0, delim);
				trim(token);
				token2 = strtok(token, delim2);
				while (token2)
				{
					 	
					trim(token2);
					cJSON_AddItemToArray(compliance, cJSON_CreateString(token2));
					token2 = strtok(0, delim2);
					 
				}
				
			}
	   }  
    }
    regfree (& r);
	for (i = 0; i < matches; i++)
        free(results[i]);
     
} 

 
 void W_JSON_ParseGroupsCompliance(cJSON *root, int nested){
 	 
	cJSON *groups;
	cJSON *group;
	cJSON *rule;
	cJSON *compliance1;
	cJSON *compliance2;
	compliance1 = cJSON_CreateArray();
	compliance2 = cJSON_CreateArray();
	int i;
	regex_t regex_cis;
	regex_t regex_pci;
	const char * regex_cis_text;
	const char * regex_pci_text;
	char *results[MAX_MATCHES];
	int matches = 0;
	char buffer[MAX_STRING];
	int foundCIS = 0;
	int foundPCI = 0;
	int j = 0;
	// Getting groups object JSON
	if(!nested)
		rule = root;
	else
		rule = cJSON_GetObjectItem(root,"rule");

	groups = cJSON_GetObjectItem(rule,"groups");
	 
	// Counting total groups
	// Set regex! CAUTION !=!=!=!=!=!=!=! Start with '"' because JSON PRINT function give the string like that
	regex_cis_text = "^\"cis_([[:alnum:]]+[ [:alnum:]]*)_([[:digit:]]+[.[:digit:]]*)";
	regex_pci_text = "^\"pci_dss_([[:digit:]]+[.[:digit:]]*)";
	compile_regex(& regex_cis, regex_cis_text);
	compile_regex(& regex_pci, regex_pci_text);
	 
	i = 0;
	while((group = cJSON_GetArrayItem(groups,i))){
		// PCI
		matches = match_regex(& regex_pci, cJSON_Print(group), results);
		if(matches > 0){
			cJSON_DeleteItemFromArray(groups,i);
			 
			i--;
			if(foundPCI == 0){
				foundPCI = 1;
				cJSON_AddItemToArray(groups, cJSON_CreateString("pci_dss"));
				cJSON_AddItemToObject(rule,"PCI_DSS", compliance1);
				 
			}
			 
			memset(buffer, '\0', sizeof(buffer));
			strncpy(buffer, results[0], sizeof(buffer));
			cJSON_AddItemToArray(compliance1, cJSON_CreateString(buffer));
			 
			for (j = 0; j < matches; j++)
				free(results[j]);
			i++;
			 
			continue;
			 
		}
		// CIS
		matches = match_regex(& regex_cis, cJSON_Print(group), results);
		 
		if(matches > 1){
			cJSON_DeleteItemFromArray(groups,i);
			 
			i--;
			if(foundCIS == 0){
				foundCIS = 1;
				cJSON_AddItemToArray(groups, cJSON_CreateString("cis"));
				cJSON_AddItemToObject(rule,"CIS", compliance2);
				 
			}
			 	
			memset(buffer, '\0', sizeof(buffer));
			strncpy(buffer, results[1], 100);
			strcat(buffer, " ");
			strncat(buffer, results[0], 100);
			 
			cJSON_AddItemToArray(compliance2, cJSON_CreateString(buffer));
			for (j = 0; j < matches; j++)
				free(results[j]);
			i++;
			 
			continue;
		}
		i++;
	}

	regfree (& regex_pci); 
	regfree (& regex_cis);


 }
 
// STRTOK every "-" delimiter to get differents groups to our json array. 
 void W_JSON_ParseGroups(cJSON *root, const Eventinfo *lf, int nested){
	cJSON *groups;
	cJSON *rule;
	 
	if(!nested)
		rule = root;
	else
		rule = cJSON_GetObjectItem(root,"rule");

	cJSON_AddItemToObject(rule,"groups", groups = cJSON_CreateArray());
	 
	char buffer[MAX_STRING];
	strncpy(buffer, lf->generated_rule->group, sizeof(buffer));	
	char delim[2];
	delim[0] = ',';
	delim[1] = 0;
	char* token = strtok(buffer, delim);
	while (token)
	{
		cJSON_AddItemToArray(groups, cJSON_CreateString(strdup(token)));
		token = strtok(0, delim);
		 
	}	 
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
void W_JSON_ParseLocation(cJSON *root, const Eventinfo *lf, int archives){
	if(lf->location[0] == '('){
		char *e;
		char string[strlen(lf->location)];
		strcpy(string,lf->location);
		int index;
		e = strchr(string, '>');
		index = (int)(e - string);
		str_cut(string, 0, index);
		str_cut(string, 0, 1);
		if(archives == 1)
			cJSON_AddStringToObject(root, "location_desc", string);
		else
			cJSON_AddStringToObject(root, "location", string);
	}else{
		if(archives == 1)
			cJSON_AddStringToObject(root, "location_desc", lf->location);
		else
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
        debug1 ("Regex error compiling '%s': %s\n",
                 regex_text, error_message);
        return 1;
    }
    return 0;
}

int match_regex (regex_t * r, const char * to_match, char * results[MAX_MATCHES])
{
    const char * p = to_match;
    const int n_matches = 10;
    regmatch_t m[n_matches];
    int totalResults = 0;
    while (1) {
        int i = 0;
        int nomatch = regexec (r, p, n_matches, m, 0);
        if (nomatch) {
            //printf ("No more matches.\n");
            return totalResults;
        }
        for (i = 0; i < n_matches; i++) {
            int start;
            int finish;
            if (m[i].rm_so == -1) {
                break;
            }
            start = m[i].rm_so + (p - to_match);
            finish = m[i].rm_eo + (p - to_match);
            if (i > 0) {
                results[totalResults] = malloc((finish - start)*sizeof(char));
                sprintf (results[totalResults], "%.*s", (finish - start),to_match + start);
                totalResults = totalResults + 1;
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
void trim(char * s) {
    char * p = s;
    int l = strlen(p);

    while(isspace(p[l - 1])) p[--l] = 0;
    while(* p && isspace(* p)) ++p, --l;

    memmove(s, p, l + 1);
}
void removeChar( char * string, char letter ) {
	unsigned int i;
	for(i = 0; i < strlen( string ); i++ )
		if( string[i] == letter )
	  		strcpy( string + i, string + i + 1 );
}
