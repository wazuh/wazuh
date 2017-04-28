/* Copyright (C) 2015 Wazuh Inc
 * All rights reserved.
 *
 */

// Support strptime() on Linux
#ifdef __linux__
#define _XOPEN_SOURCE 600
#endif

#include "json_extended.h"
#include <stddef.h>
#include "config.h"

#define MAX_MATCHES 10
#define MAX_STRING 1024
#define MAX_STRING_LESS 30

void W_ParseJSON(cJSON* root, const Eventinfo* lf)
{
    // Parse hostname & Parse AGENTIP
    if(lf->hostname) {
        W_JSON_ParseHostname(root, lf);
        W_JSON_ParseAgentIP(root, lf);
    }
    // Parse Location
    if(lf->location) {
        W_JSON_ParseLocation(root, lf, 0);
        W_JSON_ParseAgentless(root,lf);
    }
    // Parse groups && Parse PCIDSS && Parse CIS
    if(lf->generated_rule && lf->generated_rule->group) {
        W_JSON_ParseGroups(root, lf, 1);
    }
    // Parse CIS and PCIDSS rules from rootcheck .txt benchmarks
    if(lf->full_log && W_isRootcheck(root, 1)) {
        W_JSON_ParseRootcheck(root, lf, 1);
    }
    // Parse labels
    if (lf->labels && lf->labels[0].key) {
        W_JSON_ParseLabels(root, lf);
    }
}

// Detect if the alert is coming from rootcheck controls.
int W_isRootcheck(cJSON* root, int nested)
{
    cJSON* groups;
    cJSON* group;
    cJSON* rule;
    char* group_json;

    int totalGroups, i;

    if(!nested)
        rule = root;
    else
        rule = cJSON_GetObjectItem(root, "rule");

    if (!(groups = cJSON_GetObjectItem(rule, "groups")))
        return 0;

    totalGroups = cJSON_GetArraySize(groups);
    for(i = 0; i < totalGroups; i++) {
        group = cJSON_GetArrayItem(groups, i);
        group_json = cJSON_Print(group);
        if(strcmp(group_json, "\"rootcheck\"") == 0) {
            free(group_json);
            return 1;
        }
        free(group_json);
    }
    return 0;
}

// Getting security compliance field from rootcheck rules benchmarks .txt
void W_JSON_ParseRootcheck(cJSON* root, const Eventinfo* lf, int nested)
{
    regex_t r;
    cJSON* rule;
    cJSON* compliance;
    const char* regex_text;
    const char* find_text;
    char* token;
    char* token2;
    char* results[MAX_MATCHES];
    int matches, i, j;
    const char delim[2] = ":";
    const char delim2[2] = ",";
    char fullog[MAX_STRING] = "";

    // Allocate memory
    for(i = 0; i < MAX_MATCHES; i++)
        results[i] = malloc((MAX_STRING_LESS) * sizeof(char));

    // Getting groups object JSON
    if(!nested)
        rule = root;
    else
        rule = cJSON_GetObjectItem(root, "rule");

    // Getting full log string
    strncpy(fullog, lf->full_log, MAX_STRING - 1);
    // Searching regex
    regex_text = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    find_text = fullog;
    compile_regex(&r, regex_text);
    matches = match_regex(&r, find_text, results);

    if(matches > 0) {
        for(i = 0; i < matches; i++) {
            token = strtok(results[i], delim);

            if (!token)
                continue;

            trim(token);

            for(j = 0; token[j]; j++) {
                token[j] = tolower(token[j]);
            }
            if(token) {
                cJSON_AddItemToObject(rule, token, compliance = cJSON_CreateArray());
                token = strtok(0, delim);
                trim(token);
                token2 = strtok(token, delim2);
                while(token2) {

                    trim(token2);
                    cJSON_AddItemToArray(compliance, cJSON_CreateString(token2));
                    token2 = strtok(0, delim2);
                }
            }
        }
    }
    regfree(&r);
    for(i = 0; i < MAX_MATCHES; i++)
        free(results[i]);
}

// STRTOK every "-" delimiter to get differents groups to our json array.
void W_JSON_ParseGroups(cJSON* root, const Eventinfo* lf, int nested)
{
    cJSON* groups;
    cJSON* rule;
    int firstPCI, firstCIS, foundCIS, foundPCI;
    char delim[2];
    char buffer[MAX_STRING] = "";
    char* token;

    firstPCI = firstCIS = 1;
    foundPCI = foundCIS = 0;
    delim[0] = ',';
    delim[1] = 0;

    if(!nested)
        rule = root;
    else
        rule = cJSON_GetObjectItem(root, "rule");

    cJSON_AddItemToObject(rule, "groups", groups = cJSON_CreateArray());
    strncpy(buffer, lf->generated_rule->group, MAX_STRING - 1);

    token = strtok(buffer, delim);
    while(token) {
        foundPCI = foundCIS = 0;
        foundPCI = add_groupPCI(rule, token, firstPCI);
        if(!foundPCI)
            foundCIS = add_groupCIS(rule, token, firstCIS);

        if(foundPCI && firstPCI)
            firstPCI = 0;
        if(foundCIS && firstCIS)
            firstCIS = 0;

        if(!foundPCI && !foundCIS) {
            cJSON_AddItemToArray(groups, cJSON_CreateString(token));
        }
        token = strtok(0, delim);
    }
}
// Parse groups PCI
int add_groupPCI(cJSON* rule, char* group, int firstPCI)
{
    cJSON* pci;
    char *aux;
    // If group begin with pci_dss_ we have a PCI group
    if((startsWith("pci_dss_", group)) == 1) {
        // Once we add pci_dss group and create array for PCI_DSS requirements
        if(firstPCI == 1) {
            pci = cJSON_CreateArray();
            cJSON_AddItemToObject(rule, "pci_dss", pci);
        } else {
            pci = cJSON_GetObjectItem(rule, "pci_dss");
        }
        // Prepare string and add it to PCI dss array
        aux = strdup(group);
        str_cut(aux, 0, 8);
        cJSON_AddItemToArray(pci, cJSON_CreateString(aux));
        free(aux);
        return 1;
    }
    return 0;
}

int add_groupCIS(cJSON* rule, char* group, int firstCIS)
{
    cJSON* cis;
    char *aux;
    if((startsWith("cis_", group)) == 1) {
        if(firstCIS == 1) {
            cis = cJSON_CreateArray();
            cJSON_AddItemToObject(rule, "cis", cis);
        } else {
            cis = cJSON_GetObjectItem(rule, "cis");
        }
        aux = strdup(group);
        str_cut(aux, 0, 4);
        cJSON_AddItemToArray(cis, cJSON_CreateString(aux));
        free(aux);
        return 1;
    }
    return 0;
}

// If hostname being with "(" means that alerts came from an agent, so we will remove the brakets
// ** TODO ** Regex instead str_cut
void W_JSON_ParseHostname(cJSON* root,const Eventinfo* lf)
{
    cJSON* agent;
    cJSON* manager;
    agent = cJSON_GetObjectItem(root, "agent");
    manager = cJSON_GetObjectItem(root, "manager");
    if(lf->hostname[0] == '(') {
        char* search;
        char string[MAX_STRING] = "";
        int index;

        strncpy(string, lf->hostname, MAX_STRING - 1);
        search = strchr(string, ')');

        if(search) {
            index = (int)(search - string);
            str_cut(string, index, -1);
            str_cut(string, 0, 1);
            cJSON_AddStringToObject(agent, "name", string);
        }
    } else if(lf->agent_id && !strcmp(lf->agent_id, "000")){
        cJSON_AddStringToObject(agent, "name", cJSON_GetObjectItem(manager,"name")->valuestring);
        cJSON_AddStringToObject(root, "hostname", lf->hostname);
    }else{
        cJSON_AddStringToObject(root, "hostname", lf->hostname);
    }
}
// Parse timestamp
void W_JSON_AddTimestamp(cJSON* root, const Eventinfo* lf)
{
    char buffer[25] = "";
    struct tm tm;
    time_t timestamp;
    char *end;

    if (lf->year && lf->mon[0] && lf->day && lf->hour[0]) {
        timestamp = time(NULL);
        memcpy(&tm, localtime(&timestamp), sizeof(struct tm));

        if (!(end = strptime(lf->hour, "%T", &tm)) || *end) {
            merror("%s: ERROR: Could not parse hour '%s'.", ARGV0, lf->hour);
            return;
        }

        if (!(end = strptime(lf->mon, "%b", &tm)) || *end) {
            merror("%s: ERROR: Could not parse month '%s'.", ARGV0, lf->mon);
            return;
        }

        tm.tm_year = lf->year - 1900;
        tm.tm_mday = lf->day;

        strftime(buffer, 25, "%FT%T%z", &tm);
        cJSON_AddStringToObject(root, "timestamp", buffer);
    }
}

// The IP of an agent usually comes in "hostname" field, we will extract it.
// ** TODO ** Regex instead str_cut
void W_JSON_ParseAgentIP(cJSON* root, const Eventinfo* lf)
{
    char *string;
    char *ip;
    char *end;
    cJSON* agent;

    if (lf->hostname[0] == '(') {
        string = strdup(lf->hostname);

        if ((ip = strchr(string, ')'))) {
            if ((end = strchr(ip += 2, '-')))
                *end = '\0';

            if (strcmp(ip, "any")){
                agent = cJSON_GetObjectItem(root, "agent");
                cJSON_AddStringToObject(agent, "ip", ip);
            }
        }

        free(string);
    }
}

// The file location usually comes with more information about the alert (like hostname or ip) we will extract just the
// "/var/folder/file.log".
void W_JSON_ParseLocation(cJSON* root, const Eventinfo* lf, int archives)
{
    if(lf->location[0] == '(') {
        char* search;
        char string[MAX_STRING] = "";
        strncpy(string, lf->location, MAX_STRING - 1);
        int index;
        search = strchr(string, '>');
        if(search) {
            index = (int)(search - string);
            str_cut(string, 0, index);
            str_cut(string, 0, 1);

            if(archives == 1)
                cJSON_AddStringToObject(root, "location_desc", string);
            else
                cJSON_AddStringToObject(root, "location", string);
        }
    } else {
        if(archives == 1)
            cJSON_AddStringToObject(root, "location_desc", lf->location);
        else
            cJSON_AddStringToObject(root, "location", lf->location);
    }
}

// Parse agentless devices (this may delete agent item)

void W_JSON_ParseAgentless(cJSON* root, const Eventinfo* lf) {
    char *location;
    char *script;
    char *user;
    char *host;
    char *end;
    cJSON *agentless;

    // Agentless devices have agentID = 000 and location matches:
    // (script) user@host->location

    if (lf->location[0] == '(' && lf->agent_id && !strcmp(lf->agent_id, "000")) {
        location = strdup(lf->location);

        script = location + 1;
        user = strstr(script, ") ");

        if (user) {
            *user = '\0';
            user += 2;
            host = strchr(user, '@');

            if (host) {
                *host = '\0';
                host++;

                end = strstr(host, "->");

                if (end) {
                    *end = '\0';

                    // Add item "agentless"

                    agentless = cJSON_CreateObject();
                    cJSON_AddItemToObject(root, "agentless", agentless);
                    cJSON_AddStringToObject(agentless, "script", script);
                    cJSON_AddStringToObject(agentless, "user", user);
                    cJSON_AddStringToObject(agentless, "host", host);

                    // Delete item "agent"
                    cJSON_DeleteItemFromObject(root, "agent");
                }
            }
        }

        free(location);
    }
}

#define MAX_ERROR_MSG 0x1000
// Regex compilator
int compile_regex(regex_t* r, const char* regex_text)
{
    int status = regcomp(r, regex_text, REG_EXTENDED | REG_NEWLINE);
    if(status != 0) {
        char error_message[MAX_ERROR_MSG];
        regerror(status, r, error_message, MAX_ERROR_MSG);
        debug1("Regex error compiling '%s': %s\n", regex_text, error_message);
        return 1;
    }
    return 0;
}

int match_regex(regex_t* r, const char* to_match, char* results[MAX_MATCHES])
{
    const char* p = to_match;
    const int n_matches = 10;
    regmatch_t m[n_matches];
    int totalResults = 0;
    while(1) {
        int i = 0;
        int nomatch = regexec(r, p, n_matches, m, 0);
        if(nomatch) {
            // printf ("No more matches.\n");
            return totalResults;
        }
        for(i = 0; i < n_matches; i++) {
            int start;
            int finish;
            if(m[i].rm_so == -1) {
                break;
            }
            start = m[i].rm_so + (p - to_match);
            finish = m[i].rm_eo + (p - to_match);
            if(i > 0) {
                sprintf(results[totalResults], "%.*s", (finish - start), to_match + start);
                totalResults = totalResults + 1;
            }
        }
        p += m[0].rm_eo;
    }
    return 0;
}

int str_cut(char* str, int begin, int len)
{
    int l = strlen(str);

    if(len < 0)
        len = l - begin;
    if(begin + len > l)
        len = l - begin;
    memmove(str + begin, str + begin + len, l - begin - len + 1);

    return len;
}
void trim(char* s)
{
    char* p = s;
    int l = strlen(p);

    while(isspace(p[l - 1]))
        p[--l] = 0;
    while(*p && isspace(*p))
        ++p, --l;

    memmove(s, p, l + 1);
}

int startsWith(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}

// Add a dynamic field with object nesting
void W_JSON_AddField(cJSON *root, const char *key, const char *value) {
    cJSON *object;
    char *current;
    char *nest = strchr(key, '.');
    size_t length;

    if (nest) {
        length = nest - key;
        current = malloc(length + 1);
        strncpy(current, key, length);
        current[length] = '\0';

        if (!(object = cJSON_GetObjectItem(root, current)))
            cJSON_AddItemToObject(root, current, object = cJSON_CreateObject());

        W_JSON_AddField(object, nest + 1, value);
        free(current);
    } else
        cJSON_AddStringToObject(root, key, value);
}

// Parse labels
void W_JSON_ParseLabels(cJSON *root, const Eventinfo *lf) {
    int i;
    cJSON *agent;
    cJSON *labels;

    agent = cJSON_GetObjectItem(root, "agent");

    labels = cJSON_CreateObject();
    cJSON_AddItemToObject(agent, "labels", labels);

    for (i = 0; lf->labels[i].key != NULL; i++) {
        if (!lf->labels[i].flags.hidden || Config.show_hidden_labels) {
            W_JSON_AddField(labels, lf->labels[i].key, lf->labels[i].value);
        }
    }
}
