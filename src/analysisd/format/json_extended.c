/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 */

#include "json_extended.h"
#include <stddef.h>
#include "config.h"
#include <regex.h>

#define MAX_MATCHES 10
#define MAX_STRING 1024
#define MAX_STRING_LESS 30

static const char *pattern = "^[A-Z][a-z][a-z] [ 0123][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] ([^ ]+)";
static regex_t * regexCompiled; // Shared regex between write thread, AR thread and logtest thread
static pthread_rwlock_t regexMutex = PTHREAD_RWLOCK_INITIALIZER;

void W_ParseJSON(cJSON* root, const Eventinfo* lf)
{
    int i;

    // Parse hostname & Parse AGENTIP
    if(lf->full_log && lf->hostname) {
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
        W_JSON_ParseGroups(root, lf);
    }
    // Parse CIS and PCIDSS rules from rootcheck .txt benchmarks
    if(lf->full_log && W_isRootcheck(root)) {
        W_JSON_ParseRootcheck(root, lf);
    }
    // Parse labels
    if (lf->labels && lf->labels[0].key) {
        for (i = 0; lf->labels[i].key != NULL; i++) {
            if (!lf->labels[i].flags.system) {
                W_JSON_ParseLabels(root, lf);
                break;
            }
        }
    }
}

// Detect if the alert is coming from rootcheck controls.
int W_isRootcheck(cJSON* root)
{
    cJSON* groups;
    cJSON* group;
    cJSON* rule;
    char* group_json;

    int totalGroups, i;

    rule = cJSON_GetObjectItem(root, "rule");

    if (!rule) {
        return 0;
    }

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
void W_JSON_ParseRootcheck(cJSON* root, const Eventinfo* lf)
{
    static regex_t* r = NULL;
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
    char * saveptr;

    // Allocate memory
    for(i = 0; i < MAX_MATCHES; i++)
        results[i] = malloc((MAX_STRING_LESS) * sizeof(char));

    // Getting groups object JSON
    rule = cJSON_GetObjectItem(root, "rule");

    if (!rule) {
        merror("at W_JSON_ParseGroups(): No rule object found.");
        goto end;
    }

    // Getting full log string
    strncpy(fullog, lf->full_log, MAX_STRING - 1);
    // Searching regex
    regex_text = "\\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\\}";
    find_text = fullog;

    if (!(r || (r = compile_regex(regex_text)))) {
        // Internal error
        goto end;
    }

    matches = match_regex(r, find_text, results);

    if(matches > 0) {
        for(i = 0; i < matches; i++) {
            token = strtok_r(results[i], delim, &saveptr);

            if (!token)
                continue;

            trim(token);

            for(j = 0; token[j]; j++) {
                token[j] = tolower(token[j]);
            }
            if(token) {
                cJSON_AddItemToObject(rule, token, compliance = cJSON_CreateArray());
                token = strtok_r(0, delim, &saveptr);
                trim(token);
                token2 = strtok_r(token, delim2, &saveptr);
                while(token2) {

                    trim(token2);
                    cJSON_AddItemToArray(compliance, cJSON_CreateString(token2));
                    token2 = strtok_r(0, delim2, &saveptr);
                }
            }
        }
    }

end:
    for(i = 0; i < MAX_MATCHES; i++)
        free(results[i]);
}

// STRTOK every "-" delimiter to get differents groups to our json array.
void W_JSON_ParseGroups(cJSON* root, const Eventinfo* lf)
{
    cJSON* groups;
    cJSON* rule;
    int firstPCI, firstCIS, firstGDPR, firstGPG13, firstHIPAA, firstNIST, firstTSC;
    char delim[2];
    char buffer[MAX_STRING] = "";
    char* token;
    char* saveptr;

    firstPCI = firstCIS = firstGDPR = firstGPG13 = firstHIPAA = firstNIST = firstTSC = 1;
    delim[0] = ',';
    delim[1] = 0;

    rule = cJSON_GetObjectItem(root, "rule");

    if (!rule) {
        return;
    }

    cJSON_AddItemToObject(rule, "groups", groups = cJSON_CreateArray());
    strncpy(buffer, lf->generated_rule->group, MAX_STRING - 1);

    token = strtok_r(buffer, delim, &saveptr);
    while(token) {
        if (add_groupPCI(rule, token, firstPCI)) {
            firstPCI = 0;
        } else if (add_groupCIS(rule, token, firstCIS)) {
            firstCIS = 0;
        } else if (add_groupGDPR(rule, token, firstGDPR)) {
            firstGDPR = 0;
        } else if (add_groupGPG13(rule, token, firstGPG13)) {
            firstGPG13 = 0;
        } else if (add_groupHIPAA(rule, token, firstHIPAA)) {
            firstHIPAA = 0;
        } else if (add_groupNIST(rule, token, firstNIST)) {
            firstNIST = 0;
        } else if (add_groupTSC(rule, token, firstTSC)) {
            firstTSC = 0;
        } else {
            if (token) cJSON_AddItemToArray(groups, cJSON_CreateString(token));
        }
        token = strtok_r(0, delim, &saveptr);
    }

    //Add SCA compliance groups
    cJSON *data = cJSON_GetObjectItem(root,"data");
    if(data){
        cJSON *sca = cJSON_GetObjectItem(data,"sca");
        if(sca){
            cJSON *check = cJSON_GetObjectItem(sca,"check");
            if(check){
                cJSON *compliances = cJSON_GetObjectItem(check,"compliance");
                cJSON *compliance;
                cJSON_ArrayForEach(compliance,compliances){
                    add_SCA_groups(rule, compliance->string, compliance->valuestring);
                }
            }
        }
    }
}

void add_SCA_groups(cJSON *rule, char* compliance, char* value){

    if(!value) return;

    char *aux;
    int new_group = 0;
    os_strdup(value, aux);
    cJSON *group = cJSON_GetObjectItem(rule, compliance);
    if(!group){
        group = cJSON_CreateArray();
        new_group = 1;
    }
    char *token;
    char *state;
    for(token = strtok_r(aux, ",", &state); token; token = strtok_r(NULL, ",", &state)){
        trim(token);
        if(strlen(token) == 0)
            continue;
        cJSON_AddItemToArray(group, cJSON_CreateString(token));
    }

    if(new_group){
        if(cJSON_GetArraySize(group) > 0){
            cJSON_AddItemToObject(rule, compliance, group);
        } else {
            cJSON_Delete(group);
        }
    }

    free(aux);
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

// Parse groups GDPR
int add_groupGDPR(cJSON* rule, char* group, int firstGDPR)
{
    cJSON* gdpr;
    char *aux;
    if((startsWith("gdpr_", group)) == 1) {
        if(firstGDPR == 1) {
            gdpr = cJSON_CreateArray();
            cJSON_AddItemToObject(rule, "gdpr", gdpr);
        } else {
            gdpr = cJSON_GetObjectItem(rule, "gdpr");
        }
        aux = strdup(group);
        str_cut(aux, 0, 5);
        cJSON_AddItemToArray(gdpr, cJSON_CreateString(aux));
        free(aux);
        return 1;
    }
    return 0;
}

// Parse groups GPG13
int add_groupGPG13(cJSON* rule, char* group, int firstGPG13)
{
    cJSON* gpg13;
    char *aux;
    if((startsWith("gpg13_", group)) == 1) {
        if(firstGPG13 == 1) {
            gpg13 = cJSON_CreateArray();
            cJSON_AddItemToObject(rule, "gpg13", gpg13);
        } else {
            gpg13 = cJSON_GetObjectItem(rule, "gpg13");
        }
        aux = strdup(group);
        str_cut(aux, 0, 6);
        cJSON_AddItemToArray(gpg13, cJSON_CreateString(aux));
        free(aux);
        return 1;
    }
    return 0;
}

int add_groupHIPAA(cJSON* rule, char* group, int firstHIPAA)
{
    cJSON* hipaa;
    char *aux;
    if((startsWith("hipaa_", group)) == 1) {
        if(firstHIPAA == 1) {
            hipaa = cJSON_CreateArray();
            cJSON_AddItemToObject(rule, "hipaa", hipaa);
        } else {
            hipaa = cJSON_GetObjectItem(rule, "hipaa");
        }
        aux = strdup(group);
        str_cut(aux, 0, 6);
        cJSON_AddItemToArray(hipaa, cJSON_CreateString(aux));
        free(aux);
        return 1;
    }
    return 0;
}

int add_groupNIST(cJSON* rule, char* group, int firstNIST)
{
    cJSON* nist;
    char *aux;
    if((startsWith("nist_800_53_", group)) == 1) {
        if(firstNIST == 1) {
            nist = cJSON_CreateArray();
            cJSON_AddItemToObject(rule, "nist_800_53", nist);
        } else {
            nist = cJSON_GetObjectItem(rule, "nist_800_53");
        }
        aux = strdup(group);
        str_cut(aux, 0, 12);
        cJSON_AddItemToArray(nist, cJSON_CreateString(aux));
        free(aux);
        return 1;
    }
    return 0;
}

int add_groupTSC(cJSON* rule, char* group, int firstTSC)
{
    cJSON* tsc;
    char *aux;
    if((startsWith("tsc_", group)) == 1) {
        if(firstTSC == 1) {
            tsc = cJSON_CreateArray();
            cJSON_AddItemToObject(rule, "tsc", tsc);
        } else {
            tsc = cJSON_GetObjectItem(rule, "tsc");
        }
        aux = strdup(group);
        str_cut(aux, 0, 4);
        cJSON_AddItemToArray(tsc, cJSON_CreateString(aux));
        free(aux);
        return 1;
    }
    return 0;
}
// If hostname being with "(" means that alerts came from an agent, so we will remove the brakets
void W_JSON_ParseHostname(cJSON* root,const Eventinfo* lf)
{
    cJSON* agent;
    cJSON* manager;
    cJSON* predecoder;
    cJSON * name;
    char * agent_hostname = NULL;
    regmatch_t match[2];
    int match_size;

    agent = cJSON_GetObjectItem(root, "agent");
    manager = cJSON_GetObjectItem(root, "manager");

    // If location starts with '(' the event comes from an agent

    if(lf->location[0] == '(') {
        cJSON_AddStringToObject(agent, "name", lf->hostname);
    } else {
        if(lf->agent_id && !strcmp(lf->agent_id, "000")){
            if (name = cJSON_GetObjectItem(manager,"name"), name) {
                cJSON_AddItemReferenceToObject(agent, "name", name);
            }
        }
    }

    // Get predecoder hostname
    w_rwlock_rdlock(&regexMutex);
    if (!regexCompiled) {
        // Change regex mutex to write lock
        w_rwlock_unlock(&regexMutex);
        w_rwlock_wrlock(&regexMutex);

        // re-check if regex is not compiled, compile it (Prevent leak)
        if (!regexCompiled) {
            os_malloc(sizeof(regex_t), regexCompiled);

            if (regcomp(regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Can not compile regular expression.");
            }
        }
        // Change regex mutex to read lock
        w_rwlock_unlock(&regexMutex);
        w_rwlock_rdlock(&regexMutex);
    }

    int regex_status = regexec(regexCompiled, lf->full_log, 2, match, 0);
    w_rwlock_unlock(&regexMutex);

    if (regex_status == 0) {
        match_size = match[1].rm_eo - match[1].rm_so;
        os_malloc(match_size + 1, agent_hostname);
        snprintf (agent_hostname, match_size + 1, "%.*s", match_size, lf->full_log + match[1].rm_so);

        if (!cJSON_HasObjectItem(root, "predecoder")) {
            cJSON_AddItemToObject(root, "predecoder", predecoder = cJSON_CreateObject());
        } else {
            predecoder = cJSON_GetObjectItem(root, "predecoder");
        }

        cJSON_AddStringToObject(predecoder, "hostname", agent_hostname);
        free(agent_hostname);
    }
}
// Parse timestamp
void W_JSON_AddTimestamp(cJSON* root, const Eventinfo* lf)
{
    char timestamp[160];
    char datetime[64];
    char timezone[64];
    struct tm tm = { .tm_sec = 0 };

    if (lf->time.tv_sec) {
        localtime_r(&lf->time.tv_sec, &tm);
        strftime(datetime, sizeof(datetime), "%FT%T", &tm);
        strftime(timezone, sizeof(timezone), "%z", &tm);
        snprintf(timestamp, sizeof(timestamp), "%s.%03ld%s", datetime, lf->time.tv_nsec / 1000000, timezone);
        cJSON_AddStringToObject(root, "timestamp", timestamp);
    }
}

// The IP of an agent usually comes in "hostname" field, we will extract it.
void W_JSON_ParseAgentIP(cJSON* root, const Eventinfo* lf)
{
    char *string = NULL;
    char *ip;
    char *end;
    cJSON* agent;

    ip = labels_get(lf->labels, "_agent_ip");

    if (!ip) {

        if (lf->location[0] == '(') {
            string = strdup(lf->location);

            if ((ip = strchr(string, ')'))) {
                if ((end = strchr(ip += 2, '-')))
                    *end = '\0';
            }
        }
    }

    if (ip && strcmp(ip, "any")){
        agent = cJSON_GetObjectItem(root, "agent");
        cJSON_AddStringToObject(agent, "ip", ip);
    }

    os_free(string);

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
regex_t* compile_regex(const char* regex_text)
{
    regex_t* regex;
    int status;

    os_malloc(sizeof(regex_t), regex);
    status = regcomp(regex, regex_text, REG_EXTENDED | REG_NEWLINE);

    if (status != 0) {
        char error_message[MAX_ERROR_MSG];
        regerror(status, regex, error_message, MAX_ERROR_MSG);
        merror("Regex error compiling '%s': %s", regex_text, error_message);
        free(regex);
        return NULL;
    }

    return regex;
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
    if(!s) return;

    char* p = s;
    int l = strlen(p);

    while( l > 0 && isspace(p[l - 1]))
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

// Parse labels
void W_JSON_ParseLabels(cJSON *root, const Eventinfo *lf) {
    int i;
    cJSON *agent;
    cJSON *labels;

    agent = cJSON_GetObjectItem(root, "agent");

    labels = cJSON_CreateObject();
    cJSON_AddItemToObject(agent, "labels", labels);

    for (i = 0; lf->labels[i].key != NULL; i++) {
        if (!lf->labels[i].flags.system && (!lf->labels[i].flags.hidden || Config.show_hidden_labels)) {
            W_JSON_AddField(labels, lf->labels[i].key, lf->labels[i].value);
        }
    }
}
