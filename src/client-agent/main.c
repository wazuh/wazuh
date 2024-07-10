/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* agent daemon */

#include "shared.h"
#include "agentd.h"

#ifndef ARGV0
#define ARGV0 "wazuh-agentd"
#endif


/* Prototypes */
static void help_agentd(char *home_path) __attribute((noreturn));


/* Print help statement */
static void help_agentd(char *home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", OSSECCONF);
    print_out(" ");
    os_free(home_path);
    exit(1);
}

#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>

#define API_URL "https://localhost:55000"

#define BUFFER_SIZE 8192

static char buffer[BUFFER_SIZE];

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream) {
    strncat(buffer, ptr, size * nmemb);
    return size * nmemb;
}

/* Function to perform the token validation */
int validate_token(const char *token) {
    CURL *curl;
    CURLcode res;
    memset(buffer, 0, BUFFER_SIZE);

    char url[256];
    snprintf(url, sizeof(url), "%s/management_authorization", API_URL);

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"action\":\"agent:uninstall\"}");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 0;
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "Error parsing JSON\n");
        return 0;
    }

    cJSON *authorized = cJSON_GetObjectItemCaseSensitive(json, "authorized");
    int result = cJSON_IsTrue(authorized);

    cJSON_Delete(json);
    return result;
}

/* Function to authenticate and get the token */
char* authenticate_user(const char *user, const char *password) {
    CURL *curl;
    CURLcode res;
    memset(buffer, 0, BUFFER_SIZE);

    char url[256];
    snprintf(url, sizeof(url), "%s/security/user/authenticate?raw=true", API_URL);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        char userpwd[256];
        snprintf(userpwd, sizeof(userpwd), "%s:%s", user, password);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return NULL;
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "Error parsing JSON\n");
        return NULL;
    }

    cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");
    if (!cJSON_IsObject(data)) {
        fprintf(stderr, "Error retrieving data object\n");
        cJSON_Delete(json);
        return NULL;
    }

    cJSON *token = cJSON_GetObjectItemCaseSensitive(data, "token");
    if (!cJSON_IsString(token) || (token->valuestring == NULL)) {
        fprintf(stderr, "Error retrieving token\n");
        cJSON_Delete(json);
        return NULL;
    }

    char *token_str = strdup(token->valuestring);
    cJSON_Delete(json);
    return token_str;
}

int main(int argc, char **argv)
{
    int c = 0;
    int test_config = 0;
    int debug_level = 0;
    char *home_path = w_homedir(argv[0]);

    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = OSSECCONF;
    const char *uninstall_auth_login = NULL;
    const char *uninstall_auth_token = NULL;

    uid_t uid;
    gid_t gid;

    run_foreground = 0;

    /* Set the name */
    OS_SetName(ARGV0);

	/* Change working directory */
    if (chdir(home_path) == -1) {
        merror(CHDIR_ERROR, home_path, errno, strerror(errno));
        os_free(home_path);
        exit(1);
    }

    agent_debug_level = getDefine_Int("agent", "debug", 0, 2);

    struct option long_opts[] = {
        {"uninstall-auth-login", 1, NULL, 1},
        {"uninstall-auth-token", 1, NULL, 2}
    };

    while ((c = getopt_long(argc, argv, "Vtdfhu:g:D:c:", long_opts, NULL)) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agentd(home_path);
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    merror_exit("-u needs an argument");
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                mwarn("-D is deprecated.");
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument.");
                }
                cfg = optarg;
                break;
            case 1:
                if (!optarg) {
                    merror_exit("--uninstall-auth-login needs an argument");
                }
                uninstall_auth_login = optarg;
                break;
            case 2:
                if (!optarg) {
                    merror_exit("--uninstall-auth-token needs an argument");
                }
                uninstall_auth_token = optarg;
                break;
            default:
                help_agentd(home_path);
                break;
        }
    }

    /* Anti tampering functionality */
    if (uninstall_auth_token) {
        if (validate_token(uninstall_auth_token)) {
            exit(0);
        } else {
            exit(1);
        }
    } else if (uninstall_auth_login) {
        char *user = strtok(strdup(uninstall_auth_login), ":");
        char *password = strtok(NULL, ":");
        char *token = authenticate_user(user, password);
        if (token && validate_token(token)) {
            free(token);
            exit(0);
        } else {
            free(token);
            exit(1);
        }
    }

    agt = (agent *)calloc(1, sizeof(agent));
    if (!agt) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = agent_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);
    mdebug1(STARTUP_MSG, (int)getpid());

    /* Read config */
    if (ClientConf(cfg) < 0) {
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!(agt->server && agt->server[0].rip)) {
        merror(AG_INV_IP);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_Address(agt->server)){
        merror(AG_INV_MNGIP, agt->server[0].rip);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_IPv6_Link_Local_Interface(agt->server)){
        merror(AG_INV_INT);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (agt->notify_time == 0) {
        agt->notify_time = NOTIFY_TIME;
    }
    if (agt->max_time_reconnect_try == 0 ) {
        agt->max_time_reconnect_try = RECONNECT_TIME;
    }
    if (agt->max_time_reconnect_try <= agt->notify_time) {
        agt->max_time_reconnect_try = (agt->notify_time * 3);
        minfo("Max time to reconnect can't be less than notify_time(%d), using notify_time*3 (%d)", agt->notify_time, agt->max_time_reconnect_try);
    }

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Exit if test config */
    if (test_config) {
        exit(0);
    }

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Agentd Start */
    AgentdStart(uid, gid, user, group);

    return (0);
}
