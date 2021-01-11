/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "alerts.h"
#include "config.h"
#include "active-response.h"
#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "os_execd/execd.h"
#include "eventinfo.h"
#include "wazuh_db/wdb.h"

#define NEW_AR_MECHANISM "v4.2.0"

void OS_Exec(int execq, int *arq, const Eventinfo *lf, const active_response *ar)
{
    char exec_msg[OS_SIZE_8192 + 1];
    char msg[OS_SIZE_8192 + 1];
    const char *ip;
    const char *user;
    char *filename = NULL;
    char *extra_args = NULL;

    memset(exec_msg, 0, OS_SIZE_8192 + 1);
    memset(msg, 0, OS_SIZE_8192 + 1);

    /* Clean the IP */
    ip = "-";
    if (lf->srcip) {
        ip = get_ip(lf);
        if(ip == NULL) {
            return;
        }
    }

    /* Get username */
    user = "-";
    if (lf->dstuser) {
        user = lf->dstuser;
    }

    /* Get filename */
    if (lf->filename) {
        filename = os_shell_escape(lf->filename);
    }

    /* Get extra_args */
    if (ar->ar_cmd->extra_args) {
        extra_args = os_shell_escape(ar->ar_cmd->extra_args);
    }
    /* Active Response on the server
     * The response must be here if the ar->location is set to AS
     * or the ar->location is set to local (REMOTE_AGENT) and the
     * event location is from here.
     */
    if ((ar->location & AS_ONLY) ||
            ((ar->location & REMOTE_AGENT) && (lf->location[0] != '(')) ) {
        if (!(Config.ar & LOCAL_AR)) {
            goto cleanup;
        }
        if(getActiveResponseInJSON(lf, ar, extra_args, exec_msg)) {
            goto cleanup;
        }
        if (OS_SendUnix(execq, exec_msg, 0) < 0) {
            merror("Error communicating with execd.");
        }
    }

    /* Active Response to the forwarder */
    else if ((Config.ar & REMOTE_AR)) {

        /* We need to identify the version of Wazuh installed on the agents because
         * if the agents version is <4.2, it is necessary to send legacy
         * message in string format. Instead if the agent version is >=4.2,
         * we need to send the new message in JSON format.*/

        if (ar->location & ALL_AGENTS) {

            int sock = -1;
            int *id_array = NULL;

            id_array = wdb_get_all_agents(FALSE, &sock);
            if(!id_array) {
                merror("Unable to get agent's ID array.");
                wdbc_close(&sock);
                goto cleanup;
            }

            for (size_t i = 0; id_array[i] != -1; i++) {
                cJSON *json_agt_info = NULL;
                cJSON *json_agt_version = NULL;
                char c_agent_id[OS_SIZE_16];
                char *agt_version = NULL;

                memset(exec_msg, 0, OS_SIZE_8192 + 1);
                memset(msg, 0, OS_SIZE_8192 + 1);

                json_agt_info = wdb_get_agent_info(id_array[i], &sock);
                if (!json_agt_info) {
                    merror("Failed to get agent '%d' information from Wazuh DB.", id_array[i]);
                    continue;
                }

                json_agt_version = cJSON_GetObjectItem(json_agt_info->child, "version");

                if(cJSON_IsString(json_agt_version) && json_agt_version->valuestring != NULL) {
                    agt_version = json_agt_version->valuestring;
                } else {
                    merror("Failed to get agent '%d' version.", id_array[i]);
                    cJSON_Delete(json_agt_info);
                    continue;
                }

                // agt_version contains "Wazuh vX.X.X", only the last part is needed.
                char *version = strchr(agt_version, 'v');
                if(strcmp(version, NEW_AR_MECHANISM) >= 0) {
                    if(getActiveResponseInJSON(lf, ar, extra_args, msg)) {
                        cJSON_Delete(json_agt_info);
                        continue;
                    }
                } else {
                    getActiveResponseInString(lf, ar, ip, user, filename, extra_args, msg);
                }

                cJSON_Delete(json_agt_info);

                snprintf(c_agent_id, OS_SIZE_16, "%.3d", id_array[i]);
                get_exec_msg(lf, ar, c_agent_id, msg, exec_msg);

                if ((OS_SendUnix(*arq, exec_msg, 0)) < 0) {
                    merror("Error communicating with ar queue.");
                }
            }

            os_free(id_array);
            wdbc_close(&sock);

        } else {

            int sock = -1;
            cJSON *json_agt_info = NULL;
            cJSON *json_agt_version = NULL;
            char c_agent_id[OS_SIZE_16];
            char *agt_version = NULL;
            int agt_id = OS_INVALID;

            if (ar->location & SPECIFIC_AGENT) {
                agt_id = atoi(ar->agent_id);

            } else if (ar->location & REMOTE_AGENT) {
                char *location = lf->location;

                char *hostname = extract_word_between_two_words(location, "(", ")");
                if(!hostname) {
                    merror("Unable to extract hostname from the string between the two words");
                    goto cleanup;
                }

                char *ip_remote_agent = extract_word_between_two_words(location, " ", "-");
                if(!ip_remote_agent) {
                    merror("Unable to extract ip from the string between the two words");
                    os_free(hostname);
                    goto cleanup;
                }

                agt_id = wdb_find_agent(hostname, ip_remote_agent, &sock);

                os_free(hostname);
                os_free(ip_remote_agent);
                wdbc_close(&sock);
            }

            if(agt_id == OS_INVALID) {
                merror("Unable to get agent ID.");
                goto cleanup;
            }

            json_agt_info = wdb_get_agent_info(agt_id, &sock);
            wdbc_close(&sock);
            if (!json_agt_info) {
                merror("Failed to get agent '%d' information from Wazuh DB.", agt_id);
                goto cleanup;
            }

            json_agt_version = cJSON_GetObjectItem(json_agt_info->child, "version");

            if(cJSON_IsString(json_agt_version) && json_agt_version->valuestring != NULL) {
                agt_version = json_agt_version->valuestring;
            } else {
                merror("Failed to get agent '%d' version.", agt_id);
                cJSON_Delete(json_agt_info);
                goto cleanup;
            }

            // agt_version contains "Wazuh vX.X.X", only the last part is needed.
            char *version = strchr(agt_version, 'v');
            if(strcmp(version, NEW_AR_MECHANISM) >= 0) {
                if(getActiveResponseInJSON(lf, ar, extra_args, msg)) {
                    cJSON_Delete(json_agt_info);
                    goto cleanup;
                }
            } else {
                getActiveResponseInString(lf, ar, ip, user, filename, extra_args, msg);
            }

            cJSON_Delete(json_agt_info);

            snprintf(c_agent_id, OS_SIZE_16, "%.3d", agt_id);
            get_exec_msg(lf, ar, c_agent_id, msg, exec_msg);

            if ((OS_SendUnix(*arq, exec_msg, 0)) < 0) {
                merror("Error communicating with ar queue.");
            }
        }
    }

    cleanup:

    /* Clean up Memory */
    os_free(filename);
    os_free(extra_args);

    return;
}

/**
 * @brief extract word from a string between two words
 *
 * @param[in] sentence The string where the words are found.
 * @param[in] word1 Word on the left side of the word to extract.
 * @param[in] word2 Word on the right side of the word to extract.
 * @return The word to extract or NULL on failure, remember to free memory after return
 */
char *extract_word_between_two_words(const char* sentence, const char* word1, const char* word2)
{
    const char *p1 = strstr(sentence, word1);
    if(!p1) {
        return NULL;
    }
    p1 = p1 + strlen(word1);

    const char *p2 = strstr(p1, word2);
    if(!p2) {
        return NULL;
    }

    size_t len = p2-p1;

    char *word = NULL;
    os_malloc(sizeof(char)*(len+1), word);
    strncpy(word, p1, len);
    word[len] = '\0';

    return word;
}

/**
 * @brief get the IP.
 *
 * @param[in] lf Event information.
 * @return const char* on success or NULL on failure.
 */
const char* get_ip(const Eventinfo *lf)
{
    const char *ip;
    ip = "-";

    if (strncmp(lf->srcip, "::ffff:", 7) == 0) {
        ip = lf->srcip + 7;
    } else {
        ip = lf->srcip;
    }

    /* Check if IP is to be ignored */
    if (Config.white_list) {
        if (OS_IPFoundList(ip, Config.white_list)) {
            return NULL;
        }
    }

    /* Check if it is a hostname */
    if (Config.hostname_white_list) {
        size_t srcip_size;
        OSMatch **wl;

        srcip_size = strlen(ip);

        wl = Config.hostname_white_list;
        while (*wl) {
            if (OSMatch_Execute(ip, srcip_size, *wl)) {
                return NULL;
            }
            wl++;
        }
    }
    return ip;
}

/**
 * @brief Build the string message
 *
 * @param[in] lf Event information.
 * @param[in] ar Active Response information.
 * @param[in] ip IP to send the specific message.
 * @param[in] user
 * @param[in] filename
 * @param[in] extra_args Added arguments.
 * @param[out] temp_msg Message in string format.
 * @return void.
 */
void getActiveResponseInString( const Eventinfo *lf,
                                const active_response *ar,
                                const char *ip,
                                const char *user,
                                char *filename,
                                char *extra_args,
                                char *temp_msg)
{
    snprintf(temp_msg, OS_SIZE_1024,
            "%s %s %s %ld.%ld %d %s %s %s",
            ar->name,
            user,
            ip,
            (long int)lf->time.tv_sec,
            __crt_ftell,
            lf->generated_rule->sigid,
            lf->location,
            filename ? filename : "-",
            extra_args ? extra_args : "-");
}

/**
 * @brief Add the header to the message to send to remoted
 *
 * @param[in] lf Event information.
 * @param[in] ar Active Response information.
 * @param[in] agent_id Agent ID to identify where the AR will be executed.
 * @param[in] msg Message that can be in JSON or string format
 * @param[out] exec_msg Complete massage containing the message and the header.
 * @return void.
 */
void get_exec_msg(const Eventinfo *lf, const active_response *ar, char *agent_id, const char *msg, char *exec_msg)
{
    char temp_msg[OS_SIZE_1024 + 1] = "\0";

    /* If lf->location start with a ( was generated by remote agent and its
    * ID is included in lf->location if missing then it must have been
    * generated by the local analysisd, so prepend a false id tag */
    if (lf->location[0] != '(') {
        strcpy(exec_msg, "(local_source) ");
    }

    /* As now there are 2 different message formats (the JSON and the string)
    * ALL_AGENTS are not available, instead of that, we need to send a SPECIFIC
    * message to each agent after checking the agent version. */
    snprintf(temp_msg, OS_SIZE_1024,
            "%s %c%c%c %s",
            lf->location,
            NONE_C,
            (ar->location & REMOTE_AGENT) ? REMOTE_AGENT_C : NONE_C,
            (ar->location & SPECIFIC_AGENT || ar->location & ALL_AGENTS) ? SPECIFIC_AGENT_C : NONE_C,
            agent_id != NULL ? agent_id : "(null)");

    strcat(exec_msg, temp_msg);
    strcat(exec_msg, " ");
    strcat(exec_msg, msg);
}
