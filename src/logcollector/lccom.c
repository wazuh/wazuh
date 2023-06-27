/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * Mar 12, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "logcollector.h"
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"
#include "state.h"

#define LEN_LOCATION   (10)
#define LEN_BOOL_STR   (5)
#define MAX_LEN_HEADER (150)
#define SIZE_1KB       (1024)


bool getObjectIndexFromJsonStats(char *outjson_aux, size_t *ptrs, uint16_t *amountObj );
uint16_t checkJson64k(char *outjson, uint16_t initialIndex, uint16_t amountObj, size_t *ptrs, char *output, size_t *sizeOutput);
void addHeader(char *strJson, char *bufferTmp, char *headerData, size_t lenHeaderData, char *header, size_t lenHeader);
void addHeaderGlobal(char *strJson, char *bufferTmp, char *headerData, size_t lenHeaderData, char *header, size_t lenHeader);
void addClosingTags(char *strJson);
void addHeaderInterval(char *strJson, char *bufferTmp, char *headerData, size_t lenHeaderData, char *header, size_t lenHeader);
void extractHeadersFromJson(char *buffJson, char *headerGlobal, char *headerInterval, char *headerData, size_t *LenHeaderInterval, size_t *LenHeaderData, size_t *LenHeaderGlobal);
void addStartandEndTagsToJsonStrBlock(char *buffJson, char *headerGlobal, char *headerInterval, char *headerData, size_t LenHeaderInterval, size_t LenHeaderData, size_t LenHeaderGlobal, size_t counter, bool getNextPage);
bool isJsonUpdated(void);
uint16_t getJsonStr64kBlockFromLatestIndex(char **output, bool getNextPage);

size_t lccom_dispatch(char * command, char ** output){

    const char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            mdebug1("LCCOM getconfig needs arguments.");
            os_strdup("err LCCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return lccom_getconfig(rcv_args, output);

    } else if (strcmp(rcv_comm, "getstate") == 0) {
        return lccom_getstate(output, false);
    } else if (strcmp(rcv_comm, "getstate next") == 0) {
        return lccom_getstate(output, true);
    } else {
        mdebug1("LCCOM Unrecognized command '%s'.", rcv_comm);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

bool getObjectIndexFromJsonStats(char *outjson_aux, size_t *ptrs, uint16_t *amountObj ) {
    bool isReadyIndex = false;
    int i = 0;
    ptrs[i++] = (size_t)outjson_aux;   //ptrs[0] inicio de estadisticas sin 1er location

    while (outjson_aux != NULL) {
        outjson_aux = strstr(outjson_aux, "\"location\"");
        if (outjson_aux == NULL) {
            isReadyIndex =  true;
            break;
        }
        ptrs[i++] = (size_t)(&outjson_aux[0]);
        outjson_aux = outjson_aux + LEN_LOCATION ;
    }
    *amountObj = i;
    return isReadyIndex;
}

uint16_t checkJson64k(char *outjson, uint16_t initialIndex, uint16_t amountObj, size_t *ptrs, char *output, size_t *sizeOutput) {

    size_t counter = 0;
    uint16_t currentIndex = (initialIndex == 0) ? 1 : initialIndex;
    uint16_t lastIndex = 0;

    if (output != NULL && outjson != NULL) {
        while ( currentIndex < amountObj ) {
            size_t len = ptrs[currentIndex] - ptrs[currentIndex-1];
            size_t currentLength = len;
            counter += currentLength;
            if ( counter < OS_MAXSTR - SIZE_1KB) {
                currentIndex++;
            } else {
                memset(output,0, OS_MAXSTR);
                memcpy(output, (const char *)ptrs[initialIndex], ptrs[currentIndex-1] - ptrs[initialIndex]);
                lastIndex = currentIndex - 1;
                counter = 0;
                currentIndex = 1;
                break;
            }
        }

        if(currentIndex != 1 && (counter < OS_MAXSTR - SIZE_1KB)) {
            memset(output,0, OS_MAXSTR);
            strncpy(output, outjson + ptrs[initialIndex] - ptrs[0], ptrs[currentIndex-1] - ptrs[initialIndex-1] + strlen(outjson + ptrs[currentIndex-1] -ptrs[0]));
        }
    }
    *sizeOutput = counter;
    return currentIndex == 1 ? lastIndex : currentIndex;
}

void addHeader(char *strJson, char *bufferTmp, char *headerData, size_t lenHeaderData, char *header, size_t lenHeader) {
    if (bufferTmp != NULL && strJson != NULL) {
        memcpy(bufferTmp, headerData, lenHeaderData);
        memcpy(bufferTmp + lenHeaderData, header, lenHeader);
        memcpy(bufferTmp + lenHeaderData + lenHeader, strJson, OS_MAXSTR - lenHeaderData - lenHeader);
        memset(strJson,0 , OS_MAXSTR);
        memcpy(strJson, bufferTmp, OS_MAXSTR);
    }
}

void addHeaderGlobal(char *strJson, char *bufferTmp, char *headerData, size_t lenHeaderData, char *header, size_t lenHeader) {
    addHeader(strJson, bufferTmp, headerData, lenHeaderData, header, lenHeader);
}

void addClosingTags(char *strJson) {
    if (strJson != NULL) {
        memcpy(strJson + strlen(strJson) - 2,"]}}}", 4); // 2 -> ,{  4-> ]}}}
    }
}

void addHeaderInterval(char *strJson, char *bufferTmp, char *headerData, size_t lenHeaderData, char *header, size_t lenHeader) {
    addHeader(strJson, bufferTmp, headerData, lenHeaderData, header, lenHeader);
}

void extractHeadersFromJson(char *buffJson, char *headerGlobal, char *headerInterval, char *headerData, size_t *LenHeaderInterval, size_t *LenHeaderData, size_t *LenHeaderGlobal) {
    char *ptrInterval = NULL;
    char *ptrFilesInterval = NULL;
    char *ptrGlobal = NULL;
    char *ptrFilesGlobal = NULL;
    char *ptrData = NULL;

    if (buffJson != NULL) {
        if (headerGlobal != NULL && headerInterval != NULL) {
            if ((ptrGlobal = strstr(buffJson, "\"global\"")) != NULL) {
                if ((ptrFilesGlobal = strstr(ptrGlobal , "\"files\"")) != NULL) {
                    *LenHeaderGlobal = ptrFilesGlobal - ptrGlobal + strlen("\"files\"") + 3;
                    memcpy(headerGlobal, ptrGlobal, *LenHeaderGlobal);
                }
            }
        }

        if (headerInterval != NULL && LenHeaderInterval != NULL) {
            if ((ptrInterval = strstr(buffJson, "\"interval\"")) != NULL) {
                if ((ptrFilesInterval = strstr(ptrInterval , "\"files\"")) != NULL) {
                    *LenHeaderInterval = ptrFilesInterval - ptrInterval + strlen("\"files\"") + 3;
                    memcpy(headerInterval, ptrInterval, *LenHeaderInterval);
                }
            }
        }

        if (headerData != NULL && LenHeaderData != NULL) {
            if ((ptrData = strstr(buffJson, "\"data\"")) != NULL) {
                *LenHeaderData = ptrData + strlen("\"files\"") - buffJson + 1;
                memcpy(headerData, buffJson, *LenHeaderData);
            }
        }
    }
}

void addStartandEndTagsToJsonStrBlock(char *buffJson, char *headerGlobal, char *headerInterval, char *headerData, size_t LenHeaderInterval, size_t LenHeaderData, size_t LenHeaderGlobal, size_t counter, bool getNextPage) {
    static bool flag_interval = false;
    static bool flag_global   = false;
    char bufferTmp[OS_MAXSTR] = {0};
    memset(bufferTmp,0,OS_MAXSTR);

    /* starts from the first page when the request is getstate*/
    if (getNextPage == false) {
        flag_interval = false;
        flag_global   = false;
    }

    if (buffJson != NULL && headerGlobal != NULL && headerInterval != NULL && headerData != NULL) {
        if (flag_global == false) {
            if (strstr(buffJson, "{\"error\"") != NULL) {
                if (strstr(buffJson, "\"data\"") != NULL) {
                    if (strstr(buffJson, "\"global\"") != NULL) {
                        flag_global = true;
                        if (strstr(buffJson, "\"files\"") != NULL) {
                            if (strstr(buffJson, "\"interval\"") != NULL) {
                                flag_interval = true;
                                if (counter == 0){
                                    /* 1: find error,data,global,files,intervals,files
                                            and greather than 64k
                                    */
                                    addClosingTags(buffJson);
                                } else {
                                    /* 2: find error,data,global,files,intervals,files
                                            and lower than 64k, it closes self
                                    */
                                    flag_interval = false;
                                    flag_global = false;
                                }
                            } else {
                                /* 3:
                                find error,data,global,files, dont find intervals,files
                                and greather than 64k
                                */
                                addClosingTags(buffJson);
                                flag_interval = false;
                            }
                        }
                    } else {
                        flag_global = false;
                        mwarn("global no found\r\n");
                    }
                }
            }
        } else if (flag_interval == false && flag_global == true) {
            if (strstr(buffJson, "\"interval\"") != NULL) {
                flag_interval = true;
                if (counter == 0 ) {
                    /* 4: remainder of first block onwards, already find global
                    find intervals,files y greather than 64k
                    */
                    addClosingTags(buffJson);
                    addHeaderGlobal(buffJson, bufferTmp, headerData, LenHeaderData, headerGlobal, LenHeaderGlobal);
                } else  {
                    /* 5: remainder of first block onwards, already find global
                    find intervals,files y lower than 64k, it closes self
                    */
                    addHeaderGlobal(buffJson, bufferTmp, headerData, LenHeaderData, headerGlobal, LenHeaderGlobal);
                    flag_interval = false;
                }
            } else {
                /* 6: remainder of first block onwards, already find global
                intervals,files not found y greather than 64k
                always  global and interval are full json therefore dont is need lower than 64k
                */
                addClosingTags(buffJson);
                addHeaderGlobal(buffJson, bufferTmp, headerData, LenHeaderData, headerGlobal, LenHeaderGlobal);
                flag_interval = false;
            }
        } else if (flag_interval == true && flag_global == true) {
            if (counter == 0) {
                /* 7:
                remainder of interval block onwards
                greather than 64k
                */
                addClosingTags(buffJson);
                addHeaderInterval(buffJson, bufferTmp, headerData, LenHeaderData, headerInterval, LenHeaderInterval);


            } else {
                /* 8:
                remainder of interval block onwards
                lower than 64k, it closes self
                */
                addHeaderInterval(buffJson, bufferTmp, headerData, LenHeaderData, headerInterval, LenHeaderInterval);
                flag_interval = false;
                flag_global = false;
            }
        }
    }
}

bool isJsonUpdated(void) {
    static time_t mtime_prev = 0;
    time_t mtime_current = 0;
    struct stat outstat;
    struct tm *tm_stat;
    char date_string[256];
    bool isJsonUpdated = false;

    /*should be reset index to the first page when some files are added or removed*/
    if (stat(LOGCOLLECTOR_STATE, &outstat) == 0) {
        tm_stat = localtime(&outstat.st_mtime);
        /* Get localized date string. */
        strftime(date_string, sizeof(date_string), "%c", tm_stat);
        mtime_current = mktime(tm_stat);
        mdebug2(" %s %s\n", date_string, LOGCOLLECTOR_STATE);
    }

    if (difftime(mtime_current, mtime_prev) != 0 && mtime_prev != 0) {
        mdebug2("cJSON has updated");
        isJsonUpdated = true;
    }
    mtime_prev = mtime_current;

    return isJsonUpdated;
}

uint16_t getJsonStr64kBlockFromLatestIndex(char **output, bool getNextPage) {
    char buffer[OS_MAXSTR] = {0};
    char headerGlobal[MAX_LEN_HEADER] = {0};
    char headerInterval[MAX_LEN_HEADER] = {0};
    char headerData[MAX_LEN_HEADER] = {0};
    bool isReadyIndex = 0;
    uint16_t i = 0;
    static uint16_t apiLatestIndex = 0;
    size_t ptrs[OS_MAXSTR] = {0};
    size_t counter = 0;
    size_t LenHeaderInterval = 0;
    size_t LenHeaderData = 0;
    size_t LenHeaderGlobal = 0;

    isReadyIndex = getObjectIndexFromJsonStats (*output, ptrs, &i);
    apiLatestIndex = (getNextPage == false) ? 0 : apiLatestIndex;
    extractHeadersFromJson(*output, headerGlobal, headerInterval, headerData, &LenHeaderInterval, &LenHeaderData, &LenHeaderGlobal);

    if (isReadyIndex) {
        apiLatestIndex = checkJson64k (*output, apiLatestIndex, i, ptrs, buffer, &counter);
        addStartandEndTagsToJsonStrBlock (buffer, headerGlobal, headerInterval, headerData,
                                        LenHeaderInterval, LenHeaderData, LenHeaderGlobal, counter, getNextPage);

        if (apiLatestIndex == i){
            apiLatestIndex = 0;
            i = 0;
            memset(headerGlobal, 0, MAX_LEN_HEADER);
            memset(headerInterval, 0, MAX_LEN_HEADER);
            memset(headerData, 0, MAX_LEN_HEADER);
            memset(ptrs, 0, OS_MAXSTR - 1);
            LenHeaderInterval = 0;
            LenHeaderData = 0;
            LenHeaderGlobal = 0;
        }
        os_free(*output);
        os_strdup (buffer, *output);
    }
    return  strlen(buffer);
}

void replaceBoolToStr(char *buffer, char *match, bool value) {
    char *ptr = NULL;
    if (buffer != NULL && match != NULL) {
        if ((ptr = strstr(buffer, match)) != NULL) {
            memcpy(ptr + strlen(match), value == true ? "true " : "false", LEN_BOOL_STR);
        }
    }
}

size_t lccom_getstate(char ** output, bool getNextPage) {
    size_t retval = 0;
    cJSON * state_json = NULL;
    cJSON * w_packet = cJSON_CreateObject();
    if (state_json = w_logcollector_state_get(), state_json == NULL) {
        cJSON_AddNumberToObject(w_packet, "error", 1);
        cJSON_AddObjectToObject(w_packet, "data");
        cJSON_AddStringToObject(w_packet, "message", "Statistics unavailable");
        mdebug1("At LCCOM getstate: Statistics unavailable");
    } else {
        cJSON_AddNumberToObject(w_packet, "error", 0);
        cJSON_AddFalseToObject(w_packet, "remaining");
        cJSON_AddFalseToObject(w_packet, "json_updated");
        cJSON_AddItemToObject(w_packet, "data", state_json);
    }
    *output = cJSON_PrintUnformatted(w_packet);
    cJSON_Delete(w_packet);

    if (strlen(*output) > OS_MAXSTR) {
        /*getNextPage = true; only for test*/
        retval = getJsonStr64kBlockFromLatestIndex(output, getNextPage);
        replaceBoolToStr(*output, "\"remaining\":", strlen(*output) >= OS_MAXSTR - (2*SIZE_1KB));
        replaceBoolToStr(*output, "\"json_updated\":", isJsonUpdated());
    } else {
        retval = strlen(*output);
    }
    return retval;
}

size_t lccom_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "localfile") == 0){
        if (cfg = getLocalfileConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "socket") == 0){
        if (cfg = getSocketConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getLogcollectorInternalOptions(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else {
        goto error;
    }
error:
    mdebug1("At LCCOM getconfig: Could not get '%s' section", section);
    os_strdup("err Could not get requested section", *output);
    return strlen(*output);
}


#ifndef WIN32
void * lccom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(LC_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", LC_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At lccom_main(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At lccom_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At lccom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("At lccom_main(): OS_RecvSecureTCP(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        case OS_MAXLEN:
            merror("Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            length = lccom_dispatch(buffer, &response);
            OS_SendSecureTCP(peer, length, response);
            free(response);
            close(peer);
        }
        free(buffer);
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}

#endif
