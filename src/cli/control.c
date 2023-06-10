#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd.h"
#include "cJSON.h"


static void controlCmd(cmdStatus_t *status);
static char *execute(const char *cmd);;
static cJSON * getObjectFromArrayByKey(cJSON *array, char *key);

void controlInit(void){
    cmdLoad("control", "Nicer wazuh-control", hintDefaultStyle, controlCmd);
}

static void controlCmd(cmdStatus_t *c){
    int st = cmdGetState(c);
    int green = 0;
    int fd, count;
    char *s;
    cJSON *root, *version, *revision, *type, *object, *daemon, *status;
    cJSON * data_array, *data_object;
    int array_size, i;
    char *cmds[] = {
        "/var/ossec/bin/wazuh-control -j info",
        "/var/ossec/bin/wazuh-control -j status",
        "/var/ossec/bin/wazuh-control -j start",
        "/var/ossec/bin/wazuh-control -j stop",
        "/var/ossec/bin/wazuh-control -j restart",
        "/var/ossec/bin/wazuh-control -j enable",
        "/var/ossec/bin/wazuh-control -j disable",
    };

    switch(st){
        case 0:
            s = execute(cmds[0]);
            if(s == NULL){
                cmdPrintf(c, "Ocurrio un error al ejecutar el comando.\r\n");
                cmdEnd(c);
                return;
            }

            root = cJSON_Parse(s);
            if(!root){
                cmdPrintf(c, "Bad response 1.\r\n");
                cmdEnd(c);
                free(s);
                return;
            }

            cJSON * data_array = cJSON_GetObjectItem(root, "data");
            if(!data_array || !cJSON_IsArray(data_array)){
                cmdPrintf(c, "Failed to get data array.\r\n");
                cJSON_Delete(root);
                cmdEnd(c);
                free(s);
                return;
            }

            version = getObjectFromArrayByKey(data_array, "WAZUH_VERSION");
            revision = getObjectFromArrayByKey(data_array, "WAZUH_REVISION");
            type = getObjectFromArrayByKey(data_array, "WAZUH_TYPE");

            if(!version || !revision || !type){
                cmdPrintf(c, "Information could not be retrieved\r\n");
            }

            cmdPrintf(c, "%sWazuh %s %s, rev.%s%s\r\n",
                ansiEraseScreen() ansiModeInverseSet(),
                cJSON_GetStringValue(type),
                cJSON_GetStringValue(version),
                cJSON_GetStringValue(revision),
                ansiModeResetAll()
            );
            free(s);
            cJSON_Delete(root);
            cmdSetState(c, 1);
        break;
        case 1:
            s = execute(cmds[1]);
            if(s == NULL){
                cmdPrintf(c, "Ocurrio un error al ejecutar el comando.\r\n");
                cmdEnd(c);
                return;
            }

            root = cJSON_Parse(s);
            if(!root){
                cmdPrintf(c, "Bad response 1.\r\n");
                cmdEnd(c);
                free(s);
                return;
            }

            data_array = cJSON_GetObjectItem(root, "data");
            if(!data_array || !cJSON_IsArray(data_array)){
                cmdPrintf(c, "Failed to get array data.\r\n");
                cJSON_Delete(root);
                cmdEnd(c);
                free(s);
                return;
            }

            array_size = cJSON_GetArraySize(data_array);
            cmdPrintf(c, "%20s | %10s\r\n", "Daemon", "status");
            for(i = 0; i < array_size; i++){
                object = cJSON_GetArrayItem(data_array, i);
                daemon = cJSON_GetObjectItemCaseSensitive(object, "daemon");
                status = cJSON_GetObjectItemCaseSensitive(object, "status");
                if(daemon && cJSON_IsString(daemon) && status && cJSON_IsString(status)){
                    green = strcmp(cJSON_GetStringValue(status), "running");
                    cmdPrintf(c, "%20s | %s%10s%s\r\n",
                        cJSON_GetStringValue(daemon),
                        green? ansiColorBackgroundRed(): ansiColorBackgroundGreen(),
                        cJSON_GetStringValue(status),
                        CSI"0m"
                    );
                }
            }

            free(s);
            cJSON_Delete(root);
            cmdEnd(c);
        break;
        default:break;
    }
}

static char *execute(const char *cmd){
    char buffer[1024] = {0};
    int len;
    FILE *p;
    char *r;
    
    p = popen(cmd, "r");

    if(!p)
        return NULL;
    
    if(fgets(buffer, sizeof(buffer), p) == NULL){
        pclose(p);
        return NULL;
    }
    len = strlen(buffer);
    r = calloc(1, len + 1);
    strcpy(r, buffer);
    return r;
}

static cJSON * getObjectFromArrayByKey(cJSON *array, char *key){
    cJSON *object = NULL, *item = NULL;
    int array_size, i;
    
    if(!array || !cJSON_IsArray(array)){
        return NULL;
    }

    array_size = cJSON_GetArraySize(array);
    for(i = 0; i < array_size; i++){
        object = cJSON_GetArrayItem(array, i);
        item = cJSON_GetObjectItemCaseSensitive(object, key);
        if(item && cJSON_IsString(item)){
            return item;
        }
    }
    return NULL;
}