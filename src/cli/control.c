#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd.h"
#include "cJSON.h"

typedef struct controlStatus_t{
    cmdStatus_t *cmd;
    int currentOption;
    int selectedOption;
    int start;
    int stop;
    int restart;
    int status;
    int end;
    keyActions_t actions;
}controlStatus_t;

static void controlCmd(cmdStatus_t *status);
static char *execute(const char *cmd);;
static cJSON * getObjectFromArrayByKey(cJSON *array, char *key);
static void printResult(controlStatus_t *c,  char *s);
static void printHeader(controlStatus_t *c, char *s);
static void refreshMenu(controlStatus_t *cs);

static void controlCursorRight(UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c);
static void controlCursorLeft (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c);
static void controlEnter      (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c);
static void controlTab        (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c);
static void controlEscape     (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c);

static const char *cmds[] = {
        "/var/ossec/bin/wazuh-control -j info",
        "/var/ossec/bin/wazuh-control -j stop",
        "/var/ossec/bin/wazuh-control -j start",
        "/var/ossec/bin/wazuh-control -j restart",
        "/var/ossec/bin/wazuh-control -j status",
        "/var/ossec/bin/wazuh-control -j enable",
        "/var/ossec/bin/wazuh-control -j disable",
    };


void controlInit(void){
    cmdLoad("control", "Nicer wazuh-control", hintDefaultStyle, controlCmd);
}

static void controlCmd(cmdStatus_t *c){
    int st;
    int fd, count;
    char *s;
    char key;
    cJSON *root, *version, *revision, *type, *object, *daemon, *status;
    cJSON * data_array, *data_object;
    int array_size, i;
    controlStatus_t *cs;
    keyAction_t action;

    st = cmdGetState(c);

    switch(st){
        case 0:
            /* Start command */
            cs = calloc(1, sizeof(controlStatus_t));
            if(cs == NULL){
                cmdPrintf(c, "There was an error while executing the command.\r\n");
                cmdEnd(c);
                return;
            }
            cs->cmd = c;
            cmdSetCustomData(c, cs, free);

            cs->actions.CursorRight = (void (*)(void *, stream_t *, char))controlCursorRight;
            cs->actions.CursorLeft  = (void (*)(void *, stream_t *, char))controlCursorLeft;
            cs->actions.Enter       = (void (*)(void *, stream_t *, char))controlEnter;
            cs->actions.Tab         = (void (*)(void *, stream_t *, char))controlTab;
            cs->actions.Escape      = (void (*)(void *, stream_t *, char))controlEscape;

            cmdSetState(c, 1);
        break;

        case 1:
            cs = cmdGetCustomData(c);
            /* Show process list */
            s = execute(cmds[0]);
                if(s == NULL){
                cmdPrintf(c, "There was an error while executing the command.\r\n");
                cmdEnd(c);
                return;
            }

            printHeader(cs, s);
            cs->selectedOption = 4;
            cmdSetState(cs, 2);
        case 2:
            cs = cmdGetCustomData(c);
            printf("Executing: %s\r\n", cmds[cs->selectedOption]);
            s = execute(cmds[cs->selectedOption]);
            if(s == NULL){
                cmdPrintf(c, "There was an error while executing the command.\r\n");
                cmdEnd(c);
                return;
            }
            if(cs->selectedOption == 4){
                printResult(cs, s);
                cmdDraw(c, "\r\n\r\n\r\n");
                refreshMenu(cs);
                cmdSetState(c, 3);
                cs->selectedOption = 0;
            }
            else{
                cs->selectedOption = 4;
                free(s);
            }
        break;

        case 3:
            /* Wait for option */
            cs = cmdGetCustomData(c);
            if( (cmdDataAvailable(c) != 0 && cmdGetChar(c, &key) == 1)){
                action = keyActionGet(cmdStreamGet(c), &(cs->actions), key);
                if(action){
                    action(cs, cmdStreamGet(c), key);
                }
            }

            if(cs->selectedOption){
                cmdPrintf(cs->cmd, ansiCursorPreviousLines(1));
                cmdPrintf(cs->cmd, "\r\n" ansiEraseLineCursorToEnd() "Please wait...");
                cmdPrintf(cs->cmd, ansiCursorPreviousLines(21));
                cmdSetState(c, 2);
            }

            if(cs->end)
                cmdEnd(c);
        break;
        case 4:
            cmdSetState(c, 2);
        break;
        case 5:
            cmdSetState(c, 2);
        break;
        case 6:
            cmdSetState(c, 2);
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
    printf("r: %s\r\n", r);
    return r;
}

static void printHeader(controlStatus_t *c, char *s){
    cJSON *root, *version, *revision, *type, *object, *daemon, *status;
    cJSON * data_array, *data_object;
    int array_size, i;
    int green = 0;

    root = cJSON_Parse(s);
    if(!root){
        cmdPrintf(c, "Bad response 1.\r\n");
        cmdEnd(c);
        free(s);
        return;
    }

    data_array = cJSON_GetObjectItem(root, "data");
    if(!data_array || !cJSON_IsArray(data_array)){
        cmdPrintf(c->cmd, "Failed to get data array.\r\n");
        cJSON_Delete(root);
        cmdEnd(c->cmd);
        free(s);
        return;
    }

    version = getObjectFromArrayByKey(data_array, "WAZUH_VERSION");
    revision = getObjectFromArrayByKey(data_array, "WAZUH_REVISION");
    type = getObjectFromArrayByKey(data_array, "WAZUH_TYPE");

    if(!version || !revision || !type){
        cmdPrintf(c->cmd, "Information could not be retrieved\r\n");
    }

    cmdDraw(c->cmd, ansiEraseScreen() "┌──────────────────────────────────┐\r\n");
    cmdDraw(c->cmd, "│%sWazuh %s %s, rev.%s    %s│\r\n",
        ansiModeInverseSet(),
        cJSON_GetStringValue(type),
        cJSON_GetStringValue(version),
        cJSON_GetStringValue(revision),
        ansiModeResetAll()
    );
    cmdDraw(c->cmd, "├─────────────────────┬────────────┤\r\n");
    free(s);
    cJSON_Delete(root);
}
static void printResult(controlStatus_t *c,  char *s){
    cJSON *root, *version, *revision, *type, *object, *daemon, *status;
    cJSON * data_array, *data_object;
    int array_size, i;
    int green = 0;

    root = cJSON_Parse(s);
    if(!root){
        cmdPrintf(c->cmd, "Bad response 1.\r\n");
        cmdEnd(c->cmd);
        free(s);
        return;
    }

    data_array = cJSON_GetObjectItem(root, "data");
    if(!data_array || !cJSON_IsArray(data_array)){
        cmdPrintf(c->cmd, "Failed to get array data.\r\n");
        cJSON_Delete(root);
        cmdEnd(c->cmd);
        free(s);
        return;
    }

    array_size = cJSON_GetArraySize(data_array);
    cmdDraw(c->cmd, "│%-20s │ %-10s │\r\n", "Daemon", "status");
    cmdDraw(c->cmd, "├─────────────────────┼────────────┤\r\n");
    for(i = 0; i < array_size; i++){
        object = cJSON_GetArrayItem(data_array, i);
        daemon = cJSON_GetObjectItemCaseSensitive(object, "daemon");
        status = cJSON_GetObjectItemCaseSensitive(object, "status");
        if(daemon && cJSON_IsString(daemon) && status && cJSON_IsString(status)){
            green = strcmp(cJSON_GetStringValue(status), "running");
            cmdDraw(c->cmd, "│%-20s │ %s%-10s%s │\r\n",
                cJSON_GetStringValue(daemon),
                green? ansiColorBackgroundRed(): ansiColorBackgroundGreen(),
                cJSON_GetStringValue(status),
                CSI"0m"
            );
        }
    }

    free(s);
    cJSON_Delete(root);
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

static void controlCursorRight  (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c){
    if(cs->currentOption < 3)
        cs->currentOption++;
    else
        cs->currentOption = 0;
    refreshMenu(cs);
}

static void controlCursorLeft(UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c){
    if(cs->currentOption > 0)
        cs->currentOption--;
    else
        cs->currentOption = 3;
    refreshMenu(cs);
}

static void controlEnter     (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c){
    cs->selectedOption = cs->currentOption + 1;
}

static void controlTab       (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c){
    controlCursorRight(cs, s, c);
    refreshMenu(cs);
}

static void controlEscape    (UNUSED controlStatus_t *cs, UNUSED stream_t *s, UNUSED char c){
    cs->end = 1;
}

static void refreshMenu(controlStatus_t *cs){
    cmdPrintf(cs->cmd, ansiCursorPreviousLines(3));
    cmdDraw(cs->cmd, "├─────────────────────┴────────────┤\r\n");
    cmdDraw(cs->cmd, "│%s STOP %s  %s START %s %s RESTART %s %s STATUS %s│\r\n",
        cs->currentOption == 0? ansiModeInverseSet():"", ansiModeInverseRes(),
        cs->currentOption == 1? ansiModeInverseSet():"", ansiModeInverseRes(),
        cs->currentOption == 2? ansiModeInverseSet():"", ansiModeInverseRes(),
        cs->currentOption == 3? ansiModeInverseSet():"", ansiModeInverseRes()
    );
        //cs->currentOption == 3? ansiModeInverseSet():"", 1?"ENABLE ":"DISABLE",  ansiModeInverseRes());
    cmdDraw(cs->cmd, "└──────────────────────────────────┘\r\n" ansiEraseLineCursorToEnd() "Done!");
}