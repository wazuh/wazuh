#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <termios.h>

#include "cmd.h"
#include "shared.h"
#include "addagent/manage_agents.h"
#include "hints.h"
#include "action.h"
#include "common.h"

typedef struct agentStatus_t{
    cJSON *agents;
    int selectedAgent;
    int refresh;
    int exit;
    int count;
    cJSON *root;
    keyActions_t actions;
}agentStatus_t;

typedef struct agentInfo_t{
    char *id;
    char *name;
    char *ip;
    char *status;
    char *os;
    char *version;
    char *configSum;
    char *mergedSum;
    char *lastKeepAlive;
    char *syscheckTime;
    char *syscheckEndTime;
}agentInfo_t;
typedef struct agents2Status_t{
    cJSON *agentList;
    agentInfo_t *info;
    int selectedAgent;
    int refresh;
    int exit;
    int count;
    cJSON *root;
    keyActions_t actions2;
};

extern char shost[512];
static void agentsCmd(cmdStatus_t *s);
static void agentsCmd2(cmdStatus_t *s);
static void showAgentSet(cmdStatus_t *s, agentStatus_t *set, int setSize);

static void agentsCursorUp  (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsCursorDown(UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsEnter     (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsTab       (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsEscape    (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c);

void agentsInit(void){
    cmdLoad("agents", "Native agents managment", hintDefaultStyle, agentsCmd);
    cmdLoad("agents2", "manage-agent & manage-control wrapper", hintDefaultStyle, agentsCmd2);
}

static void agentsCmd2(cmdStatus_t *s){

}

static void agentsCmd(cmdStatus_t *s){
    agentStatus_t *status;
    int st = cmdGetState(s);
    char *render;
    cJSON *item;
    char key;
    keyAction_t action;

    switch(st){
        case 0: /* Command initializacion */
            /* Prepare custom data */
            status = calloc(1, sizeof(agentStatus_t));
            if(!status){
                cmdPrintf(s, "An error ocurred reserving memory. The command cannot continue\r\n");
                cmdEnd(s);
                return;
            }
            cmdSetCustomData(s, status, free);

            status->actions.CursorUp   = (void (*)(void *, stream_t *, char))agentsCursorUp;
            status->actions.CursorDown = (void (*)(void *, stream_t *, char))agentsCursorDown;
            status->actions.Enter      = (void (*)(void *, stream_t *, char))agentsEnter;
            status->actions.Tab        = (void (*)(void *, stream_t *, char))agentsTab;
            status->actions.Escape     = (void (*)(void *, stream_t *, char))agentsEscape;

            /* Obtain agent information */
            status->agents = (cJSON*)calloc(1, sizeof(cJSON));
            if(!status->agents){
                cmdPrintf(s, "An error ocurred reserving memory. The command cannot continue\r\n");
                cmdEnd(s);
                return;
            }

            print_agents(1, 0, 0, 0, status->agents);

            status->root = cJSON_CreateObject();

            status->agents = cJSON_CreateArray();
            if (!(status->root && status->agents)){
	            exit(1);
                cmdEnd(s);
            }

            cJSON_AddNumberToObject(status->root, "error", 0);
            cJSON_AddItemToObject(status->root, "data", status->agents);

	        item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "id", "000");
            cJSON_AddStringToObject(item, "name", shost);
            cJSON_AddStringToObject(item, "ip", "127.0.0.1");
            cJSON_AddStringToObject(item, "status", "server_status");
            cJSON_AddItemToArray(status->agents, item);
            
            print_agents(1, 0, 0, 0, status->agents);

            status->count = cJSON_GetArraySize(status->agents);
            status->selectedAgent = 0;
            status->refresh = 1;

            cmdDraw(s, "┌──────┬──────────────────────┬──────────────────────┬──────────────────────┐\r\n");
            cmdDraw(s, "│ ID   │  AGENT NAME          │ AGENT IP             │ AGENT STATUS         │\r\n");
            cmdDraw(s, "├──────┼──────────────────────┼──────────────────────┼──────────────────────┤\r\n");

            cmdSetState(s, 1);
        break;

        case 1:
            status = (agentStatus_t *)cmdGetCustomData(s);
            if( (cmdDataAvailable(s) != 0 && cmdGetChar(s, &key) == 1)){
                action = keyActionGet(cmdStreamGet(s), &(status->actions), key);
                if(action)
                    action(status, s, key);
            }
            if(status->refresh){
                status->refresh = 0;
                showAgentSet(s, status, 10);
            }
            if(status->exit){
                showAgentSet(s, status, 10);
                cmdSetState(s, 2);
            }
        break;
        case 2:
            status = (agentStatus_t *)cmdGetCustomData(s);
            cJSON_Delete(status->root);
            cmdPrintf(s, ansiEraseScreen());
            cmdEnd(s);
        break;
    }
}

static void showAgentSet(cmdStatus_t *s, agentStatus_t *set, int setSize){
    int i = 0;
    cJSON *agents = cJSON_GetObjectItem(set->root, "data");
    cJSON * item, *id, *name, *ip, *stat;
    do{
        item = cJSON_GetArrayItem(agents, i);

        if(item){
            id = cJSON_GetObjectItem(item, "id");
            name = cJSON_GetObjectItem(item, "name");
            ip = cJSON_GetObjectItem(item, "ip");
            stat = cJSON_GetObjectItem(item, "status");
            cmdDraw(s, "│ %s%-4s │ %-20s │ %-20s │ %-20s\033[0m │\r\n", 
                set->selectedAgent == i? "\033[47m\033[30m":"",
                id->valuestring,
                name->valuestring,
                ip->valuestring,
                stat->valuestring
            );
        }
        i++;
    }while(item && i < setSize);

    cmdDraw(s, "└──────┴──────────────────────┴──────────────────────┴──────────────────────┘\r\n");
    cmdPrintf(s, "\033[0m%s", ansiCursorUp(set->count+1));
}

static void agentsCursorUp  (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c){
    if(status->selectedAgent){
        status->selectedAgent--;
        status->refresh = 1;
    }
}

static void agentsCursorDown(UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c){
    if(status->selectedAgent < status->count-1){
        status->selectedAgent++;
        status->refresh = 1;
    }
}

static void agentsEnter     (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c){

}

static void agentsTab       (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c){

}

static void agentsEscape    (UNUSED agentStatus_t *status, UNUSED stream_t *s, UNUSED char c){
    status->exit = 1;
}
