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

typedef struct agentControl_t{
    int selectedAgent;
    int count;
    int exit;
    int refresh;
}agentControl_t;

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
typedef struct agentStatus_t{
    cJSON *agentList;
    agentInfo_t *info;
    cJSON *agents;
    agentControl_t control;
    cmdStatus_t *cmd;
    int exit;
    cJSON *root;
    keyActions_t actions;
}agentStatus_t;

extern char shost[512];
static void agentsCmd(cmdStatus_t *s);
static void agents2Cmd(cmdStatus_t *s);
static void showAgentSet(cmdStatus_t *s, agentStatus_t *set, int setSize);

static void agentsCursorUp  (UNUSED agentControl_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsCursorDown(UNUSED agentControl_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsEnter     (UNUSED agentControl_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsTab       (UNUSED agentControl_t *status, UNUSED stream_t *s, UNUSED char c);
static void agentsEscape    (UNUSED agentControl_t *status, UNUSED stream_t *s, UNUSED char c);

void agentsInit(void){
    cmdLoad("agents", "Native agents managment", hintDefaultStyle, agentsCmd);
    cmdLoad("2agents", "manage-agent & manage-control wrapper", hintDefaultStyle, agents2Cmd);
}
static const char *cmds[] = {
    "/var/ossec/bin/agent_control -j -l",        // List all agents
    "/var/ossec/bin/agent_control -j -lc",       // List online agents
    "/var/ossec/bin/agent_control -j -ln",       // List offline agents
    "/var/ossec/bin/agent_control -j -i %s",     // Get agent %s info
    "/var/ossec/bin/agent_control -j -R -a",     // Restarts all agents
    "/var/ossec/bin/agent_control -j -R -u %s",  // Restarts agent %s
    "/var/ossec/bin/agent_control -j -r -a",     // Run integrity/rootkit on all agents
    "/var/ossec/bin/agent_control -j -r -u %s"   // Run integrity/rootkit on agent%s
};
static void agents2Cmd(cmdStatus_t *c){
    int st;
    int fd, count;
    char *s;
    char key;
    cJSON *version, *revision, *type, *object, *daemon;
    cJSON * data_array, *data_object;
    int array_size, i;
    agentStatus_t *a2s;
    keyAction_t action;

    st = cmdGetState(c);

    switch(st){
        case 0:
            /* Start command */
            a2s = calloc(1, sizeof(agentStatus_t));
            if(a2s == NULL){
                cmdPrintf(c, "There was an error while executing the command.\r\n");
                cmdEnd(c);
                return;
            }
            a2s->cmd = c;
            cmdSetCustomData(c, a2s, free);
            a2s->actions.CursorUp   = (void (*)(void *, stream_t *, char))agentsCursorUp;
            a2s->actions.CursorDown = (void (*)(void *, stream_t *, char))agentsCursorDown;
            a2s->actions.Enter      = (void (*)(void *, stream_t *, char))agentsEnter;
            a2s->actions.Tab        = (void (*)(void *, stream_t *, char))agentsTab;
            a2s->actions.Escape     = (void (*)(void *, stream_t *, char))agentsEscape;
            s = execute(cmds[0]);

            if(s == NULL){
                cmdPrintf(c, "There was an error while executing the command.\r\n");
                cmdEnd(c);
                return;        
            }

            printf(s);

            a2s->root = cJSON_Parse(s);

            if(!a2s->root){
                cmdPrintf(c, "Bad response 1.\r\n");
                cmdEnd(c);
                if(s)
                    free(s);
                return;
            }

            a2s->agents = cJSON_GetObjectItem(a2s->root, "data");
            printf("a2s->agents: %p\r\n", a2s->agents);
            a2s->control.count = cJSON_GetArraySize(a2s->agents);
            printf("cJSON_GetArraySize(a2s->agents): %d\r\n", a2s->control.count);
            a2s->control.selectedAgent = 0;
            a2s->control.refresh = 1;

            cmdDraw(c, "┌──────┬──────────────────────┬──────────────────────┬──────────────────────┐\r\n");
            cmdDraw(c, "│ ID   │  AGENT NAME          │ AGENT IP             │ AGENT STATUS         │\r\n");
            cmdDraw(c, "├──────┼──────────────────────┼──────────────────────┼──────────────────────┤\r\n");

            cmdSetState(c, 1);
        break;

        case 1:
            a2s = (agentStatus_t *)cmdGetCustomData(c);
            if( (cmdDataAvailable(c) != 0 && cmdGetChar(c, &key) == 1)){
                printf("line:%d\r\n", __LINE__); fflush(stdout);
                action = keyActionGet(cmdStreamGet(c), &(a2s->actions), key);
                if(action)
                    action(&(a2s->control), cmdStreamGet(c), key);
            }
            
            if(a2s->control.refresh){
                a2s->control.refresh = 0;
                showAgentSet(c, a2s, 10);
            }
            
            if(a2s->exit){
                showAgentSet(c, a2s, 10);
                cmdSetState(c, 2);
            }
            
        break;
        case 2:
            a2s = (agentStatus_t *)cmdGetCustomData(s);
            cJSON_Delete(a2s->root);
            cmdPrintf(c, ansiEraseScreen());
            cmdEnd(c);
        break;
    }       
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
            status->control.count = cJSON_GetArraySize(status->agents);
            status->control.selectedAgent = 0;
            status->control.refresh = 1;

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
                    action(&(status->control),  cmdStreamGet(s), key);
            }
            if(status->control.refresh){
                status->control.refresh = 0;
                showAgentSet(s, status, 10);
            }
            if(status->control.exit){
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
    //cJSON *agents = cJSON_GetObjectItem(set->root, "data");
    cJSON * item, *id, *name, *ip, *stat;
    do{
        item = cJSON_GetArrayItem(set->agents, i);

        if(item){
            id = cJSON_GetObjectItem(item, "id");
            name = cJSON_GetObjectItem(item, "name");
            ip = cJSON_GetObjectItem(item, "ip");
            stat = cJSON_GetObjectItem(item, "status");
            cmdDraw(s, "│ %s%-4s │ %-20s │ %-20s │ %-20s\033[0m │\r\n", 
                set->control.selectedAgent == i? "\033[47m\033[30m":"",
                id->valuestring,
                name->valuestring,
                ip->valuestring,
                stat->valuestring
            );
        }
        i++;
    }while(item && i < setSize);

    cmdDraw(s, "└──────┴──────────────────────┴──────────────────────┴──────────────────────┘\r\n");
    cmdPrintf(s, "\033[0m%s", ansiCursorUp(set->control.count+1));
}

static void agentsCursorUp  (UNUSED agentControl_t *ctrl, UNUSED stream_t *s, UNUSED char c){
    printf("ctrl->selectedAgent: %d\r\n", ctrl->selectedAgent);
    if(ctrl->selectedAgent){
        printf("ctrl->selectedAgent: %d\r\n", ctrl->selectedAgent);
        ctrl->selectedAgent--;
        ctrl->refresh = 1;
    }
    printf("ctrl->selectedAgent: %d\r\n", ctrl->selectedAgent);
}

static void agentsCursorDown(UNUSED agentControl_t *ctrl, UNUSED stream_t *s, UNUSED char c){
    printf("ctrl->selectedAgent: %d\r\n", ctrl->selectedAgent);
    if(ctrl->selectedAgent < ctrl->count-1){
        printf("ctrl->selectedAgent: %d\r\n", ctrl->selectedAgent);
        ctrl->selectedAgent++;
        printf("ctrl->selectedAgent: %d\r\n", ctrl->selectedAgent);
        ctrl->refresh = 1;
    }
    printf("ctrl->selectedAgent: %d\r\n", ctrl->selectedAgent);
}

static void agentsEnter     (UNUSED agentControl_t *ctrl, UNUSED stream_t *s, UNUSED char c){

}

static void agentsTab       (UNUSED agentControl_t *ctrl, UNUSED stream_t *s, UNUSED char c){

}

static void agentsEscape    (UNUSED agentControl_t *ctrl, UNUSED stream_t *s, UNUSED char c){
    ctrl->exit = 1;
}
