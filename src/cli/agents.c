#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <termios.h>
#include <ncurses.h>

#include "cmd.h"
#include "shared.h"
#include "cJSON.h"
#include "addagent/manage_agents.h"
#include "hints.h"

typedef struct agentStatus_t{
    cJSON *agents;
    int selectedAgent;
    int first;
    int count;
    cJSON *root;
}agentStatus_t;

extern char shost[512];
static void agentsCmd(cmdStatus_t *s);
static void showAgentSet(cmdStatus_t *s, agentStatus_t *set, int setSize);

void agentsInit(void){
    printf("Cargando agents\r\n");
    cmdLoad("agents", "list agents", hintDefaultStyle, agentsCmd);
}

static void agentsCmd(cmdStatus_t *s){
    agentStatus_t *status;
    int st = cmdGetState(s);
    char *render;
    cJSON *item;
    char key;

    switch(st){
        case 0: /* Command initializacion */

            /* Prepare custom data */
            status = calloc(1, sizeof(agentStatus_t));
            if(!status){
                cmdPrintf(s, "Ocurrio un error. No es posible ejecutar el comando\r\n");
                cmdEnd(s);
                return;
            }
            cmdSetCustomData(s, status);

            /* Obtain agent information */
            status->agents = (cJSON*)calloc(1, sizeof(cJSON));
            if(!status->agents){
                cmdPrintf(s, "Ocurrio un error2 . No es posible ejecutar el comando\r\n");
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
            status->first = 1;

            cmdPrintf(s, "ID  |  AGENT NAME | AGENT IP | AGENT STATUS\r\n");

            cmdSetState(s, 1);
            //initscr();
            /*cbreak();
            noecho();
            //scrollok(stdscr, TRUE);
            nodelay(stdscr, TRUE);*/
        break;

        case 1:
            status = (agentStatus_t *)cmdGetCustomData(s);
            if( (cmdDataAvailable(s) != 0 && cmdGetChar(s, &key) == 1) || status->first){
                if(key == 'g' || status->first){
                    status->first = 0;
                    showAgentSet(s, status, 10);
                    status->selectedAgent++;
                    if(status->selectedAgent == 3)
                        status->selectedAgent = 0;
                }
            }
            if(key == 'q')
                cmdSetState(s, 2);

            // Closing JSON Object array
            //char *render = cJSON_PrintUnformatted(status->root);

//            printf("Count: %d\n", status->count);
//            printf("%s", render);
//            free(render);
//            printf("\n");

            // cmdSetState(s, st + 1);
        break;
        case 2:
            status = (agentStatus_t *)cmdGetCustomData(s);
            cJSON_Delete(status->root);
            cmdEnd(s);
            //endwin();
        break;
    }
}

/*void get_agent_info(cJSON *agents, agentStatus_t *status){

}
*/
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
            cmdPrintf(s, "%s%s | %s | %s | %s\033[0m\r\n", 
                set->selectedAgent == i? "\033[47m\033[30m":"",
                id->valuestring,
                name->valuestring,
                ip->valuestring,
                stat->valuestring
            );
        }
        i++;
    }while(item && i < setSize);
    printf("Out Show agents\r\n");
    cmdPrintf(s, "\033[0m\033[%dA", set->count);
}
