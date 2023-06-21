#include "ansi.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char *ansiCommand(char *command);
static void ansiAddToCleanList(void *p);

/* Screen modes */
char *ansiMode(int mode, int foreground, int background){
    char cmd[20] = CSI;
    char tmp[10];
    const char *values[] = {
            "1","22","2","22","3","23","4","24","5","25","7","27","8","28","9","29"
    };
    int count = 0, i;

    mode &= 0x1FFF;

    /* There is nothing to do!*/
    if( mode == 0 && foreground == 0 && background == 0)
        return "";

    if(mode){
        if(mode & MODE_RESET)
            return CSI"0m";

        for(i = 0 ; i < 16 ; i++){
            if(mode & 0x01 << i){
                if(count)
                    strcat(cmd, ";");
                strcat(cmd, values[i]);
                count++;
            }
        }
    }

    if(foreground > 29 && foreground < 40){
        snprintf(tmp, sizeof(tmp), "%d", foreground),
        strcat(cmd, count?";" :""); count++;
        strcat(cmd, tmp);
    }
    if(background > 39 && background < 50){
        snprintf(tmp, sizeof(tmp), "%d", background),
        strcat(cmd, count?";" :""); count++;
        strcat(cmd, tmp);
    }

    if(count){
        strcat(cmd, "m");
    }
    else
        return "";

    return ansiCommand(cmd);
}

/* Implements command and updates memory clean list */
static char *ansiCommand(char *command){
    char *p;
    int len = snprintf(NULL, 0,"\033[%s", command);
    p = malloc(len + 1);
    if(p)
        snprintf(p, len+1,"\033[%s", command);
    ansiAddToCleanList(p);
    for(int i=0;i<strlen(p);i++)
        printf("%02X",(unsigned char) p[i]);
    printf("\r\n"); fflush(stdout);
    return p;
}

static void ansiAddToCleanList(void *p){

}

static void ansiClean(void){

}

char *ansiOneParam(char command, int param){
    char temp[50];
    sprintf(temp, "%d%c", param, command);
    return ansiCommand(temp);
}

char *ansiTwoParam(char command, int param1, int param2){
    char temp[50];
    sprintf(temp, "%d;%d%c", param1, param2, command);
    return ansiCommand(temp);
}
