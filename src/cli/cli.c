#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#include "hints.h"
#include "cli.h"
#include "liner.h"
#include "cmd.h"

typedef enum cliState_t{
    cliGetLinerSession = 0,
    cliGetLine,
    cliExecuteCommand,
    cliEnd
}cliState_t;

typedef struct cliSession_t{
    char prompt[100];
    cliState_t state;
    bool work;
    cmdStatus_t *currentCmd;
    linerSession_t *ls;
    stream_t *s;
    int userLevel;
}cliSession_t;

static hintStyle_t cliDefaultStyle = {
        .bold = 0,
        .back = colorBlack,
        .fore = colorGreen,
        .header = " <- [",
        .trailer = "]"
};

static void (*cliAutocompleteCb)(stringList_t *l, char *buf) = NULL;
static hint_t *(*cliHintsCb)(char *str) = NULL;

static void cliAutocompleteCallback(stringList_t *l, char *buf);
static hint_t *cliHintsCallback(char *str);

void cliSetAutocompleteCallback(void (*cb)(stringList_t *l, char *buf)){
    cliAutocompleteCb = cb;
}

void cliSetHintsCallback(hint_t * (*cb)(char *str)){
    cliHintsCb = cb;
}

static cmdStatus_t *cliParse(char *line, cliSession_t *cs){
    return cmdFind(cs, line);
}

static void exitCmd(cmdStatus_t *s){
    cmdExit(s);
    cmdEnd(s);
}

void cliExit(cliSession_t *s){
    s->work = false;
}

cliSession_t * cliInit(stream_t *s){
    cliSession_t *cs = calloc(1, sizeof(cliSession_t));
    if(!cs)
        return NULL;
    cs->s = s;

    cmdLoad("exit", "Exits wazuh-interpreter", cliDefaultStyle, exitCmd);
    return cs;
}

static hint_t *cliHintsCallback(char *str){
    return cliHintsCb(str);
}

static void cliAutocompleteCallback(stringList_t *l, char *buf){
    cliAutocompleteCb(l, buf);
}

void cliTask(cliSession_t *cs){
    char *line;

    if(!cs)
        return;

    cs->state = cliGetLinerSession;
    cs->work = true;
    cs->currentCmd = NULL;
    strcpy(cs->prompt, "wazuh:\\>");

    while(cs->work){
        switch(cs->state){
            case cliGetLinerSession:
                cs->ls = linerNewSession(cs->s);
                if(cs->ls) {
                    cs->state = cliGetLine;
                    linerSetHintCallback(cliHintsCallback);
                    linerSetAutoCompleteCallback(cs->ls, cliAutocompleteCallback);
                }
                break;
            case cliGetLine:
                line = liner(cs->ls);

                if (line == NULL){
                    break;
                }

                cs->currentCmd = cliParse(line, cs);
                if(cs->currentCmd){
                    linerHistoryAdd(cs->ls, line);
                    cs->state = cliExecuteCommand;
                }
                else{
                    if(strlen(line ))
                        cliPrintf(cs, "El comando es invalido\r\n");
                }
                break;

            case cliExecuteCommand:
                if(cmdExecute(cs->currentCmd) == false)
                    cs->state = cliEnd;
                break;

            case cliEnd:
                cs->state = cliGetLine;
                break;
        }
    }
}
int cliPrintf(cliSession_t *cs, char *fmt, ...){
    int len;
    va_list arg_ptr;

    va_start(arg_ptr, fmt);
    len = cliVPrintf(cs, fmt, arg_ptr);
    va_end(arg_ptr);

    return len;
}
int cliVPrintf(cliSession_t *cs, char *fmt, va_list arg){
    int len;
    char *p;
    va_list arg2;

    va_copy(arg2, arg);
    len = vsnprintf(NULL, 0, fmt, arg2);
    va_end(arg2);

    p =  malloc(len + 1);
    if(!p)
        return 0;

    len = vsprintf(p, fmt, arg);
    cs->s->write(p, len);

    free(p);
    return len;
}

void cliString(cliSession_t *cs, char *str){
    cs->s->write(str, strlen(str));
}

int cliDataAvailable(cliSession_t *cs){
    return cs->s->dataAvailable();
}

int cliGetChar(cliSession_t *cs, char *c){
    return cs->s->getChar(c);
}

stream_t * cliStreamGet(cliSession_t *cs){
    return cs->s;
}

int cliUserLevelGet(cliSession_t *cs){
    return cs->userLevel;
}