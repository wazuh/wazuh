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
    linerSession_t *linerSession;
    stream_t *stream;
    int userLevel;
}cliSession_t;

static hintStyle_t cliDefaultStyle = {
        .bold = 0,
        .back = colorBlack,
        .fore = colorGreen,
        .header = " <- [",
        .trailer = "]"
};

static void (*cliAutocompleteCb)(stringList_t *autocompleteList, char *key) = NULL;
static hint_t *(*cliHintsCb)(char *str) = NULL;

static void cliAutocompleteCallback(stringList_t *autocompleteList, char *key);
static hint_t *cliHintsCallback(char *str);
static int cliPrintf(cliSession_t *cliSession, char *fmt, ...);

void cliSetAutocompleteCallback(void (*cb)(stringList_t *autocompleteList, char *key)){
    cliAutocompleteCb = cb;
}

void cliSetHintsCallback(hint_t * (*callback)(char *str)){
    cliHintsCb = callback;
}

static cmdStatus_t *cliParse(char *line, cliSession_t *cliSession){
    return cmdFind(cliSession, line);
}

static void exitCmd(cmdStatus_t *cmdStatus){
    cmdExit(cmdStatus);
    cmdEnd(cmdStatus);
}

void cliExit(cliSession_t *cliSession){
    cliSession->work = false;
}

void cliInit(void){
    cmdInit();
}

cliSession_t * cliNewSession(stream_t *stream){
    cliSession_t *cliSession = calloc(1, sizeof(cliSession_t));
    if(!cliSession)
        return NULL;
    cliSession->stream = stream;

    cmdLoad("exit", "Exits wazuh-interpreter", cliDefaultStyle, exitCmd);
    return cliSession;
}

static hint_t *cliHintsCallback(char *str){
    return cliHintsCb(str);
}

static void cliAutocompleteCallback(stringList_t *autocompleteList, char *buf){
    cliAutocompleteCb(autocompleteList, buf);
}

void cliSetPrompt(cliSession_t *cliSession, char *prompt){
    int len;
    if(!cliSession || !prompt)
        return;

    len = strlen(prompt);
    if(!len || len > 99)
        return;
    strcpy(cliSession->prompt, prompt);
}

void cliTask(cliSession_t *cliSession){
    char *line;

    if(!cliSession)
        return;

    cliSession->state = cliGetLinerSession;
    cliSession->work = true;
    cliSession->currentCmd = NULL;
    strcpy(cliSession->prompt, "wazuh:\\>");

    while(cliSession->work){
        switch(cliSession->state){
            case cliGetLinerSession:
                cliSession->linerSession = linerNewSession(cliSession->stream);
                if(cliSession->linerSession) {
                    cliSession->state = cliGetLine;
                    linerSetHintCallback(cliHintsCallback);
                    linerSetAutoCompleteCallback(cliSession->linerSession, cliAutocompleteCallback);
                }
                break;
            case cliGetLine:
                line = liner(cliSession->linerSession);

                if (line == NULL){
                    break;
                }

                cliSession->currentCmd = cliParse(line, cliSession);
                if(cliSession->currentCmd){
                    linerHistoryAdd(cliSession->linerSession, line);
                    cliSession->state = cliExecuteCommand;
                }
                else{
                    if(strlen(line ))
                        cliPrintf(cliSession, "El comando es invalido\r\n");
                }
                break;

            case cliExecuteCommand:
                /* TODO:
                    If command is poorly coded and hangs, it will hang the CLI.
                    An threaded approch could be used where every execution is done
                    on a separate thread and a key combination is reserved for the CLI
                    to "kill" the command.
                */
                if(cmdExecute(cliSession->currentCmd) == false)
                    cliSession->state = cliEnd;
                break;

            case cliEnd:
                cliSession->state = cliGetLine;
                break;
        }
    }
}

static int cliPrintf(cliSession_t *cliSession, char *fmt, ...){
    int len;
    va_list arg_ptr;

    va_start(arg_ptr, fmt);
    len = cliVPrintf(cliSession, fmt, arg_ptr);
    va_end(arg_ptr);

    return len;
}
int cliVPrintf(cliSession_t *cliSession, char *fmt, va_list arg){
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
    cliSession->stream->write(p, len);

    free(p);
    return len;
}

void cliString(cliSession_t *cliSession, char *str){
    cliSession->stream->write(str, strlen(str));
}

int cliDataAvailable(cliSession_t *cliSession){
    return cliSession->stream->dataAvailable();
}

int cliGetChar(cliSession_t *cliSession, char *c){
    return cliSession->stream->getChar(c);
}

stream_t * cliStreamGet(cliSession_t *cliSession){
    return cliSession->stream;
}

int cliUserLevelGet(cliSession_t *cliSession){
    return cliSession->userLevel;
}