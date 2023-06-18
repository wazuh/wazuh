#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "hints.h"
#include "cmd.h"
#include "color.h"
#include "cli.h"

typedef struct cmd_t{
    char *cmd;
    hint_t hint;
    void (*fn)(cmdStatus_t *status);
}cmd_t;

typedef struct cmdList_t{
    cmd_t *cmd;
    int cmdCount;
}cmdList_t;

typedef struct cmdStatus_t{
    cmd_t *cmd;
    int state;
    void *data;
    void (*freeData)(void *data); 
    bool running;
    cliSession_t *cs;
}cmdStatus_t;

static cmdList_t cmds = {
        .cmd = NULL,
        .cmdCount = 0
};

static cmdStatus_t cmdStatus = {
        .cmd = NULL,
        .state = 0,
        .data = NULL
};

static int cmdVPrintf(cmdStatus_t *s, char *fmt, va_list arg);
static void cmdAutocompleteCallback(stringList_t *l, char *buf);
static hint_t *cmdHintsCallback(char *key);

static void cmdCmd(cmdStatus_t *s){
    int st = cmdGetState(s);
    switch(st){
        case 0:
            if(st < cmds.cmdCount){
                cmdPrintf(s, "\r\nComando  Categoria      Descripcion\r\n");
                cmdPrintf(s, "%-8s %10s %s\r\n", cmds.cmd[st].cmd, "Categoria", cmds.cmd[st].hint.text);
            }
            else{
                cmdPrintf(s, "No hay comandos disponibles\r\n");
                cmdEnd(s);
            }
            break;
        default:
            if(st < cmds.cmdCount){
                cmdPrintf(s, "%-8s %10s %s\r\n", cmds.cmd[st].cmd, "Categoria", cmds.cmd[st].hint.text);
            }
            else{
                cmdEnd(s);
            }
            break;
    }
    cmdSetState(s, st+1);
}

void cmdExit(cmdStatus_t *s){
    cliExit(s->cs);
}

hintStyle_t hintDefaultStyle = {
        .bold = 0,
        .back = colorBlack,
        .fore = colorGreen,
        .header = " <- [",
        .trailer = "]"
};

void cmdInit(void){
    cmdLoad("cmd", "Lists commands", hintDefaultStyle, cmdCmd);
    cliSetAutocompleteCallback(cmdAutocompleteCallback);
    cliSetHintsCallback(cmdHintsCallback);
}
void cmdLoad(char *cmd, char * hint, hintStyle_t style, void (*fn)(cmdStatus_t *status)){
    cmd_t *c = NULL;
    c = (cmd_t *)realloc(cmds.cmd, sizeof(cmd_t) * (cmds.cmdCount + 1));

    if(!c)
        return;

    cmds.cmd = c;
    cmds.cmd[cmds.cmdCount].cmd  = cmd;
    cmds.cmd[cmds.cmdCount].hint.text = hint;
    cmds.cmd[cmds.cmdCount].hint.style = style;
    cmds.cmd[cmds.cmdCount].fn   = fn;
    cmds.cmdCount += 1;
}

cmdStatus_t *cmdFind(cliSession_t *cs, char *cmd){
    int i = 0;

    while(i < cmds.cmdCount){
        if(!strncasecmp(cmd, cmds.cmd[i].cmd, strlen(cmds.cmd[i].cmd))){
            cmdStatus.cmd = &cmds.cmd[i];
            cmdStatus.data = NULL;
            cmdStatus.state = 0;
            cmdStatus.running = true;
            cmdStatus.cs = cs;
            return &cmdStatus;
        }
        i++;
    }
    return NULL;
}

bool cmdExecute(cmdStatus_t *s){
    if(s->running && s->cmd && s->cmd->fn) {
        s->cmd->fn(s);
        if(s->state == 0)
            s->running = 0;
    }
    else
        s->running = false;

    return s->running;
}

void cmdEnd(cmdStatus_t *s){
    if(s->data && s->freeData)
        s->freeData(s->data);
    s->running = false;
}

void cmdSetState(cmdStatus_t *s, int state){
    s->state = state;
}

int cmdGetState(cmdStatus_t *s){
    return s->state;
}

void cmdSetCustomData(cmdStatus_t *s, void *data, void (*f)(void *)){
    s->freeData = f;
    s->data = data;
}

void * cmdGetCustomData(cmdStatus_t *s){
    return s->data;
}

void cmdString(cmdStatus_t *s, char *str){
    cliString(s->cs, str);
}

int cmdPrintf(cmdStatus_t *s, char *fmt, ...){
    int len;
    va_list arg_ptr;

    va_start(arg_ptr, fmt);
    len = cmdVPrintf(s, fmt, arg_ptr);
    va_end(arg_ptr);

    return len;
}

static int cmdVPrintf(cmdStatus_t *s, char *fmt, va_list arg){
    return cliVPrintf(s->cs, fmt, arg);
}

static void cmdAutocompleteCallback(stringList_t *l, char *buf){
    int i=0;
    int found = 0;

    while(i < cmds.cmdCount){
        if(strlen(buf) && !strncasecmp(buf, cmds.cmd[i].cmd, strlen(buf))){
            if(found == 0){
                found = 1;
                stringListAdd(l, buf);
            }
            stringListAdd(l, cmds.cmd[i].cmd);
        }
        i++;
    }
}

static hint_t * cmdHintsCallback(char *str){
    int i=0;
    char *p;

    while(i < cmds.cmdCount){
        p = strchr(str, ' ');

        // No space was pressed yet. Compare full word
        if(!p){
            if(!strcasecmp(str, cmds.cmd[i].cmd))
                return &(cmds.cmd[i].hint);
        }

        if(strlen(cmds.cmd[i].cmd) != p-str){
            i++;
            continue;
        }

        if(!strncasecmp(str, cmds.cmd[i].cmd, (p-str))){
            return &(cmds.cmd[i].hint);
        }

        i++;
    }

    return NULL;
}
int cmdDataAvailable(cmdStatus_t *s){
    return cliDataAvailable(s->cs);
}

int cmdGetChar(cmdStatus_t *s, char *c){
    return cliGetChar(s->cs, c);
}

stream_t * cmdStreamGet(cmdStatus_t *s){
    return cliStreamGet(s->cs);
}

int cmdGetKey(cmdStatus_t *s, char *c){
    int da, i;
    char in[4];
    da = cliDataAvailable(s->cs);
    switch(da){
        case 1:
            cliGetChar(s->cs, in);
        break;
        case 2:
        break;
        case 3:
        break;
        case 0:
        default:
        return 0;
    }
    return 0;
}

#define UK_CHARSET_G0                       ESC_S "(A"
#define UK_CHARSET_G1                       ESC_S ")A"
#define ASCII_CHARSET_G0                    ESC_S "(B"
#define ASCII_CHARSET_G1                    ESC_S ")B"
#define SPECIAL_GRAPH_G0                    ESC_S "(0"
#define SPECIAL_GRAPH_G1                    ESC_S ")0"
#define ALTERNATE_ROM_STANDARD_CHARSET_G0   ESC_S "(1"
#define ALTERNATE_ROM_STANDARD_CHARSET_G1   ESC_S ")1"
#define ALTERNATE_ROM_SCPECIAL_GRAPH ESC_G0 ESC_S "(2"
#define ALTERNATE_ROM_SCPECIAL_GRAPH ESC_G1 ESC_S ")2"

void cmdDraw(cmdStatus_t *c, char *str, ...){
    unsigned int i, j, len;
    char *p;
    va_list args;

    cmdPrintf(c, UK_CHARSET_G0 SPECIAL_GRAPH_G1 ANSI_SHIFT_DOWN_STR);

    len = strlen(str);
    p = calloc(1, len + 1);
    if(!p)
        return;

    for(i = 0, j = 0; i < len ; i++){
        switch((unsigned char)str[i]){
            case 0xE2:
                i++;
                switch((unsigned char)str[i]){
                    case 0x94:
                        i++;
                        switch((unsigned char)str[i]){
                            case 0x98: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x6A'; p[j++] = ANSI_SHIFT_DOWN; break; // ┘
                            case 0x90: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x6B'; p[j++] = ANSI_SHIFT_DOWN; break; // ┐
                            case 0x8C: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x6C'; p[j++] = ANSI_SHIFT_DOWN; break; // │
                            case 0x94: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x6D'; p[j++] = ANSI_SHIFT_DOWN; break; // └
                            case 0xBC: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x6E'; p[j++] = ANSI_SHIFT_DOWN; break; // ┼
                            case 0x80: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x71'; p[j++] = ANSI_SHIFT_DOWN; break; // ─
                            case 0x9C: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x74'; p[j++] = ANSI_SHIFT_DOWN; break; // ├
                            case 0xA4: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x75'; p[j++] = ANSI_SHIFT_DOWN; break; // ┤
                            case 0xB4: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x76'; p[j++] = ANSI_SHIFT_DOWN; break; // ┴
                            case 0xAC: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x77'; p[j++] = ANSI_SHIFT_DOWN; break; // ┬
                            case 0x82: p[j++] = ANSI_SHIFT_UP; p[j++] = '\x78'; p[j++] = ANSI_SHIFT_DOWN; break; // │
                            default:   p[j++] = ANSI_SHIFT_UP; p[j++] =   'X' ; p[j++] = ANSI_SHIFT_DOWN; break;
                        }
                    break;
                }
            break;
            default:   p[j++] = str[i]; break;
        }
    }

    va_start(args, str);
    cmdVPrintf(c, p, args);
    va_end(args);
    free(p);
}