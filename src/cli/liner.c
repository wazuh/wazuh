//
// Created by beto on 27/05/23.
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "liner.h"
#include "ansi.h"
#include "string_list.h"
#include "hints.h"
#include "action.h"

#define LINER_MAX_LENGTH 4096

typedef struct autocomplete_t{
    stringList_t *list;
    void (*cb)(stringList_t *l, char *str);
}autocomplete_t;
typedef struct linerSession_t{
    int state;
    linerHideMode_t hiddenMode;
    char line[LINER_MAX_LENGTH];
    char input[LINER_MAX_LENGTH];
    char input_to_show[LINER_MAX_LENGTH];
    linerHideMode_t hideMode;

    int tabCount;
    bool end;
    bool start;
    stream_t stream;
    autocomplete_t autocomplete;

}linerSession_t;

/* There could be a liner session and a liner connection session if we would
 * like to have different callbacks
 * */
static hint_t *(*hintCallback)(char *key);
static int (*linerGetAutocompleteListFromKey)(linerSession_t *s, char *key);

static void linerGetAutocompleteOptions(linerSession_t *s);
static void linerHintRefresh(linerSession_t *s);
static void linerSetBackgroundColor(linerSession_t *s, color_t color);
static void linerSetForegroundColor(linerSession_t *s, color_t color);

static void actionCursorLeft(linerSession_t *ls, stream_t *s, char c);
static void actionCursorRight(linerSession_t *ls, stream_t *s, char c);
static void actionEscape(linerSession_t *ls, stream_t *s, char c);
static void actionBackspace(linerSession_t *ls, stream_t *s, char c);
static void actionTab(linerSession_t *ls, stream_t *s, char c);
static void actionEnter(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlA(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlB(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlC(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlD(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlE(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlF(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlK(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlL(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlN(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlP(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlT(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlU(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlW(linerSession_t *ls, stream_t *s, char c);
static void actionCursorUp(linerSession_t *ls, stream_t *s, char c);
static void actionCursorDown(linerSession_t *ls, stream_t *s, char c);
static void actionEnd(linerSession_t *ls, stream_t *s, char c);
static void actionHome(linerSession_t *ls, stream_t *s, char c);
static void actionDefault(linerSession_t *ls, stream_t *s, char c);
static void actionPageUp(linerSession_t *ls, stream_t *s, char c);
static void actionPageDown(linerSession_t *ls, stream_t *s, char c);
static void actionInsert(linerSession_t *ls, stream_t *s, char c);
static void actionDelete(linerSession_t *ls, stream_t *s, char c);
static void actionF5(linerSession_t *ls, stream_t *s, char c);
static void actionF6(linerSession_t *ls, stream_t *s, char c);
static void actionF7(linerSession_t *ls, stream_t *s, char c);
static void actionF8(linerSession_t *ls, stream_t *s, char c);
static void actionF9(linerSession_t *ls, stream_t *s, char c);
static void actionF10(linerSession_t *ls, stream_t *s, char c);
static void actionF12(linerSession_t *ls, stream_t *s, char c);
static void actionF2(linerSession_t *ls, stream_t *s, char c);
static void actionF3(linerSession_t *ls, stream_t *s, char c);
static void actionF4(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlQ(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlR(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlY(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlO(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlS(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlZ(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlX(linerSession_t *ls, stream_t *s, char c);
static void actionCtrlV(linerSession_t *ls, stream_t *s, char c);
static void actionBell(linerSession_t *ls, stream_t *s, char c);
static void actionLineFeed(linerSession_t *ls, stream_t *s, char c);

static keyActions_t linerActions = {
    .Escape = actionEscape,
    .CursorUp = actionCursorUp,
    .CursorDown = actionCursorDown,
    .CursorRight = actionCursorRight,
    .CursorLeft = actionCursorLeft,
    .Home = actionHome,
    .End = actionEnd,    .PageUp = actionPageUp,
    .PageDown = actionPageDown,
    .Insert = actionInsert,
    .Delete = actionDelete,
    .F2 = actionF2,
    .F3 = actionF3,
    .F4 = actionF4,
    .F5 = actionF5,
    .F6 = actionF6,
    .F7 = actionF7,
    .F8 = actionF8,
    .F9 = actionF9,
    .F10 = actionF10,
    .F12 = actionF12,
    .Bell = actionBell,
    .Enter = actionEnter,
    .Backspace = actionBackspace,
    .Tab = actionTab,
    .LineFeed = actionLineFeed,
    .CtrlA = actionCtrlA,
    .CtrlB = actionCtrlB,
    .CtrlC = actionCtrlC,
    .CtrlD = actionCtrlD,
    .CtrlE = actionCtrlE,
    .CtrlF = actionCtrlF,
    .CtrlK = actionCtrlK,
    .CtrlL = actionCtrlL,
    .CtrlN = actionCtrlN,
    .CtrlO = actionCtrlO,
    .CtrlP = actionCtrlP,
    .CtrlQ = actionCtrlQ,
    .CtrlR = actionCtrlR,
    .CtrlS = actionCtrlS,
    .CtrlT = actionCtrlT,
    .CtrlU = actionCtrlU,
    .CtrlV = actionCtrlV,
    .CtrlW = actionCtrlW,
    .CtrlX = actionCtrlX,
    .CtrlY = actionCtrlY,
    .CtrlZ = actionCtrlZ,
    .Default = actionDefault,
};

linerSession_t *linerNewSession(stream_t *s){
    linerSession_t *ses = calloc(1, sizeof(linerSession_t));

    if(ses == NULL)
        return NULL;

    ses->stream = *s;
    ses->start = 1;
    return ses;
}

void linerMode(linerSession_t *s, linerHideMode_t m){
    if(m < linerUnhidden || m > linerMasked)
        return;

    s->hideMode = m;
}

void linerWriteString(linerSession_t *ls, char *str){
    if(str)
        ls->stream.write(str, strlen(str));
}

char * liner(linerSession_t *ls){
    char c;
    int i;
    keyAction_t action;

    keyActionSet(&linerActions);
    ls->stream.task();
    usleep(10000);

    if(!ls->stream.isOnline())
        return NULL;

    if(ls->start){
        ls->start = 0;
        ls->end = 0;
        linerWriteString(ls, CSI"\x3F""25l" CSI"G" "\r" ansiEraseEntireLine() "\r");
        linerWriteString(ls, "wazuh:/>");
    }

    if(!ls->stream.dataAvailable())
        return NULL;

    i = ls->stream.getChar(&c);
    if(i != 1)
        return NULL;
    
    action = keyActionGet(&(ls->stream),  c);
    if(action) {
        action(ls, &(ls->stream), c);

                //s->stream.write(ansiCursorGoToColumn(0), strlen(ansiCursorGoToColumn(0)));
        linerWriteString(ls, CSI"\x3F""25l" CSI"G" "\r" ansiEraseEntireLine() "\r");
        if(ls->end){
            ls->start = 1;
            return ls->line;
        }
        linerWriteString(ls, "wazuh:/>");
        if(!ls->tabCount)
            linerWriteString(ls, ls->input);
        else
            linerWriteString(ls, stringListGet(ls->autocomplete.list, ls->tabCount));
        //linerWriteString(s, ansiCursorSavePosition() " ");  <<-- Works different on windows, linux & xterm

        linerHintRefresh(ls);
        linerWriteString(ls, "\r\n");
        linerGetAutocompleteOptions(ls);

        linerWriteString(ls, CSI"A" CSI"G" "\r\r");

        for(int k = 0 ;k < 8 + (ls->tabCount? strlen(stringListGet(ls->autocomplete.list, ls->tabCount)):strlen(ls->input)); k++)
            linerWriteString(ls, CSI"C");

        linerWriteString(ls, ansiModeResetAll());
        linerWriteString(ls, CSI"\x3F""25h");
    }
    return NULL;
}

static void linerHintRefresh(linerSession_t *ls){
    hint_t *h;

    if(!ls || !hintCallback)
        return;

    h = hintCallback(ls->tabCount? stringListGet(ls->autocomplete.list, ls->tabCount):ls->input);

    if(!h || !h->text || !strlen(h->text))
        return;

    if(h->style.header)
        linerWriteString(ls, h->style.header);

    if(h->style.bold)
        linerWriteString(ls, ansiModeBoldSet());
    linerSetBackgroundColor(ls, h->style.back);
    linerSetForegroundColor(ls, h->style.fore);

    linerWriteString(ls, h->text);

    linerWriteString(ls, ansiModeResetAll());

    if(h->style.trailer)
        linerWriteString(ls, h->style.trailer);
}

void linerSetHintCallback(hint_t * (*cb)(char *str)){
    hintCallback = cb;
}

void linerSetAutoCompleteCallback(linerSession_t *ls, void (*cb)(stringList_t *l, char *str)){
    if(!ls)
        return;

    ls->autocomplete.cb = cb;
}

static void linerGetAutocompleteOptions(linerSession_t *ls){
    int i;

    stringListRestart(&ls->autocomplete.list);

    if(ls->autocomplete.cb)
        ls->autocomplete.cb(ls->autocomplete.list, ls->input);

    linerWriteString(ls, ansiEraseEntireLine());

    if(!stringListCount(ls->autocomplete.list)) {
        return;
    }

    linerWriteString(ls, "Suggestions:");

    for(i = 0; i < stringListCount(ls->autocomplete.list); i++){
        linerWriteString(ls, " ");

        if(i == ls->tabCount){
            linerWriteString(ls, ansiModeInverseSet());
        }

        linerWriteString(ls, stringListGet(ls->autocomplete.list, i));

        if(i == ls->tabCount){
            linerWriteString(ls, ansiModeResetAll());
        }
    }
}

static void actionCursorLeft(linerSession_t *ls, stream_t *s, char c){
    printf("Cursor left pressed\n"); fflush(stdout);
}
static void actionCursorRight(linerSession_t *ls, stream_t *s, char c){
    printf("Cursor right pressed\n"); fflush(stdout);
}
static void actionEscape(linerSession_t *ls, stream_t *s, char c){
    printf("Escape pressed\n"); fflush(stdout);
}
static void actionBackspace(linerSession_t *ls, stream_t *s, char c){
    int len;
    printf("Backspace pressed\n"); fflush(stdout);
    if(!ls->tabCount){
        ls->input[strlen(ls->input) - 1] = 0;
    }
    else{
        len = strlen(stringListGet(ls->autocomplete.list, ls->tabCount));
        strncpy(ls->input, stringListGet(ls->autocomplete.list, ls->tabCount), len - 1);
    }
    ls->tabCount = 0;

}
static void actionEnter(linerSession_t *ls, stream_t *s, char c){
    int len;
    printf("Enter pressed\n"); fflush(stdout);

    linerWriteString(ls, "\r");
    linerWriteString(ls, ansiEraseEntireLine());
    linerWriteString(ls, "\rwazuh:/>");

    if(ls->tabCount){
        strcpy(ls->input, stringListGet(ls->autocomplete.list, ls->tabCount));
    }
    linerWriteString(ls, ls->input);

    s->write("\r\n", 2);

    ls->tabCount = 0;
    ls->end = 1;
    ls->start = 1;

    strncpy(ls->line, ls->input, sizeof(ls->line)-1);
    ls->line[sizeof(ls->line)-1] = 0;
    ls->input[0] = 0;
    stringListRestart(&ls->autocomplete.list);
}
static void actionCtrlA(linerSession_t *ls, stream_t *s, char c){
    printf("Control A pressed\n"); fflush(stdout);
}
static void actionCtrlB(linerSession_t *ls, stream_t *s, char c){
    printf("Control B pressed\n"); fflush(stdout);
}
static void actionCtrlC(linerSession_t *ls, stream_t *s, char c){
    printf("Control C pressed\n"); fflush(stdout);
}
static void actionCtrlD(linerSession_t *ls, stream_t *s, char c){
    printf("Control D pressed\n"); fflush(stdout);
}
static void actionCtrlE(linerSession_t *ls, stream_t *s, char c){
    printf("Control E pressed\n"); fflush(stdout);
}
static void actionCtrlF(linerSession_t *ls, stream_t *s, char c){
    printf("Control F pressed\n"); fflush(stdout);
}
static void actionCtrlK(linerSession_t *ls, stream_t *s, char c){
    printf("Control K pressed\n"); fflush(stdout);
}
static void actionCtrlL(linerSession_t *ls, stream_t *s, char c){
    printf("Control L pressed\n"); fflush(stdout);
}
static void actionCtrlN(linerSession_t *ls, stream_t *s, char c){
    printf("Control N pressed\n"); fflush(stdout);
}
static void actionCtrlP(linerSession_t *ls, stream_t *s, char c){
    printf("Control P pressed\n"); fflush(stdout);
}
static void actionCtrlT(linerSession_t *ls, stream_t *s, char c){
    printf("Control T pressed\n"); fflush(stdout);
}
static void actionCtrlU(linerSession_t *ls, stream_t *s, char c){
    printf("Control U pressed\n"); fflush(stdout);
}
static void actionCtrlW(linerSession_t *ls, stream_t *s, char c){
    printf("Control W pressed\n"); fflush(stdout);
}
static void actionCursorUp(linerSession_t *ls, stream_t *s, char c){
    printf("Cursor up pressed\n"); fflush(stdout);
}
static void actionCursorDown(linerSession_t *ls, stream_t *s, char c){
    printf("Cursor down pressed\n"); fflush(stdout);
}
static void actionEnd(linerSession_t *ls, stream_t *s, char c){
    printf("End pressed\n"); fflush(stdout);
}
static void actionHome(linerSession_t *ls, stream_t *s, char c){
    printf("Begin pressed\n"); fflush(stdout);
}
static void actionDefault(linerSession_t *ls, stream_t *s, char c){
    char str[2] = {0};
    str[0] = c;
    strcat(ls->line, str);
    strcat(ls->input, str);

    if(stringListCount(ls->autocomplete.list)) {
 //       if(s->tabCount == 0)
 //           strcpy(s->input, stringListGet(s->autocomplete.list, 0));
 //       else
            sprintf(ls->input, "%s%c", stringListGet(ls->autocomplete.list, ls->tabCount), c);
    }

    ls->tabCount = 0;
}
static void actionPageUp(linerSession_t *ls, stream_t *s, char c){
    printf("PageUp pressed\n"); fflush(stdout);
}
static void actionPageDown(linerSession_t *ls, stream_t *s, char c){
    printf("PageDown pressed\n"); fflush(stdout);
}
static void actionInsert(linerSession_t *ls, stream_t *s, char c){
    printf("Insert pressed\n"); fflush(stdout);
}
static void actionDelete(linerSession_t *ls, stream_t *s, char c){
    printf("Delete pressed\n"); fflush(stdout);
}
static void actionTab(linerSession_t *ls, stream_t *s, char c){
    ls->tabCount++;
    if(ls->tabCount >= stringListCount(ls->autocomplete.list))
        ls->tabCount = 0;
    printf("Tab pressed\n"); fflush(stdout);
}
static void actionF5(linerSession_t *ls, stream_t *s, char c){
    printf("F5 pressed\n"); fflush(stdout);
}
static void actionF6(linerSession_t *ls, stream_t *s, char c){
    printf("F6 pressed\n"); fflush(stdout);
}
static void actionF7(linerSession_t *ls, stream_t *s, char c){
    printf("F7 pressed\n"); fflush(stdout);
}
static void actionF8(linerSession_t *ls, stream_t *s, char c){
    printf("F8 pressed\n"); fflush(stdout);
}
static void actionF9(linerSession_t *ls, stream_t *s, char c){
    printf("F9 pressed\n"); fflush(stdout);
}
static void actionF10(linerSession_t *ls, stream_t *s, char c){
    printf("F10 pressed\n"); fflush(stdout);
}
static void actionF12(linerSession_t *ls, stream_t *s, char c){
    printf("F12 pressed\n"); fflush(stdout);
}
static void actionF2(linerSession_t *ls, stream_t *s, char c){
    printf("F2 pressed\n"); fflush(stdout);
}
static void actionF3(linerSession_t *ls, stream_t *s, char c){
    printf("F3 pressed\n"); fflush(stdout);
}
static void actionF4(linerSession_t *ls, stream_t *s, char c){
    printf("F4 pressed\n"); fflush(stdout);
}
static void actionCtrlQ(linerSession_t *ls, stream_t *s, char c){
    printf("Control Q pressed\n"); fflush(stdout);
}
static void actionCtrlR(linerSession_t *ls, stream_t *s, char c){
    printf("Control R pressed\n"); fflush(stdout);
}
static void actionCtrlY(linerSession_t *ls, stream_t *s, char c){
    printf("Control Y pressed\n"); fflush(stdout);
}
static void actionCtrlO(linerSession_t *ls, stream_t *s, char c){
    printf("Control O pressed\n"); fflush(stdout);
}
static void actionCtrlS(linerSession_t *ls, stream_t *s, char c){
    printf("Control S pressed\n"); fflush(stdout);
}
static void actionCtrlZ(linerSession_t *ls, stream_t *s, char c){
    printf("Control Z pressed\n"); fflush(stdout);
}
static void actionCtrlX(linerSession_t *ls, stream_t *s, char c){
    printf("Control X pressed\n"); fflush(stdout);
}
static void actionCtrlV(linerSession_t *ls, stream_t *s, char c){
    printf("Control V pressed\n"); fflush(stdout);
}
static void actionBell(linerSession_t *ls, stream_t *s, char c){
    printf("Bell received\n"); fflush(stdout);
}
static void actionLineFeed(linerSession_t *ls, stream_t *s, char c){
    printf("Linefeed received\n"); fflush(stdout);
}

bool linerEnded(linerSession_t *s){
    int e = s->end;
    s->end = 0;
    return e;
}

static void linerSetBackgroundColor(linerSession_t *s, color_t color){
    char tmp[10];
    if(color < colorBlack || color > colorDefault || color == 8)
        return;

    sprintf(tmp, "\x1B[%dm", color + 40);
    linerWriteString(s, tmp);
}

static void linerSetForegroundColor(linerSession_t *s, color_t color){
    char tmp[10];
    if(color < colorBlack || color > colorDefault || color == 8)
        return;

    sprintf(tmp, "\x1B[%dm", color + 30);
    linerWriteString(s, tmp);
}
