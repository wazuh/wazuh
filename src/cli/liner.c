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
#define UNUSED __attribute((unused))

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

typedef void (linerAction_t)(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);

/* There could be a liner session and a liner connection session if we would
 * like to have different callbacks
 * */
static hint_t *(*hintCallback)(char *key);

static void linerGetAutocompleteOptions(linerSession_t *s);
static void linerHintRefresh(linerSession_t *s);
static void linerSetBackgroundColor(linerSession_t *s, color_t color);
static void linerSetForegroundColor(linerSession_t *s, color_t color);

static void actionCursorRight(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCursorLeft (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionEscape     (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionBackspace  (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionTab        (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionEnter      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlA      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlB      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlC      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlD      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlE      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlF      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlK      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlL      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlN      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlP      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlT      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlU      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlW      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCursorUp   (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCursorDown (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionEnd        (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionHome       (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionDefault    (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionPageUp     (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionPageDown   (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionInsert     (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionDelete     (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF5         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF6         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF7         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF8         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF9         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF10        (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF12        (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF2         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF3         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionF4         (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlQ      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlR      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlY      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlO      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlS      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlZ      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlX      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionCtrlV      (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionBell       (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);
static void actionLineFeed   (UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c);

static keyActions_t linerActions = {
    .Escape      = (void (*)(void *, stream_t *, char))actionEscape,
    .CursorUp    = (void (*)(void *, stream_t *, char))actionCursorUp,
    .CursorDown  = (void (*)(void *, stream_t *, char))actionCursorDown,
    .CursorRight = (void (*)(void *, stream_t *, char))actionCursorRight,
    .CursorLeft  = (void (*)(void *, stream_t *, char))actionCursorLeft,
    .Home        = (void (*)(void *, stream_t *, char))actionHome,
    .End         = (void (*)(void *, stream_t *, char))actionEnd,    
    .PageUp      = (void (*)(void *, stream_t *, char))actionPageUp,
    .PageDown    = (void (*)(void *, stream_t *, char))actionPageDown,
    .Insert      = (void (*)(void *, stream_t *, char))actionInsert,
    .Delete      = (void (*)(void *, stream_t *, char))actionDelete,
    .F2          = (void (*)(void *, stream_t *, char))actionF2,
    .F3          = (void (*)(void *, stream_t *, char))actionF3,
    .F4          = (void (*)(void *, stream_t *, char))actionF4,
    .F5          = (void (*)(void *, stream_t *, char))actionF5,
    .F6          = (void (*)(void *, stream_t *, char))actionF6,
    .F7          = (void (*)(void *, stream_t *, char))actionF7,
    .F8          = (void (*)(void *, stream_t *, char))actionF8,
    .F9          = (void (*)(void *, stream_t *, char))actionF9,
    .F10         = (void (*)(void *, stream_t *, char))actionF10,
    .F12         = (void (*)(void *, stream_t *, char))actionF12,
    .Bell        = (void (*)(void *, stream_t *, char))actionBell,
    .Enter       = (void (*)(void *, stream_t *, char))actionEnter,
    .Backspace   = (void (*)(void *, stream_t *, char))actionBackspace,
    .Tab         = (void (*)(void *, stream_t *, char))actionTab,
    .LineFeed    = (void (*)(void *, stream_t *, char))actionLineFeed,
    .CtrlA       = (void (*)(void *, stream_t *, char))actionCtrlA,
    .CtrlB       = (void (*)(void *, stream_t *, char))actionCtrlB,
    .CtrlC       = (void (*)(void *, stream_t *, char))actionCtrlC,
    .CtrlD       = (void (*)(void *, stream_t *, char))actionCtrlD,
    .CtrlE       = (void (*)(void *, stream_t *, char))actionCtrlE,
    .CtrlF       = (void (*)(void *, stream_t *, char))actionCtrlF,
    .CtrlK       = (void (*)(void *, stream_t *, char))actionCtrlK,
    .CtrlL       = (void (*)(void *, stream_t *, char))actionCtrlL,
    .CtrlN       = (void (*)(void *, stream_t *, char))actionCtrlN,
    .CtrlO       = (void (*)(void *, stream_t *, char))actionCtrlO,
    .CtrlP       = (void (*)(void *, stream_t *, char))actionCtrlP,
    .CtrlQ       = (void (*)(void *, stream_t *, char))actionCtrlQ,
    .CtrlR       = (void (*)(void *, stream_t *, char))actionCtrlR,
    .CtrlS       = (void (*)(void *, stream_t *, char))actionCtrlS,
    .CtrlT       = (void (*)(void *, stream_t *, char))actionCtrlT,
    .CtrlU       = (void (*)(void *, stream_t *, char))actionCtrlU,
    .CtrlV       = (void (*)(void *, stream_t *, char))actionCtrlV,
    .CtrlW       = (void (*)(void *, stream_t *, char))actionCtrlW,
    .CtrlX       = (void (*)(void *, stream_t *, char))actionCtrlX,
    .CtrlY       = (void (*)(void *, stream_t *, char))actionCtrlY,
    .CtrlZ       = (void (*)(void *, stream_t *, char))actionCtrlZ,
    .Default     = (void (*)(void *, stream_t *, char))actionDefault,
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
    
    action = keyActionGet(&(ls->stream), &linerActions, c);
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

        for(int k = 0 ;k < (int)(8 + (ls->tabCount? strlen(stringListGet(ls->autocomplete.list, ls->tabCount)):strlen(ls->input))); k++)
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

bool linerEnded(linerSession_t *s){
    int e = s->end;
    s->end = 0;
    return e;
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

static __attribute((unused)) void actionCursorLeft(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCursorRight(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionEscape(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionBackspace(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){
    int len;

    if(!ls->tabCount){
        ls->input[strlen(ls->input) - 1] = 0;
    }
    else{
        len = strlen(stringListGet(ls->autocomplete.list, ls->tabCount));
        strncpy(ls->input, stringListGet(ls->autocomplete.list, ls->tabCount), len - 1);
    }
    ls->tabCount = 0;

}

static __attribute((unused)) void actionEnter(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){
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

static __attribute((unused)) void actionCtrlA(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlB(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlC(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlD(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlE(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlF(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlK(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlL(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlN(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlP(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlT(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlU(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlW(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCursorUp(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCursorDown(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionEnd(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionHome(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionDefault(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){
    char str[2] = {0};
    str[0] = c;
    strcat(ls->line, str);
    strcat(ls->input, str);

    if(stringListCount(ls->autocomplete.list)) {
        sprintf(ls->input, "%s%c", stringListGet(ls->autocomplete.list, ls->tabCount), c);
    }

    ls->tabCount = 0;
}

static __attribute((unused)) void actionPageUp(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionPageDown(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionInsert(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionDelete(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionTab(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){
    ls->tabCount++;
    if(ls->tabCount >= stringListCount(ls->autocomplete.list))
        ls->tabCount = 0;
}

static __attribute((unused)) void actionF5(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF6(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF7(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF8(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF9(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF10(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF12(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF2(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF3(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionF4(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlQ(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlR(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlY(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlO(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlS(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlZ(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlX(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionCtrlV(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionBell(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

}

static __attribute((unused)) void actionLineFeed(UNUSED linerSession_t *ls,UNUSED stream_t *s,UNUSED char c){

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
