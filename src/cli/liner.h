#ifndef LINER_LINER_H
#define LINER_LINER_H
#include <stdbool.h>
#include "stream.h"
#include "string_list.h"
#include "color.h"
#include "hints.h"

typedef enum linerHideMode_t{
    linerUnhidden=0,
    linerHidden,
    linerMasked
}linerHideMode_t;

typedef struct linerSession_t linerSession_t;

typedef struct linerHintStyle_t{
    char *header;           /* Won't be formmated */
    char *trailer;          /* Won't be formmated */
    color_t fore;
    color_t back;
    int bold;
}linerHintStyle_t;

typedef struct linerHint_t{
    char *text;
    linerHintStyle_t style;
}linerHint_t;

void linerMode(linerSession_t *s, linerHideMode_t m);
linerSession_t *linerNewSession(stream_t *s);
char * liner(linerSession_t *s);
bool linerEnded(linerSession_t *s);

void linerSetHintCallback(hint_t * (*cb)(char *str));
void linerSetAutoCompleteCallback(linerSession_t *s, void (*cb)(stringList_t *l, char *str));

/* Adds a string to the command history */
void linerHistoryAdd(linerSession_t *ls, char *s);
/* Erase command history */
void linerHistoryClear(linerSession_t *ls);
/* Resets any command history present and loads the receive list */
void linerHistoryLoad(linerSession_t *ls, stringList_t *list);
/* Returns a copy of command history */
void linerHistoryGet(linerSession_t *ls, stringList_t **list);

#endif //LINER_LINER_H
