//
// Created by beto on 27/05/23.
//

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

#endif //LINER_LINER_H
