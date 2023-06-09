//
// Created by beto on 04/06/23.
//

#ifndef HINTS_H
#define HINTS_H
#include "color.h"

typedef struct hintStyle_t{
    char *header;
    char *trailer;
    color_t fore;
    color_t back;
    int bold;
}hintStyle_t;

typedef struct hint_t{
    char *text;
    hintStyle_t style;
}hint_t;

extern hintStyle_t hintDefaultStyle;

#endif //HINTS_H
