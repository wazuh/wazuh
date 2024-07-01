#include <string.h>
#include <stdlib.h>
#include "string_list.h"

typedef struct stringList_t{
    size_t stringsCount;
    char **strings;
}stringList_t;

char * stringListGet(stringList_t *l, int idx){
    if(!l || idx >= l->stringsCount)
        return NULL;

    return l->strings[idx];
}

void stringListAdd(stringList_t *l, char *str){
    char *newString;
    char **strings;
    int len;

    if(!str)
        return;

    len = strlen(str);
    if(!len)
        return;

    newString = calloc(sizeof(char), len + 1);
    if(!newString)
        return;

    strcpy(newString, str);

    strings = realloc(l->strings, sizeof(char *) * (l->stringsCount + 1));
    if(!strings){
        free(newString);
        return;
    }

    l->strings = strings;
    l->strings[l->stringsCount] = newString;
    l->stringsCount++;
}

void stringListRestart(stringList_t **l){
    int i;
    stringList_t *pl;

    if(!l)
        return;

    if(!*l){
        *l = calloc(1, sizeof(stringList_t));
    }

    pl = *l;
    for(i = 0; i < pl->stringsCount; i++){
        if(pl[i].strings)
            free(pl->strings[i]);
    }

    free(*l);

    *l = calloc(1, sizeof(stringList_t));
}

int stringListCount(stringList_t *l){
    if(!l)
        return 0;

    return l->stringsCount;
}
