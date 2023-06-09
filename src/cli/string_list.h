//
// Created by beto on 04/06/23.
//

#ifndef STRING_LIST_H
#define STRING_LIST_H

typedef struct stringList_t stringList_t;

void stringListAdd(stringList_t *l, char *str);
void stringListRestart(stringList_t **l);
int stringListCount(stringList_t *l);
char * stringListGet(stringList_t *l, int idx);

#endif //STRING_LIST_H
