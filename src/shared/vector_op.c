/*
 * Copyright (C) 2015, Wazuh Inc.
 * June 19, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"


W_Vector *W_Vector_init(int initialSize) {

    W_Vector *v;
    os_malloc(sizeof(W_Vector), v);
    v->vector = (char **)malloc(initialSize * sizeof(char *));
    v->used = 0;
    v->size = initialSize;
    return v;
}


void W_Vector_insert(W_Vector *v, const char *element) {

    if (v) {
        if (v->used == v->size) {
            v->size *= 2;
            v->vector = (char **)realloc(v->vector, v->size * sizeof(char *));
            if(!v->vector){
                merror_exit(MEM_ERROR, errno, strerror(errno));
            }
        }
        v->vector[v->used++] = strdup(element);
    }
}


const char *W_Vector_get(W_Vector *v, int position) {

    if (v && position < v->used) {
        return v->vector[position];
    } else {
        return NULL;
    }
}


int W_Vector_length(W_Vector *v) {
    if (v) {
        return v->used;
    } else {
        return 0;
    }
}


void W_Vector_free(W_Vector *v) {
    int i;

    if (v) {
        for (i=0; i < v->used; i++) {
            os_free(v->vector[i]);
        }
        os_free (v->vector);
        os_free (v);
    }
}


int W_Vector_insert_unique(W_Vector *v, const char *element) {
    int i;
    int found = 0;

    if (v) {
        for (i=0; i < v->used; i++) {
            if (strcmp(element, v->vector[i]) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            W_Vector_insert(v, element);
        }
    }

    return found;
}
