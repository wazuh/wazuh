/*
 * Copyright (C) 2018 Wazuh Inc.
 * June 19, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"


W_Vector *W_Vector_init(int initialSize) {

    W_Vector *v = malloc(sizeof(W_Vector));
    v->vector = (char **)malloc(initialSize * sizeof(char *));
    v->used = 0;
    v->size = initialSize;
    return v;
}


void W_Vector_insert(W_Vector *v, const char *element) {

    if (v->used == v->size) {
        v->size *= 2;
        v->vector = (char **)realloc(v->vector, v->size * sizeof(char *));
    }
    v->vector[v->used++] = strdup(element);
}


const char *W_Vector_get(W_Vector *v, int position) {

    if (position < v->used) {
        return v->vector[position];
    } else {
        return NULL;
    }
}


int W_Vector_length(W_Vector *v) {
    return v->used;
}


void W_Vector_free(W_Vector *v) {

    for (int i=0; i < v->used; i++) {
        free(v->vector[i]);
    }
    free (v->vector);
    free (v);
}
