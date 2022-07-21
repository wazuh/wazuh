/*
 * Copyright (C) 2015, Wazuh Inc.
 * June 19, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef VECTOR_OP_H
#define VECTOR_OP_H

typedef struct {
    /** @brief Pointer to the char* vector. */
    char **vector;
    /** @brief Number of elements in the vector. */
    int used;
    /** @brief Size of the allocated vector. */
    int size;
} W_Vector;


/**
 * @brief Initialize a char* vector with the specified size.
 *
 * @param initialSize Vector size.
 * @return Pointer to the W_Vector initialized.
 */
W_Vector *W_Vector_init(int initialSize);


/**
 * @brief Adds a new element to the end of the vector.
 *
 * @param v Pointer to the W_Vector initialized.
 * @param element Element to be added.
 */
void W_Vector_insert(W_Vector *v, const char *element);


/**
 * @brief Gets the content from the specified position.
 *
 * @param v Pointer to the W_Vector.
 * @param position Position to be read.
 * @return Content of the specified postion.
 */
const char *W_Vector_get(W_Vector *v, int position);


/**
 * @brief Gets the number of elements in the vector.
 *
 * @param v Pointer to the W_Vector.
 * @return Number of elements.
 */
int W_Vector_length(W_Vector *v);


/**
 * @brief Deallocates the memory allocated by the vector.
 *
 * @param v Pointer to the W_Vector.
 */
void W_Vector_free(W_Vector *v);


/**
 * @brief Adds a new element if it is not present in the vector.
 *
 * @param v Pointer to the W_Vector initialized.
 * @param element Element to be added.
 * @return Returns 1 if the element is duplicated, 0 otherwise.
 */
int W_Vector_insert_unique(W_Vector *v, const char *element);

#endif /* VECTOR_OP_H */
