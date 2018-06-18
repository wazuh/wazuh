/* data_buf.h --
 * Copyright 2007 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      John Dennis <jdennis@redhat.com>
 */

#ifndef DATA_BUF_HEADER
#define DATA_BUF_HEADER

/*****************************************************************************/
/******************************* Include Files *******************************/
/*****************************************************************************/
#include "config.h"
#include "private.h"

/*****************************************************************************/
/*********************************** Defines *********************************/
/*****************************************************************************/

#define DATABUF_FLAG_PRESERVE_HEAD (1 << 0)
#define DATABUF_FLAG_STRING        (2 << 0)


/*****************************************************************************/
/******************************* Type Definitions ****************************/
/*****************************************************************************/

typedef struct Databuf {
    unsigned flags;
    size_t alloc_size;
    char *alloc_ptr;
    size_t offset;
    size_t len;
    size_t max_len;
} DataBuf;

/*****************************************************************************/
/*************************  External Global Variables  ***********************/
/*****************************************************************************/

/*****************************************************************************/
/*****************************  Inline Functions  ****************************/
/*****************************************************************************/

static inline char *databuf_beg(DataBuf *db)
{return (db->alloc_ptr == NULL) ? NULL : db->alloc_ptr+db->offset;}

/*****************************************************************************/
/****************************  Exported Functions  ***************************/
/*****************************************************************************/

AUDIT_HIDDEN_START

void databuf_print(DataBuf *db, int print_data, char *fmt, ...)
#ifdef __GNUC__
        __attribute__ ((format (printf, 3, 4)));
#else
        ;
#endif
int databuf_init(DataBuf *db, size_t size, unsigned flags);
void databuf_free(DataBuf *db);
int databuf_append(DataBuf *db, const char *src, size_t src_size);
int databuf_advance(DataBuf *db, size_t advance);
int databuf_reset(DataBuf *db);

AUDIT_HIDDEN_END

#endif
