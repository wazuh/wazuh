/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/debug_op.h"
#include "maild.h"
#include "mail_list.h"
#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"

static MailNode *n_node;
static MailNode *lastnode;

static int _memoryused = 0;
static int _memorymaxsize = 0;


/* Create the Mail List */
void OS_CreateMailList(int maxsize)
{
    n_node = NULL;

    _memorymaxsize = maxsize;
    _memoryused = 0;

    return;
}

/* Check last mail */
MailNode *OS_CheckLastMail()
{
    return (lastnode);
}

/* Get the last Mail -- or first node */
MailNode *OS_PopLastMail()
{
    MailNode *oldlast;

    oldlast = lastnode;
    if (lastnode == NULL) {
        n_node = NULL;
        return (NULL);
    }

    _memoryused--;
    lastnode = lastnode->prev;

    /* Remove the last */
    return (oldlast);
}

void FreeMailMsg(MailMsg *ml)
{
    if (ml == NULL) {
        return;
    }

    if (ml->subject) {
        free(ml->subject);
    }

    if (ml->body) {
        free(ml->body);
    }

    free(ml);
}

/* Free mail node */
void FreeMail(MailNode *ml)
{
    if (ml == NULL) {
        return;
    }
    if (ml->mail->subject) {
        free(ml->mail->subject);
    }

    if (ml->mail->body) {
        free(ml->mail->body);
    }

    free(ml->mail);
    free(ml);
}


/* Add an email to the list -- always to the beginning */
void OS_AddMailtoList(MailMsg *ml)
{
    MailNode *tmp_node = n_node;

    if (tmp_node) {
        MailNode *new_node;
        new_node = (MailNode *)calloc(1, sizeof(MailNode));

        if (new_node == NULL) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }

        /* Always add to the beginning of the list
         * The new node will become the first node and
         * new_node->next will be the previous first node
         */
        new_node->next = tmp_node;
        new_node->prev = NULL;
        tmp_node->prev = new_node;

        n_node = new_node;

        /* Add the event to the node */
        new_node->mail = ml;

        _memoryused++;

        /* Need to remove the last node */
        if (_memoryused > _memorymaxsize) {
            MailNode *oldlast;

            oldlast = lastnode;
            lastnode = lastnode->prev;

            /* Free last node */
            FreeMail(oldlast);

            _memoryused--;
        }
    }

    else {
        /* Add first node */
        n_node = (MailNode *)calloc(1, sizeof(MailNode));
        if (n_node == NULL) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }

        n_node->prev = NULL;
        n_node->next = NULL;
        n_node->mail = ml;

        lastnode = n_node;
    }

    return;
}
