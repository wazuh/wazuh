/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/debug_op.h"
#include "decoder.h"
#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"
#include "analysisd.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

OSDecoderNode *os_analysisd_decoderlist_pn;
OSDecoderNode *os_analysisd_decoderlist_nopn;
OSStore *os_analysisd_decoder_store;

STATIC OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi, OSList* log_msg);

/* Create the Event List */
void OS_CreateOSDecoderList() {

    os_analysisd_decoderlist_pn = NULL;
    os_analysisd_decoderlist_nopn = NULL;
    os_analysisd_decoder_store = NULL;
}

/* Get first osdecoder */
OSDecoderNode *OS_GetFirstOSDecoder(const char *p_name)
{
    /* If program name is set, we return the forpname list */
    if (p_name) {
        return (os_analysisd_decoderlist_pn);
    }

    return (os_analysisd_decoderlist_nopn);
}

/* Add an osdecoder to the list */
STATIC OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi, OSList* log_msg)
{
    OSDecoderNode *tmp_node = s_node;
    OSDecoderNode *new_node;
    int rm_f = 0;

    if (tmp_node) {
        os_calloc(1, sizeof(OSDecoderNode), new_node);

        /* Going to the last node */
        do {
            /* Check for common names */
            if ((strcmp(tmp_node->osdecoder->name, pi->name) == 0) &&
                    (pi->parent != NULL)) {
                if ((tmp_node->osdecoder->prematch ||
                        tmp_node->osdecoder->regex) && pi->regex_offset) {
                    rm_f = 1;
                }

                /* Multi-regexes patterns cannot have prematch */
                if (pi->prematch) {
                    smerror(log_msg, PDUP_INV, pi->name);
                    goto error;
                }

                /* Multi-regex patterns cannot have fts set */
                if (pi->fts) {
                    smerror(log_msg, PDUPFTS_INV, pi->name);
                    goto error;
                }

                if ((tmp_node->osdecoder->regex || tmp_node->osdecoder->plugindecoder)
                    && (pi->regex || pi->plugindecoder)) {
                    tmp_node->osdecoder->get_next = 1;
                } else {
                    smerror(log_msg, DUP_INV, pi->name);
                    goto error;
                }
            }

        } while (tmp_node->next && (tmp_node = tmp_node->next));

        /* Must have a prematch set */
        if (!rm_f && (pi->regex_offset & AFTER_PREVREGEX)) {
            smerror(log_msg, INV_OFFSET, pi->name);
            goto error;
        }

        tmp_node->next = new_node;

        new_node->next = NULL;
        new_node->osdecoder = pi;
        new_node->child = NULL;
    }

    else {
        /* Must not have a previous regex set */
        if (pi->regex_offset & AFTER_PREVREGEX) {
            smerror(log_msg, INV_OFFSET, pi->name);
            return (NULL);
        }

        os_calloc(1, sizeof(OSDecoderNode), tmp_node);

        tmp_node->child = NULL;
        tmp_node->next = NULL;
        tmp_node->osdecoder = pi;

        s_node = tmp_node;
    }

    return (s_node);

error:
    os_free(new_node);

    return (NULL);
}

int OS_AddOSDecoder(OSDecoderInfo *pi, OSDecoderNode **pn_osdecodernode,
                    OSDecoderNode **npn_osdecodernode, OSList* log_msg)
{
    int added = 0;
    OSDecoderNode *osdecodernode;

    /* We can actually have two lists. One with program
     * name and the other without.
     */
    if (pi->program_name) {
        osdecodernode = *pn_osdecodernode;
    } else {
        osdecodernode = *npn_osdecodernode;
    }

    /* Search for parent on both lists */
    if (pi->parent) {
        OSDecoderNode *tmp_node = *pn_osdecodernode;

        /* List with p_name */
        while (tmp_node) {
            if (strcmp(tmp_node->osdecoder->name, pi->parent) == 0) {
                OSDecoderNode *new_node = _OS_AddOSDecoder(tmp_node->child, pi, log_msg);
                if (!new_node) {
                    smerror(log_msg, DEC_PLUGIN_ERR);
                    return -added;
                }
                tmp_node->child = new_node;
                added = 1;
            }
            tmp_node = tmp_node->next;
        }

        /* List without p name */
        tmp_node = *npn_osdecodernode;
        while (tmp_node) {
            if (strcmp(tmp_node->osdecoder->name, pi->parent) == 0) {
                OSDecoderNode *new_node = _OS_AddOSDecoder(tmp_node->child, pi, log_msg);
                if (!new_node) {
                    smerror(log_msg, DEC_PLUGIN_ERR);
                    return -added;
                }
                tmp_node->child = new_node;
                added = 1;
            }
            tmp_node = tmp_node->next;
        }

        /* OSDecoder was added correctly */
        if (added == 1) {
            return (1);
        }

        smerror(log_msg, PPLUGIN_INV, pi->parent);
        return (0);
    } else {
        osdecodernode = _OS_AddOSDecoder(osdecodernode, pi, log_msg);
        if (!osdecodernode) {
            smerror(log_msg, DEC_PLUGIN_ERR);
            return (0);
        }

        /* Update global decoder pointers */
        if (pi->program_name) {
            *pn_osdecodernode = osdecodernode;
        } else {
            *npn_osdecodernode = osdecodernode;
        }
    }
    return (1);
}

void os_remove_decoders_list(OSDecoderNode *decoderlist_pn, OSDecoderNode *decoderlist_npn) {

    OSDecoderInfo **decoders;
    int pos = 0;
    int num_decoders = 0;

    os_count_decoders(decoderlist_pn, &num_decoders);
    os_count_decoders(decoderlist_npn, &num_decoders);

    os_calloc(num_decoders + 1, sizeof(OSDecoderInfo *), decoders);

    os_remove_decodernode(decoderlist_pn, decoders, &pos, &num_decoders);
    os_remove_decodernode(decoderlist_npn, decoders, &pos, &num_decoders);

    for (int i = 0; i <= pos; i++) {
        FreeDecoderInfo(decoders[i]);
    }

    os_free(decoders);
}

void os_remove_decodernode(OSDecoderNode *node, OSDecoderInfo **decoders, int *pos, int *max_size) {

    OSDecoderNode *tmp_node;

    while (node) {

        if (node->child) {
            os_remove_decodernode(node->child, decoders, pos, max_size);
        }

        tmp_node = node;
        node = node->next;

        if (tmp_node->osdecoder->internal_saving == false && *pos <= *max_size) {

            tmp_node->osdecoder->internal_saving = true;
            decoders[*pos] = tmp_node->osdecoder;
            (*pos)++;
        }

        os_free(tmp_node);
    }
}

void os_count_decoders(OSDecoderNode *node, int *num_decoders) {

    while(node) {

        if (node->child) {
            os_count_decoders(node->child, num_decoders);
        }

        (*num_decoders)++;

        node = node->next;
    }
}
