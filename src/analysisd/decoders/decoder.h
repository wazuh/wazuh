/*   $OSSEC, decoder.h, v0.2, 2006/01/04, Daniel B. Cid$   */

/* Copyright (C) 2005,2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __DECODER_H

#define __DECODER_H


/* We need the eventinfo and os_regex in here */
#include "eventinfo.h"
#include "os_regex/os_regex.h"


/* Plugin structure */
typedef struct
{
    int type;
    int fts;
    char *parent;
    char *name;
    OSRegex *regex;
    OSRegex *prematch;
    char *ftscomment;
    void (**order)(Eventinfo *lf, char *field);
}PluginInfo;

/* List structure */
typedef struct _PluginNode
{
    struct _PluginNode *next;
    struct _PluginNode *child;
    PluginInfo *plugin;
}PluginNode;



/* Functions to Create the list, Add a plugin to the
 * list and to get the first plugin.
 */
void OS_CreatePluginList();
void OS_AddPlugin(PluginInfo *pi);
PluginNode *OS_GetFirstPlugin();


/* Interfaces for the event decoders */
void *DstUser_FP(Eventinfo *lf, char *field);
void *User_FP(Eventinfo *lf, char *field);
void *SrcIP_FP(Eventinfo *lf, char *field);
void *DstIP_FP(Eventinfo *lf, char *field);
void *SrcPort_FP(Eventinfo *lf, char *field);
void *DstPort_FP(Eventinfo *lf, char *field);
void *Protocol_FP(Eventinfo *lf, char *field);
void *Action_FP(Eventinfo *lf, char *field);
void *ID_FP(Eventinfo *lf, char *field);
void *None_FP(Eventinfo *lf, char *field);

#endif

/* EOF */
