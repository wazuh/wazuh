

#ifndef __DECODER_H

#define __DECODER_H


/* We need the eventinfo in here */
#include "eventinfo.h"


/* Plugin structure */
typedef struct
{
    int type;
    int fts;
    char *parent;
    char *name;
    char *regex;
    char *prematch;
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
