

#ifndef __DECODER_H

#define __DECODER_H


/* Plugin structure */
typedef struct
{
    char *name;
    char *regex;
    char *prematch;
    char *fts;
    char *ftscomment;
    char **order;
}PluginInfo;

/* List structure */
typedef struct _PluginNode
{
    struct _PluginNode *next;
    PluginInfo *plugin;
}PluginNode;



/* Functions to Create the list, Add a plugin to the
 * list and to get the first plugin.
 */
void OS_CreatePluginList();
void OS_AddPlugin(PluginInfo *pi);
PluginNode *OS_GetFirstPlugin();

#endif

/* EOF */
