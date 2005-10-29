#ifndef _CONFIG__H

#define _CONFIG__H

#include "headers/defs.h"

/* Configuration structure */
typedef struct __Config
{
    int logall;
    int mailnotify;
    int exec;
    int fts;
    int stats;
    int integrity;
    int memorysize; /* For stateful analysis */
    int keeplogdate;
    int accuracy;
    
    int mailbylevel;
    int logbylevel;

    char **syscheck_ignore;
    int syscheck_threshold;
}_Config;


typedef struct _ar_command
{
    char *name;
    char *expect;
    char *executable;
}ar_command;


typedef struct _ar
{
    char *command;
    char *location;
    char *rules_id;
    char *rules_group;
    char *level;
}ar;


ar_command **ar_commands;
ar **active-responses;

_Config Config;  /* Global Config structure */



#endif
