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
    int externbylevel;
    char *externcmdbylevel[HIGHLEVEL +1];
    char **syscheck_ignore;
    int syscheck_threshold;
}_Config;

_Config Config;  /* Global Config structure */



#endif
