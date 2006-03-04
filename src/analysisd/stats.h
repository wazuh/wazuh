#ifndef _STAT__H

#define _STAT__H

/* Logstat functions */
void LastMsg_Change(char *log);
int LastMsg_Stats(char *log);

/* Stats definitions */
#define STATWQUEUE  "/stats/weekly"
#define STATQUEUE   "/stats/hourly"
#define STATSAVED   "/stats/total"


/* Other necessary global variables */

#endif
