#ifndef _STAT__H

#define _STAT__H

/* Logstat functions */
void LastMsg_Change(char *log);
int LastMsg_Stats(char *log);

/* Stats definitions */
#define STATWQUEUE  "/stats/weekly-average"
#define STATQUEUE   "/stats/hourly-average"
#define STATSAVED   "/stats/totals"


#endif
