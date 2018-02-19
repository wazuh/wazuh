/* This is a trivial uptime program.  I hereby release this program
 * into the public domain.  I disclaim any responsibility for this
 * program --- use it at your own risk.  (as if there were any.. ;-)
 * -michaelkjohnson (johnsonm@sunsite.unc.edu)
 *
 * Modified by Larry Greenfield to give a more traditional output,
 * count users, etc.  (greenfie@gauss.rutgers.edu)
 *
 * Modified by mkj again to fix a few tiny buglies.
 *
 * Modified by J. Cowley to add printing the uptime message to a
 * string (for top) and to optimize file handling.  19 Mar 1993.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <utmp.h>
#include <sys/ioctl.h>
#include "whattime.h"
#include "sysinfo.h"

static char buf[128];
static double av[3];

char *sprint_uptime(void) {
  struct utmp *utmpstruct;
  int upminutes, uphours, updays;
  int pos;
  struct tm *realtime;
  time_t realseconds;
  int numuser;
  double uptime_secs, idle_secs;

/* first get the current time */

  time(&realseconds);
  realtime = localtime(&realseconds);
  pos = sprintf(buf, " %02d:%02d:%02d ",
    realtime->tm_hour, realtime->tm_min, realtime->tm_sec);

/* read and calculate the amount of uptime */

  uptime(&uptime_secs, &idle_secs);

  updays = (int) uptime_secs / (60*60*24);
  strcat (buf, "up ");
  pos += 3;
  if (updays)
    pos += sprintf(buf + pos, "%d day%s, ", updays, (updays != 1) ? "s" : "");
  upminutes = (int) uptime_secs / 60;
  uphours = upminutes / 60;
  uphours = uphours % 24;
  upminutes = upminutes % 60;
  if(uphours)
    pos += sprintf(buf + pos, "%2d:%02d, ", uphours, upminutes);
  else
    pos += sprintf(buf + pos, "%d min, ", upminutes);

/* count the number of users */

  numuser = 0;
  setutent();
  while ((utmpstruct = getutent())) {
    if ((utmpstruct->ut_type == USER_PROCESS) &&
       (utmpstruct->ut_name[0] != '\0'))
      numuser++;
  }
  endutent();

  pos += sprintf(buf + pos, "%2d user%s, ", numuser, numuser == 1 ? "" : "s");

  loadavg(&av[0], &av[1], &av[2]);

  pos += sprintf(buf + pos, " load average: %.2f, %.2f, %.2f",
		 av[0], av[1], av[2]);

  return buf;
}

void print_uptime(void) {
  printf("%s\n", sprint_uptime());
}
