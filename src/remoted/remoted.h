
#ifndef __LOGREMOTE_H

#define __LOGREMOTE_H

#define SYSLOG_CONN 1   
#define SECURE_CONN 2

typedef struct _remoted
{
	char **port;
	char **group;
	char **conn;
	char **allowips;
	char **denyips;
}remoted;

int BindConf(char *cfgfile, remoted *logr);
#endif
