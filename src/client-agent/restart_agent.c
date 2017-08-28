/* Agent restarting function
 * Copyright (C) 2017 Wazuh Inc.
 * Aug 23, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "headers/defs.h"
#include "os_execd/execd.h"
#include "os_net/os_net.h"
#include "config/syscheck-config.h"
#include "agentd.h"


void * restartAgent() {

	char req[] = "restart";
	ssize_t length;

	length = strlen(req);

	#ifndef WIN32

	int sock = -1;
	char sockname[PATH_MAX + 1];

	if (isChroot()) {
		strcpy(sockname, COM_LOCAL_SOCK);
	} else {
		strcpy(sockname, DEFAULTDIR COM_LOCAL_SOCK);
	}

	if (sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR), sock < 0) {
		merror("At restartAgent(): Could not connect to socket '%s': %s (%d).", sockname, strerror(errno), errno);
	} else if (send(sock, req, length, 0) != length) {
		merror("send(): %s", strerror(errno));
	}

	close(sock);

	#else

	char output[OS_MAXSTR + 1];
	length = wcom_dispatch(req, length, output);

	#endif

	return NULL;
}

int verifyRemoteConf(){
	const char *configPath;

	if (isChroot()) {
		configPath = AGENTCONFIGINT;

	} else {
		configPath = AGENTCONFIG;
	}

	if (Test_Syscheck(configPath) < 0) {
		return -1;
	}

	return 0;
};
