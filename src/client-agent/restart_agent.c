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
#include "headers/request_op.h"
#include "os_net/os_net.h"
#include "agentd.h"


int restartAgent() {

	char req[] = "restart";
	int req_size;
	int sock = -1;

	#ifndef WIN32

	char sockname[PATH_MAX + 1];

	if (isChroot()) {
		strcpy(sockname, COM_LOCAL_SOCK);
	} else {
		strcpy(sockname, DEFAULTDIR COM_LOCAL_SOCK);
	}

	if (sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR), sock < 0) {
		merror("At restartAgent(): Could not connect to socket '%s': %s (%d).", sockname, strerror(errno), errno);
		return -1;
	}

    req_size = strlen(req);
	if (send(sock, req, req_size, 0) != req_size) {
		merror("send(): %s", strerror(errno));
	}

	close(sock);

	#else
	//Windows
	#endif

	return 0;
}
