/* Agent restarting function
 * Copyright (C) 2015, Wazuh Inc.
 * Aug 23, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "defs.h"
#include "execd.h"
#include "os_net.h"
#include "syscheck-config.h"
#include "rootcheck-config.h"
#include "localfile-config.h"
#include "client-config.h"
#include "wmodules.h"
#include "agentd.h"
#include "https_client_bridge.h"

static const char AG_IN_RCON[] = "wazuh: Invalid remote configuration";

/* Shared implementation for reloadAgent()/restartAgent(): sends `action`
 * ("reload" or "restart") to wm_control's dispatcher, the same mechanism
 * wm_control_dispatch() (src/wazuh_modules/src/wm_control.c) already handles
 * symmetrically for both verbs (systemctl <action> / bin/wazuh-control
 * <action> fallback on Linux/macOS; control_run_detached(action, ...) on
 * Windows). agent_reload already drove this path (reloadAgent()); restartAgent()
 * reuses it for the agent_restart task_type, which previously had no caller at all.
 */
static bool controlAgent(const char *action) {

	char req[16];
	snprintf(req, sizeof(req), "%s", action);

	#ifndef WIN32

	ssize_t length;
	length = strlen(req);

	int sock = -1;
	char sockname[PATH_MAX + 1];
	const int max_retries = 30;
	const int retry_delay_s = 1;
	int attempt;

	strcpy(sockname, CONTROL_SOCK);

	for (attempt = 0; attempt < max_retries; attempt++) {
		sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR);
		if (sock >= 0) {
			break;
		}

		if (errno == ENOENT || errno == ECONNREFUSED) {
			mdebug1("Control socket '%s' not yet available (attempt %d/%d), retrying...", sockname, attempt + 1, max_retries);
			sleep(retry_delay_s);
		} else {
			merror("At controlAgent(%s): Could not connect to socket '%s': %s (%d).", action, sockname, strerror(errno), errno);
			return false;
		}
	}

	if (sock < 0) {
		merror("Could not auto-%s agent. Could not connect to control socket '%s' after %d attempts.", action, sockname, max_retries);
		return false;
	}

	if (OS_SendSecureTCP(sock, length, req)) {
		merror("OS_SendSecureTCP(): %s", strerror(errno));
		close(sock);
		return false;
	}

	close(sock);
	return true;

	#else

	char *output = NULL;
	control_dispatch(req, &output);
	/* control_dispatch() (control.c) reports its own outcome via *output: "ok "
	 * on success, "err <reason>" (CreateProcess/GetModuleFileName failure, or an
	 * unrecognized command) otherwise -- it never fails by return value, only by
	 * this string, so it must be checked instead of assuming success -- this used to
	 * always return true, reporting failed restarts/reloads as dispatched. */
	bool ok = output && strncmp(output, "ok", 2) == 0;
	if (!ok) {
		merror("Could not auto-%s agent: %s", action, output ? output : "(no response)");
	}
	free(output);
	return ok;

	#endif
}

bool reloadAgent(void) {
	return controlAgent("reload");
}

bool restartAgent(void) {
	return controlAgent("restart");
}

int verifyRemoteConf(){
	const char *configPath;
 	char msg_output[OS_MAXSTR];

	configPath = AGENTCONFIG;

	if (Test_Syscheck(configPath) < 0) {
		snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ",  LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "syscheck");
		goto fail;
	} else if (Test_Rootcheck(configPath) < 0) {
		snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ",  LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "rootcheck");
		goto fail;
    } else if (Test_Localfile(configPath) < 0) {
		snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ",  LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "localfile");
		goto fail;
    } else if (Test_Agent(configPath) < 0) {
		snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ",  LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "client");
		goto fail;
	} else if (Test_WModule(configPath) < 0) {
		snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ",  LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "wodle");
		goto fail;
    }

	return 0;

	fail:
		mdebug2("Invalid remote configuration received");
		/* Manager-visible report, now over /stateless. */
		w_https_client_submit_event(msg_output, strlen(msg_output));
		return OS_INVALID;
};
