/*
 * Copyright (C) 2018 Wazuh Inc.
 * January 17, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #ifndef _DEBUG_MESSAGES__H
 #define _DEBUG_MESSAGES__H

/* vulnerability-detector messages*/
#define VU_DOWNLOAD           "(5450): Downloading %s database..."
#define VU_OVA_UPDATED        "(5451): %s OVAL has been updated correctly."
#define VU_START_SCAN         "(5452): Starting vulnerability scanning."
#define VU_END_SCAN           "(5453): Vulnerability scanning finished."
#define VU_START_AG_AN        "(5454): Analyzing agent %s vulnerabilities..."
#define VU_DETECTED_VUL       "(5455): Vulnerability %s detected in agent %s affecting: %s."
#define VU_NOT_VULN           "(5456): The '%s' package from agent %s is not vulnerable to %s. Condition: package version (%s) %s %s."
#define VU_UPDATE_DATE        "(5457): %s OVAL is in its latest version. Update date: %s"
#define VU_START_REFRESH_DB   "(5458): Refreshing Ubuntu %s databases..."
#define VU_STOP_REFRESH_DB    "(5459): Refresh of Ubuntu %s database finished."
#define VU_DB_TIMESTAMP_OVAL  "(5460): %s OVAL has not been downloaded before, so the download continues."
#define VU_STARTING_UPDATE    "(5461): Starting %s DB update..."
#define VU_AGENT_SOFTWARE_REQ "(5462): Getting agent %s software..."
#define VU_AGENT_UNSOPPORTED  "(5463): Agent %s has an unsupported Wazuh version."
#define VU_UNS_OS_VERSION     "(5464): %s version not supported (agent %s)."
#define VU_AGENT_PENDING      "(5465): Agent %s operating system could not be obtained because it has never been connected on. It will be omitted..."
#define VU_UNS_OS             "(5466): Unsupported OS. Agent %s will be omitted..."
#define VU_PACK_VER_VULN      "(5467): The '%s' package from agent %s is vulnerable to %s. Condition: package version (%s) %s %s."
#define VU_PACK_VULN          "(5468): The '%s' package is vulnerable to %s."
#define VU_UPDATE_PRE         "(5469): Preparse step."
#define VU_UPDATE_PAR         "(5470): Parse step."
#define VU_UPDATE_VU_CO       "(5471): Inserting vulnerability conditions..."
#define VU_UPDATE_VU_INFO     "(5472): Inserting vulnerability info..."
#define VU_UPDATE_VU          "(5473): Inserting vulnerabilities..."
#define VU_AGENT_INFO_ERROR   "(5474): Agent %s operating system could not be obtained. Maybe it is never connected. It will be omitted..."
#define VU_NO_SOFTWARE        "(5475): Agent %s software not available."
#define VU_AG_NO_TARGET       "(5476): The analysis can not be launched because there are no target agents."

#endif
