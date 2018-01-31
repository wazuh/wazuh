/*
 * Copyright (C) 2018 Wazuh Inc.
 * January 17, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* vulnerability-detector messages*/
#define VU_DOWNLOAD           "(5430): Downloading %s database..."
#define VU_OVA_UPDATED        "(5431): %s OVAL has been updated correctly."
#define VU_START_SCAN         "(5432): Starting vulnerability scanning."
#define VU_END_SCAN           "(5433): Vulnerability scanning finished."
#define VU_START_AG_AN        "(5434): Analyzing agent %s vulnerabilities..."
#define VU_DETECTED_VUL       "(5435): Vulnerability %s detected in agent %s affecting: %s."
#define VU_NOT_VULN           "(5436): The '%s' package with its version %s is higher than %s, so the agent %s is not vulnerable."
#define VU_UPDATE_DATE        "(5437): %s OVAL is in its latest version. Update date: %s"
#define VU_START_REFRESH_DB   "(5438): Refreshing Ubuntu %s databases..."
#define VU_STOP_REFRESH_DB    "(5439): Refresh of Ubuntu %s database finished."
#define VU_DB_TIMESTAMP_OVAL  "(5440): %s OVAL has not been downloaded before, so the download continues."
#define VU_STARTING_UPDATE    "(5431): Starting %s DB update..."
#define VU_AGENT_SOFTWARE_REQ "(5432): Requesting Agent %s software..."
