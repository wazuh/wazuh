/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#define VU_FEED_UPDATED       "(5451): %s feed has been updated correctly."
#define VU_START_SCAN         "(5452): Starting vulnerability scanning."
#define VU_END_SCAN           "(5453): Vulnerability scanning finished."
#define VU_START_AG_AN        "(5454): Analyzing agent %s vulnerabilities..."
#define VU_DETECTED_VUL       "(5455): Vulnerability %s detected in agent %s affecting: %s."
#define VU_NOT_VULN           "(5456): The '%s' package from agent %s is not vulnerable to %s. Condition: package version (%s) %s %s."
#define VU_UPDATE_DATE        "(5457): %s OVAL is in its latest version. Update date: %s"
#define VU_START_REFRESH_DB   "(5458): Refreshing %s databases..."
#define VU_STOP_REFRESH_DB    "(5459): Refresh of %s database finished."
#define VU_DB_TIMESTAMP_FEED  "(5460): %s feed has not been downloaded before, so the update continues."
#define VU_STARTING_UPDATE    "(5461): Starting %s database update..."
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
#define VU_NO_SOFTWARE        "(5475): No changes have been found with respect to the last package inventory for agent %s."
#define VU_AG_NO_TARGET       "(5476): The analysis can not be launched because there are no target agents."
#define VU_AG_DISC            "(5477): The vulnerabilities of the agent %s will not be checked because it is disconnected."
#define VU_LOCAL_FETCH        "(5478): Fetching feed from '%s'..."
#define VU_OPERATION_NOT_REC  "(5479): Operation '%s' not recognized."
#define VU_DOUBLE_NOT_VULN    "(5480): The '%s' package from agent %s is not vulnerable to %s. Condition: package version (%s) %s %s and %s %s."
#define VU_DOUBLE_VULN        "(5481): The '%s' package from agent %s is vulnerable to %s. Condition: package version (%s) %s %s and %s %s."
#define VU_UNEXP_VALUE        "(5482): Unexpected %s attribute."
#define VU_SOL_PATCHES        "(5483): Solving patches..."
#define VU_INS_TEST_SEC       "(5484): Inserting test section..."
#define VU_SYS_CHECKED        "(5485): The last package inventory for the agent %s (ID: %s) has already been checked. The vulnerability search is omitted."
#define VU_AGENT_START        "(5486): Starting vulnerability assessment for agent %s."
#define VU_AGENT_FINISH       "(5487): Finished vulnerability assessment for agent %s."
#define VU_AG_NEVER_CON       "(5488): Agent '%s' never connected."
#define VU_API_REQ_RETRY      "(5490): There was no valid response to '%s'. Retrying in %d seconds..."
#define VU_UNEXP_JSON_KEY     "(5492): Unexpected JSON key: '%s'."
#define VU_ENDING_UPDATE      "(5494): The update of the feeds ended successfully."
#define VU_DOWNLOAD_FAIL      "(5495): The download can not be completed. Retrying in %d seconds."
#define VU_INS_CPES_SEC       "(5498): Inserting CPEs section..."
#define VU_AGENT_CPE_RECV     "(5507): The CPE '%s' from the agent %d was received from wazuh-db."
#define VU_CPE_GENERATED      "(5509): CPE generated from vendor '%s' and product '%s': '%s'."
#define VU_UPDATING_NVD_YEAR  "(5512): Synchronizing the year %d of the vulnerability database..."
#define VU_GEN_CPE_COUNT      "(5514): CPEs generated for agent %s: %d/%d."
#define VU_INS_NVD_SEC        "(5516): Inserting NVD section..."
#define VU_SOCKET_RETRY       "(5518): Unable to connect to socket '%s'. Waiting %d seconds."
#define VU_INS_CPES_DIC       "(5523): Inserting Wazuh's CPE dictonary..."
#define VU_FUNCTION_TIME      "(5529): It took %ld seconds to %s vulnerabilities in agent %s."
#define VU_INS_MSB            "(5530): Inserting Microsoft Bulletins dictonary..."
#define VU_HOTFIX_VUL         "(5533): Agent %s is vulnerable to %s because does not have the '%s' patch installed."
#define VU_HOTFIX_INSTALLED   "(5534): Agent %s has installed %s that corrects the vulnerability %s."
#define VU_UPDATE_JSON_FEED   "(5537): Updating from '%s'..."
#define VU_INDEX_TIME         "(5538): It took %ld seconds to %s vulnerabilities."
#define VU_UPDATING_RH_YEAR   "(5539): Synchronizing the page %d from the vulnerability database..."
#define VU_INS_RH_SEC         "(5540): Inserting Red Hat section..."

#endif
