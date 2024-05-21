/*
 * Wazuh module parser
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_PARSER_H
#define WM_PARSER_H

/**
 * @brief Parse the output of the GCP/AWS/AZURE or any script and prints it depending on the debug
 *        level stated by the script
 * @param output Output returned by the call to the script
 * @param logger_name String to match with content of output
 * @param tag Tag that should be used when printing the messages
 * @param service_title String indicating which service is used
 */
void wm_parse_output(char *output, char *logger_name, char *tag, char* service_title);

#define _W_STRING_MAX   67108864  // Max. dynamic string size (64 MB).

#define W_STR_DEBUG     "- DEBUG - "
#define W_STR_INFO      "- INFO - "
#define W_STR_CRITICAL  "- CRITICAL - "
#define W_STR_ERROR     "- ERROR - "
#define W_STR_WARNING   "- WARNING - "

#endif /*WM_PARSER_H*/
