/*
 * Copyright (C) 2018 Wazuh Inc.
 * June 13, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

typedef enum WPOL_LANGUAGES {
    WPOL_ENGLISH,
    WPOL_SIZE
} WPOL_LANGUAGES;

const char *WPOL_DETECTION_WORD[] = {
    "Policy Target"
};

const char *WPOL_HANDLE_MAN_VERSIONS[] = {
    ",System,Handle Manipulation,"
};

const char *WPOL_FILE_SYSTEM_VERSIONS[] = {
    ",System,File System,"
};

const char *WPOL_NO_AUDITING_VERSIONS[] = {
    ",No Auditing,"
};

const char *WPOL_FAILURE_VERSIONS[] = {
    ",Failure,"
};

const char *WPOL_SUCCESS_VERSIONS[] = {
    ",Success,,1"
};
