/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <windows.h>
#include "os_regex/os_regex.h"
#include "headers/file_op.h"

#define OSSECCONF   "ossec.conf"
#define OSSECDEF    "default-ossec.conf"
#define OSSECLAST   "ossec.conf.bak"
#define CLIENTKEYS  "client.keys"
#define OS_MAXSTR   1024


/* Check if a file exists */
int fileexist(char *file);

/* Grep for a string in a file */
int dogrep(char *file, char *str);

/* Check if dir exists */
int direxist(char *dir);

/* Get Windows main directory */
void get_win_dir(char *file, int f_size);
