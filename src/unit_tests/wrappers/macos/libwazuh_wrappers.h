/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STDIO_WRAPPERS_LIBWAZUH_H
#define STDIO_WRAPPERS_LIBWAZUH_H


#undef mterror
#define mterror wrap_mterror
#undef mtwarn
#define mtwarn wrap_mtwarn
#undef mtdebug1
#define mtdebug1 wrap_mtdebug1
#undef mtdebug2
#define mtdebug2 wrap_mtdebug2
#undef wm_sendmsg
#define wm_sendmsg wrap_wm_sendmsg

void wrap_mterror(const char *tag, const char *msg, ...);
void wrap_mtwarn(const char *tag, const char *msg, ...);
void wrap_mtdebug1(const char *tag, const char *msg, ...);
void wrap_mtdebug2(const char *tag, const char *msg, ...);
int wrap_wm_sendmsg(int usec,
                    int queue,
                    const char *message,
                    const char *locmsg,
                    char loc);

#endif
