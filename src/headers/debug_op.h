/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to generate debug/information/error/warning/critical reports
 *
 * We have two debug levels (1 and 2), a verbose mode and functions to catch warnings, errors, and critical situations
 *
 * To see these messages, use the "-d","-v" options (or "-d" twice to see debug2)
 * The merror is printed by default when an important error occurs
 */

#ifndef __DEBUG_H
#define __DEBUG_H

#ifndef __GNUC__
#define __attribute__(x)
#endif

/* For internal logs */
#ifndef LOGFILE
#ifndef WIN32
#define LOGFILE   "/logs/ossec.log"
#define LOGJSONFILE "/logs/ossec.json"
#else
#define LOGFILE "ossec.log"
#define LOGJSONFILE "ossec.json"
#endif
#endif

void mdebug1(const char *msg, ...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));
void mtdebug1(const char *tag, const char *msg, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull));
void mdebug2(const char *msg, ...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));
void mtdebug2(const char *tag, const char *msg, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull));
void merror(const char *msg, ...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));
void mterror(const char *tag, const char *msg, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull));
void mwarn(const char *msg, ...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));
void mtwarn(const char *tag, const char *msg, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull));
void minfo(const char *msg, ...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));
void mtinfo(const char *tag, const char *msg, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull));
void print_out(const char *msg, ...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));
void mferror(const char *msg, ... ) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));
void mtferror(const char *tag, const char *msg, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull));
void merror_exit(const char *msg, ...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull)) __attribute__ ((noreturn));
void mterror_exit(const char *tag, const char *msg, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull)) __attribute__ ((noreturn));

/* Function to read the logging format configuration */
void os_logging_config(void);

#ifdef WIN32
char * win_strerror(unsigned long error);
#endif

/* Use these three functions to set when you
 * enter in debug, chroot or daemon mode
 */
void nowDebug(void);
int isDebug(void);

void nowChroot(void);
void nowDaemon(void);

int isChroot(void);

/* Debug analysisd */
#ifdef DEBUGAD
#define DEBUG_MSG(x,y,z) minfo(x,y,z)
#else
#define DEBUG_MSG(x,y,z)
#endif /* end debug analysisd */

#endif /* __DEBUG_H */
