/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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

#ifndef DEBUG_H
#define DEBUG_H

#ifndef __GNUC__
#define __attribute__(x)
#endif

#include <stdarg.h>
#include <cJSON.h>
/* For internal logs */
#ifndef LOGFILE
#ifndef WIN32
#define LOGFILE   "logs/ossec.log"
#define LOGJSONFILE "logs/ossec.json"
#define _PRINTF_FORMAT printf
#else
#define LOGFILE "ossec.log"
#define LOGJSONFILE "ossec.json"
#define _PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#endif
#endif

#define mdebug1(msg, ...) _mdebug1(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define plain_mdebug1(msg, ...) _plain_mdebug1(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mtdebug1(tag, msg, ...) _mtdebug1(tag, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mdebug2(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mtdebug2(tag, msg, ...) _mtdebug2(tag, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _merror(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define plain_merror(msg, ...) _plain_merror(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mterror(tag, msg, ...) _mterror(tag, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mwarn(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define plain_mwarn(msg, ...) _plain_mwarn(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mtwarn(tag, msg, ...) _mtwarn(tag, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define minfo(msg, ...) _minfo(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define plain_minfo(msg, ...) _plain_minfo(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mtinfo(tag, msg, ...) _mtinfo(tag, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mferror(msg, ...) _mferror(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mtferror(tag, msg, ...) _mtferror(tag, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror_exit(msg, ...) _merror_exit(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define plain_merror_exit(msg, ...) _plain_merror_exit(__FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mterror_exit(tag, msg, ...) _mterror_exit(tag, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mlerror_exit(level, msg, ...) _mlerror_exit(level, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

void _mdebug1(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _plain_mdebug1(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull));
void _mdebug2(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _mtdebug2(const char *tag, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull));
void _merror(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _plain_merror(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull));
void _mverror(const char * file, int line, const char * func, const char *msg, va_list args)  __attribute__((nonnull));
void _mwarn(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _plain_mwarn(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _mtwarn(const char *tag, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull));
void _mvwarn(const char * file, int line, const char * func, const char *msg, va_list args)  __attribute__((nonnull));
void _minfo(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _plain_minfo(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull));
void _mvinfo(const char * file, int line, const char * func, const char *msg, va_list args)  __attribute__((nonnull));
void print_out(const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 1, 2))) __attribute__((nonnull));
void _mferror(const char * file, int line, const char * func, const char *msg, ... ) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull));
void _mtferror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull));
void _merror_exit(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull)) __attribute__ ((noreturn));
void _plain_merror_exit(const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 4, 5))) __attribute__((nonnull)) __attribute__ ((noreturn));
void _mterror_exit(const char *tag, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull)) __attribute__ ((noreturn));
void _mlerror_exit(const int level, const char * file, int line, const char * func, const char *msg, ...) __attribute__((format(_PRINTF_FORMAT, 5, 6))) __attribute__((nonnull)) __attribute__ ((noreturn));

/**
 * @brief Logging module initializer
 */
void w_logging_init();

/* Function to read the logging format configuration */
void os_logging_config();
cJSON *getLoggingConfig(void);

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


/**
 * @brief Wrapper for the tagged log functions.
 *
 * @param level Log level.
 * @param tag Tag representing the module sending the log.
 * @param file File name.
 * @param line Line number.
 * @param func Function name.
 * @param msg Message to send into the log.
 * @param args Variable arguments list.
 */
void mtLoggingFunctionsWrapper(int level, const char* tag, const char* file, int line, const char* func, const char* msg, va_list args);

#endif /* DEBUG_H */
