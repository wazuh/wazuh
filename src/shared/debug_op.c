/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "headers/shared.h"
#include <external/cJSON/cJSON.h>

#ifdef WIN32
#define localtime_r(x, y) localtime_s(y, x)
#endif

static int dbg_flag = 0;
static int chroot_flag = 0;
static int daemon_flag = 0;
static int pid;

struct{
  unsigned int log_plain:1;
  unsigned int log_json:1;
  unsigned int read:1;
} flags;

static void _log(int level, const char *tag, const char * file, int line, const char * func, const char *msg, va_list args) __attribute__((format(printf, 5, 0))) __attribute__((nonnull));

#ifdef WIN32
void WinSetError();
#endif

static void _log(int level, const char *tag, const char * file, int line, const char * func, const char *msg, va_list args)
{
    time_t now;
    struct tm localtm;
    va_list args2; /* For the stderr print */
    va_list args3; /* For the JSON output */
    FILE *fp;
    char timestamp[OS_MAXSTR];
    char jsonstr[OS_MAXSTR];
    char *output;
    char logfile[PATH_MAX + 1];
    char * filename;

    const char *strlevel[5]={
      "DEBUG",
      "INFO",
      "WARNING",
      "ERROR",
      "CRITICAL",
    };
    const char *strleveljson[5]={
      "debug",
      "info",
      "warning",
      "error",
      "critical"
    };

    now = time(NULL);
    localtime_r(&now, &localtm);
    /* Duplicate args */
    va_copy(args2, args);
    va_copy(args3, args);

    if (!flags.read) {
      os_logging_config();
    }

    if (filename = strrchr(file, '/'), filename) {
        file = filename + 1;
    }

    if (flags.log_json) {

#ifndef WIN32
        int oldmask;

        strncpy(logfile, isChroot() ? LOGJSONFILE : DEFAULTDIR LOGJSONFILE, sizeof(logfile) - 1);
        logfile[sizeof(logfile) - 1] = '\0';

        if (!IsFile(logfile)) {
            fp = fopen(logfile, "a");
        } else {
            oldmask = umask(0006);
            fp = fopen(logfile, "w");
            umask(oldmask);

            // Make sure that the group is ossec

            if (fp && getuid() == 0) {
                gid_t group;

                if (group = Privsep_GetGroup(GROUPGLOBAL), group != (gid_t)-1) {
                    if (chown(logfile, 0, group)) {
                        // Don't log anything
                    }
                }
            }
        }
#else
        strncpy(logfile, LOGJSONFILE, sizeof(logfile) - 1);
        logfile[sizeof(logfile) - 1] = '\0';
        fp = fopen(logfile, "a");
#endif

        if (fp) {
            cJSON *json_log = cJSON_CreateObject();

            snprintf(timestamp,OS_MAXSTR,"%d/%02d/%02d %02d:%02d:%02d",
                    localtm.tm_year + 1900, localtm.tm_mon + 1,
                    localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

            vsnprintf(jsonstr, OS_MAXSTR, msg, args3);

            cJSON_AddStringToObject(json_log, "timestamp", timestamp);
            cJSON_AddStringToObject(json_log, "tag", tag);

            if (dbg_flag > 0) {
                cJSON_AddNumberToObject(json_log, "pid", pid);
                cJSON_AddStringToObject(json_log, "file", file);
                cJSON_AddNumberToObject(json_log, "line", line);
                cJSON_AddStringToObject(json_log, "routine", func);
            }

            cJSON_AddStringToObject(json_log, "level", strleveljson[level]);
            cJSON_AddStringToObject(json_log, "description", jsonstr);

            output = cJSON_PrintUnformatted(json_log);

            (void)fprintf(fp, "%s", output);
            (void)fprintf(fp, "\n");

            cJSON_Delete(json_log);
            free(output);
            fflush(fp);
            fclose(fp);
        }
    }

    if (flags.log_plain) {
      /* If under chroot, log directly to /logs/ossec.log */

#ifndef WIN32
        int oldmask;

        strncpy(logfile, isChroot() ? LOGFILE : DEFAULTDIR LOGFILE, sizeof(logfile) - 1);
        logfile[sizeof(logfile) - 1] = '\0';

        if (!IsFile(logfile)) {
            fp = fopen(logfile, "a");
        } else {
            oldmask = umask(0006);
            fp = fopen(logfile, "w");
            umask(oldmask);

            // Make sure that the group is ossec

            if (fp && getuid() == 0) {
                gid_t group;

                if (group = Privsep_GetGroup(GROUPGLOBAL), group != (gid_t)-1) {
                    if (chown(logfile, 0, group)) {
                        // Don't log anything
                    }
                }
            }
        }
#else
        strncpy(logfile, LOGFILE, sizeof(logfile) - 1);
        logfile[sizeof(logfile) - 1] = '\0';
        fp = fopen(logfile, "a");
#endif

        /* Maybe log to syslog if the log file is not available */
        if (fp) {
            (void)fprintf(fp, "%d/%02d/%02d %02d:%02d:%02d ",
                        localtm.tm_year + 1900, localtm.tm_mon + 1,
                        localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

            if (dbg_flag > 0) {
                (void)fprintf(fp, "%s[%d] %s:%d at %s(): ", tag, pid, file, line, func);
            } else {
                (void)fprintf(fp, "%s: ", tag);
            }

            (void)fprintf(fp, "%s: ", strlevel[level]);
            (void)vfprintf(fp, msg, args);
            (void)fprintf(fp, "\n");

            fflush(fp);
            fclose(fp);
        }
    }

    /* Only if not in daemon mode */
    if (daemon_flag == 0) {
        /* Print to stderr */
        (void)fprintf(stderr, "%d/%02d/%02d %02d:%02d:%02d ",
                      localtm.tm_year + 1900, localtm.tm_mon + 1 , localtm.tm_mday,
                      localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

        if (dbg_flag > 0) {
            (void)fprintf(stderr, "%s[%d] %s:%d at %s(): ", tag, pid, file, line, func);
        } else {
            (void)fprintf(stderr, "%s: ", tag);
        }

        (void)fprintf(stderr, "%s: ", strlevel[level]);
        (void)vfprintf(stderr, msg, args2);
#ifdef WIN32
        (void)fprintf(stderr, "\r\n");
#else
        (void)fprintf(stderr, "\n");
#endif
    }

    /* args must be ended here */
    va_end(args2);
    va_end(args3);
}

void os_logging_config(){
  OS_XML xml;
  const char * xmlf[] = {"ossec_config", "logging", "log_format", NULL};
  char * logformat;
  char ** parts = NULL;
  int i;

  pid = (int)getpid();
  flags.read = 1;

  if (OS_ReadXML(chroot_flag ? OSSECCONF : DEFAULTCPATH, &xml) < 0){
    flags.log_plain = 1;
    flags.log_json = 0;
    OS_ClearXML(&xml);
    merror_exit(XML_ERROR, chroot_flag ? OSSECCONF : DEFAULTCPATH, xml.err, xml.err_line);
  }

  logformat = OS_GetOneContentforElement(&xml, xmlf);

  if (!logformat || logformat[0] == '\0'){

    flags.log_plain = 1;
    flags.log_json = 0;

    free(logformat);
    OS_ClearXML(&xml);
    mdebug1(XML_NO_ELEM, "log_format");

  }else{

    parts = OS_StrBreak(',', logformat, 2);
    char * part;
    if (parts){
      for (i=0; parts[i]; i++){
        part = w_strtrim(parts[i]);
        if (!strcmp(part, "plain")){
          flags.log_plain = 1;
        }else if(!strcmp(part, "json")){
          flags.log_json = 1;
        }else{
          flags.log_plain = 1;
          flags.log_json = 0;
          merror_exit(XML_VALUEERR, "log_format", part);
        }
      }
      for (i=0; parts[i]; i++){
        free(parts[i]);
      }
      free(parts);
    }

    free(logformat);
    OS_ClearXML(&xml);
  }
}

cJSON *getLoggingConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *logg = cJSON_CreateObject();

    if (flags.log_plain) cJSON_AddStringToObject(logg,"plain","yes"); else cJSON_AddStringToObject(logg,"plain","no");
    if (flags.log_json) cJSON_AddStringToObject(logg,"json","yes"); else cJSON_AddStringToObject(logg,"json","no");

    cJSON_AddItemToObject(root,"logging",logg);

    return root;
}

void _mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    if (dbg_flag >= 1) {
        va_list args;
        int level = LOGLEVEL_DEBUG;
        const char *tag = __local_name;
        va_start(args, msg);
        _log(level, tag, file, line, func, msg, args);
        va_end(args);
    }
}

void _mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    if (dbg_flag >= 1) {
        va_list args;
        int level = LOGLEVEL_DEBUG;
        va_start(args, msg);
        _log(level, tag, file, line, func, msg, args);
        va_end(args);
    }
}

void _mdebug2(const char * file, int line, const char * func, const char *msg, ...)
{
    if (dbg_flag >= 2) {
        va_list args;
        int level = LOGLEVEL_DEBUG;
        const char *tag = __local_name;
        va_start(args, msg);
        _log(level, tag, file, line, func, msg, args);
        va_end(args);
    }
}

void _mtdebug2(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    if (dbg_flag >= 2) {
        va_list args;
        int level = LOGLEVEL_DEBUG;
        va_start(args, msg);
        _log(level, tag, file, line, func, msg, args);
        va_end(args);
    }
}

void _merror(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_ERROR;
    const char *tag = __local_name;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);
}

void _mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_ERROR;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);
}

void _mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_WARNING;
    const char *tag = __local_name;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);
}

void _mtwarn(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_WARNING;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);
}

void _minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_INFO;
    const char *tag = __local_name;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);
}

void _mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_INFO;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);
}

/* Only logs to a file */
void _mferror(const char * file, int line, const char * func, const char *msg, ...)
{
    int level = LOGLEVEL_ERROR;
    const char *tag = __local_name;
    int dbg_tmp;
    va_list args;
    va_start(args, msg);

    /* We set daemon flag to 1, so nothing is printed to the terminal */
    dbg_tmp = daemon_flag;
    daemon_flag = 1;
    _log(level, tag, file, line, func, msg, args);

    daemon_flag = dbg_tmp;

    va_end(args);
}

/* Only logs to a file */
void _mtferror(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    int level = LOGLEVEL_ERROR;
    int dbg_tmp;
    va_list args;
    va_start(args, msg);

    /* We set daemon flag to 1, so nothing is printed to the terminal */
    dbg_tmp = daemon_flag;
    daemon_flag = 1;
    _log(level, tag, file, line, func, msg, args);

    daemon_flag = dbg_tmp;

    va_end(args);
}

void _merror_exit(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_CRITICAL;
    const char *tag = __local_name;

#ifdef WIN32
    /* If not MA */
#ifndef MA
    WinSetError();
#endif
#endif

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);

    exit(1);
}

void _mterror_exit(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_CRITICAL;

#ifdef WIN32
    /* If not MA */
#ifndef MA
    WinSetError();
#endif
#endif

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);

    exit(1);
}

void nowChroot()
{
    chroot_flag = 1;
}

void nowDaemon()
{
    daemon_flag = 1;
}

void print_out(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

    /* Print to stderr */
    (void)vfprintf(stderr, msg, args);

#ifdef WIN32
    (void)fprintf(stderr, "\r\n");
#else
    (void)fprintf(stderr, "\n");
#endif

    va_end(args);
}

void nowDebug()
{
    dbg_flag++;
}

int isDebug(void)
{
    return dbg_flag;
}

int isChroot()
{
    return (chroot_flag);
}

#ifdef WIN32
char * win_strerror(unsigned long error) {
    static TCHAR messageBuffer[4096];
    LPSTR end;

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, messageBuffer, sizeof(messageBuffer) / sizeof(TCHAR), NULL);

    if (end = strchr(messageBuffer, '\r'), end) {
        *end = '\0';
    }

    return messageBuffer;
}
#endif
