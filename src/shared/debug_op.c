/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
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

static struct{
  unsigned int log_plain:1;
  unsigned int log_json:1;
  unsigned int initialized:1;
  unsigned int mutex_initialized:1;
} flags;

static pthread_mutex_t logging_mutex;

static void _log_function(int level, const char *tag, const char * file, int line, const char * func, const char *msg, bool plain_only, va_list args) __attribute__((format(printf, 5, 0))) __attribute__((nonnull));

// Wrapper for the real _log_function
static void _log(int level, const char *tag, const char * file, int line, const char * func, const char *msg, va_list args) __attribute__((format(printf, 5, 0))) __attribute__((nonnull));
static void _log(int level, const char *tag, const char * file, int line, const char * func, const char *msg, va_list args) {
    _log_function(level, tag, file, line, func, msg, false, args);
}


#ifdef WIN32
void WinSetError();
#endif

static void print_stderr_msg(char* timestamp, const char *tag, const char * file, int line, const char * func, const char* level, const char *msg, bool use_va_list, va_list args2) {
    (void)fprintf(stderr, "%s ", timestamp);

    if (dbg_flag > 0) {
        (void)fprintf(stderr, "%s[%d] %s:%d at %s(): ", tag, pid, file, line, func);
    } else {
        (void)fprintf(stderr, "%s: ", tag);
    }

    (void)fprintf(stderr, "%s: ", level);
    if (use_va_list) {
        (void)vfprintf(stderr, msg, args2);
    } else {
        (void)fprintf(stderr, "%s", msg);
    }
#ifdef WIN32
    (void)fprintf(stderr, "\r\n");
#else
    (void)fprintf(stderr, "\n");
#endif
}

static void _log_function(int level, const char *tag, const char * file, int line, const char * func, const char *msg, bool plain_only, va_list args)
{
    va_list args2; /* For the stderr print */
    va_list args3; /* For the JSON output */
    FILE *fp;
    char jsonstr[OS_MAXSTR];
    char *output;
    char logfile[PATH_MAX + 1];
    char * filename;
    char *timestamp = w_get_timestamp(time(NULL));

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

    /* Duplicate args */
    va_copy(args2, args);
    va_copy(args3, args);

    if (!flags.initialized) {
        /* If not initialized and plain_only is true, we avoid reading the
           the ossec.conf file due to the call to many shared libraries (XML read, etc.).
           The module will be initialized later. */
        if(plain_only) {
            flags.log_plain = 1;
            flags.log_json = 0;
            if(!flags.mutex_initialized) {
                flags.mutex_initialized = 1;
                int error_code = pthread_mutex_init(&logging_mutex, NULL);
                if (error_code != 0 && daemon_flag == 0) {
                    char err_msg[OS_SIZE_128] = {0};
                    snprintf(err_msg, OS_SIZE_128, "Failed to initialize logging mutex (%d).", error_code);
                    print_stderr_msg(timestamp, __local_name, __FILE__, __LINE__, __func__, strlevel[LOGLEVEL_ERROR],
                                     err_msg, false, args);
                }
            }
        } else {
            w_logging_init();
            mdebug1("Logging module auto-initialized");
        }
    }

    if (filename = strrchr(file, '/'), filename) {
        file = filename + 1;
    }

    /* The plain_only flag allows to bypass the JSON output even when it's enabled to
       avoid the call to external libraries like cJSON. */
    if (!plain_only && flags.log_json) {

#ifndef WIN32
        int oldmask;

        strncpy(logfile, LOGJSONFILE, sizeof(logfile) - 1);
        logfile[sizeof(logfile) - 1] = '\0';

        if (!IsFile(logfile)) {
            fp = wfopen(logfile, "a");
        } else {
            oldmask = umask(0006);
            fp = wfopen(logfile, "w");
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
        fp = wfopen(logfile, "a");
#endif

        if (fp) {
            cJSON *json_log = cJSON_CreateObject();

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

            w_mutex_lock(&logging_mutex);
            (void)fprintf(fp, "%s", output);
            (void)fprintf(fp, "\n");
            fflush(fp);
            w_mutex_unlock(&logging_mutex);

            cJSON_Delete(json_log);
            free(output);
            fclose(fp);
        }
    }

    if (flags.log_plain) {
      /* If under chroot, log directly to /logs/ossec.log */

#ifndef WIN32
        int oldmask;

        strncpy(logfile, LOGFILE, sizeof(logfile) - 1);
        logfile[sizeof(logfile) - 1] = '\0';

        if (!IsFile(logfile)) {
            fp = wfopen(logfile, "a");
        } else {
            oldmask = umask(0006);
            fp = wfopen(logfile, "w");
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
        fp = wfopen(logfile, "a");
#endif

        /* Maybe log to syslog if the log file is not available */
        if (fp) {
            // Not using w_ variant to avoid calling this same method again.
            int error_code = pthread_mutex_lock(&logging_mutex);
            if (error_code != 0 && daemon_flag == 0) {
                char err_msg[OS_SIZE_128] = {0};
                snprintf(err_msg, OS_SIZE_128, "Failed to lock logging mutex (%d).", error_code);
                print_stderr_msg(timestamp, __local_name, __FILE__, __LINE__, __func__, strlevel[LOGLEVEL_ERROR],
                                 err_msg, false, args);
            }
            (void)fprintf(fp, "%s ", timestamp);

            if (dbg_flag > 0) {
                (void)fprintf(fp, "%s[%d] %s:%d at %s(): ", tag, pid, file, line, func);
            } else {
                (void)fprintf(fp, "%s: ", tag);
            }

            (void)fprintf(fp, "%s: ", strlevel[level]);
            (void)vfprintf(fp, msg, args);
            (void)fprintf(fp, "\n");
            fflush(fp);
            // Not using w_ variant to avoid calling this same method again.
            error_code = pthread_mutex_unlock(&logging_mutex);
            if (error_code != 0 && daemon_flag == 0) {
                char err_msg[OS_SIZE_128] = {0};
                snprintf(err_msg, OS_SIZE_128, "Failed to unlock logging mutex (%d).", error_code);
                print_stderr_msg(timestamp, __local_name, __FILE__, __LINE__, __func__, strlevel[LOGLEVEL_ERROR],
                                 err_msg, false, args);
            }

            fclose(fp);
        }
    }

    /* Only if not in daemon mode */
    if (daemon_flag == 0) {
        print_stderr_msg(timestamp, tag, file, line, func, strlevel[level], msg, true, args2);
    }

    free(timestamp);
    /* args must be ended here */
    va_end(args2);
    va_end(args3);
}

void w_logging_init(){
    flags.initialized = 1;
    if(!flags.mutex_initialized) {
        flags.mutex_initialized = 1;
        w_mutex_init(&logging_mutex, NULL);
    }
    os_logging_config();
}

void os_logging_config(){
  OS_XML xml;
  const char * xmlf[] = {"ossec_config", "logging", "log_format", NULL};
  char * logformat;
  char ** parts = NULL;
  int i;

  pid = (int)getpid();

  if (OS_ReadXML(OSSECCONF, &xml) < 0){
    flags.log_plain = 1;
    flags.log_json = 0;
    OS_ClearXML(&xml);
    mlerror_exit(LOGLEVEL_ERROR, XML_ERROR, OSSECCONF, xml.err, xml.err_line);
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
          mlerror_exit(LOGLEVEL_ERROR, XML_VALUEERR, "log_format", part);
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

void _plain_mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    if (dbg_flag >= 1) {
        va_list args;
        int level = LOGLEVEL_DEBUG;
        const char *tag = __local_name;
        va_start(args, msg);
        _log_function(level, tag, file, line, func, msg, true, args);
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

void _plain_merror(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_ERROR;
    const char *tag = __local_name;

    va_start(args, msg);
    _log_function(level, tag, file, line, func, msg, true, args);
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

void _mverror(const char * file, int line, const char * func, const char *msg, va_list args)
{
    int level = LOGLEVEL_ERROR;
    const char *tag = __local_name;
    _log(level, tag, file, line, func, msg, args);
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

void _plain_mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_WARNING;
    const char *tag = __local_name;

    va_start(args, msg);
    _log_function(level, tag, file, line, func, msg, true, args);
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

void _mvwarn(const char * file, int line, const char * func, const char *msg, va_list args)
{
    int level = LOGLEVEL_WARNING;
    const char *tag = __local_name;
    _log(level, tag, file, line, func, msg, args);
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

void _plain_minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_INFO;
    const char *tag = __local_name;

    va_start(args, msg);
    _log_function(level, tag, file, line, func, msg, true, args);
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

void _mvinfo(const char * file, int line, const char * func, const char *msg, va_list args)
{
    int level = LOGLEVEL_INFO;
    const char *tag = __local_name;
    _log(level, tag, file, line, func, msg, args);
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

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);

#ifdef WIN32
    /* If not MA */
#ifndef MA
    WinSetError();
#endif
#endif

    exit(1);
}

void _plain_merror_exit(const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_CRITICAL;
    const char *tag = __local_name;

    va_start(args, msg);
    _log_function(level, tag, file, line, func, msg, true, args);
    va_end(args);

#ifdef WIN32
    /* If not MA */
#ifndef MA
    WinSetError();
#endif
#endif

    exit(1);
}

void _mterror_exit(const char *tag, const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    int level = LOGLEVEL_CRITICAL;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);

#ifdef WIN32
    /* If not MA */
#ifndef MA
    WinSetError();
#endif
#endif

    exit(1);
}

void _mlerror_exit(const int level, const char * file, int line, const char * func, const char *msg, ...)
{
    va_list args;
    const char *tag = __local_name;

    va_start(args, msg);
    _log(level, tag, file, line, func, msg, args);
    va_end(args);

#ifdef WIN32
    /* If not MA */
#ifndef MA
    WinSetError();
#endif
#endif

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

void mtLoggingFunctionsWrapper(int level, const char* tag, const char* file, int line, const char* func, const char* msg, va_list args) {
    switch(level) {
        case(LOGLEVEL_DEBUG):
            if (dbg_flag >= 1) {
                _log(level, tag, file, line, func, msg, args);
            }
            break;
        case(LOGLEVEL_DEBUG_VERBOSE):
            if (dbg_flag >= 2) {
                _log(LOGLEVEL_DEBUG, tag, file, line, func, msg, args);
            }
            break;
        case(LOGLEVEL_INFO):
        case(LOGLEVEL_WARNING):
        case(LOGLEVEL_ERROR):
            _log(level, tag, file, line, func, msg, args);
            break;
        case(LOGLEVEL_CRITICAL):
            _log(level, tag, file, line, func, msg, args);
#ifdef WIN32
            /* If not MA */
#ifndef MA
            WinSetError();
#endif
#endif
            exit(1);
            break;
        default:
            break;
    }
}
