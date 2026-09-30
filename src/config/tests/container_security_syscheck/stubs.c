/* Stubs for the <container_security><syscheck> contract test.
 *
 * Only what the parser reaches but does not need for its behaviour: the logging
 * (captured so cases can assert on it), and a handful of symbols syscheck-config.c
 * references from parts of the configuration this test never exercises. */

#include "shared.h"
#include "syscheck-config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define CAP_LINES 64
#define CAP_LEN   512

static char g_log[CAP_LINES][CAP_LEN];
static int g_lines = 0;
int g_error_count = 0;
int g_warn_count = 0;

static void capture(const char* level, const char* msg, va_list args)
{
    char body[CAP_LEN - 8];

    vsnprintf(body, sizeof(body), msg, args);

    if (g_lines < CAP_LINES)
    {
        snprintf(g_log[g_lines], CAP_LEN, "%s %s", level, body);
        g_lines++;
    }
}

void log_reset(void)
{
    g_lines = 0;
    g_error_count = 0;
    g_warn_count = 0;
}

int log_contains(const char* needle)
{
    for (int i = 0; i < g_lines; i++)
    {
        if (strstr(g_log[i], needle) != NULL)
        {
            return 1;
        }
    }

    return 0;
}

void log_dump(void)
{
    for (int i = 0; i < g_lines; i++)
    {
        printf("      | %s\n", g_log[i]);
    }
}

void _merror(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file;
    (void)line;
    (void)func;
    va_list args;
    va_start(args, msg);
    capture("ERROR", msg, args);
    va_end(args);
    g_error_count++;
}

void _mwarn(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file;
    (void)line;
    (void)func;
    va_list args;
    va_start(args, msg);
    capture("WARN", msg, args);
    va_end(args);
    g_warn_count++;
}

void _minfo(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file;
    (void)line;
    (void)func;
    va_list args;
    va_start(args, msg);
    capture("INFO", msg, args);
    va_end(args);
}

void _mdebug1(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file;
    (void)line;
    (void)func;
    va_list args;
    va_start(args, msg);
    capture("DEBUG", msg, args);
    va_end(args);
}

void _mdebug2(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file;
    (void)line;
    (void)func;
    va_list args;
    va_start(args, msg);
    capture("DEBUG2", msg, args);
    va_end(args);
}

void _mferror(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file;
    (void)line;
    (void)func;
    va_list args;
    va_start(args, msg);
    capture("ERROR", msg, args);
    va_end(args);
    g_error_count++;
}

void _merror_exit(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file;
    (void)line;
    (void)func;
    va_list args;
    va_start(args, msg);
    capture("FATAL", msg, args);
    va_end(args);
    exit(1);
}

/* <restrict> is stored as a compiled OSMatch. The parser only has to keep the
 * pattern alive and attached; matching happens at scan time, which this test does
 * not reach, so a real regex engine would only add link surface. */
int OSMatch_Compile(const char* pattern, OSMatch* reg, int flags)
{
    (void)flags;

    if (pattern == NULL || reg == NULL)
    {
        return 0;
    }

    memset(reg, 0, sizeof(*reg));
    os_strdup(pattern, reg->raw);
    return 1;
}

void OSMatch_FreePattern(OSMatch* reg)
{
    if (reg != NULL)
    {
        os_free(reg->raw);
    }
}

/* Reached only by <scan_day>/<scan_time>/<synchronization>, which this test does
 * not configure. */
char* OS_IsValidDay(const char* day_str)
{
    (void)day_str;
    return NULL;
}

char* OS_IsValidUniqueTime(const char* time)
{
    (void)time;
    return NULL;
}

int os_IsStrOnArray(const char* str, char** array)
{
    (void)str;
    (void)array;
    return 0;
}

void* OSHash_Free(OSHash* self)
{
    (void)self;
    return NULL;
}

int ReadConfig(int modules, const char* cfgfile, void* d1, void* d2)
{
    (void)modules;
    (void)cfgfile;
    (void)d1;
    (void)d2;
    return 0;
}

FILE* wfopen(const char* path, const char* mode)
{
    return fopen(path, mode);
}

void w_file_cloexec(FILE* fp)
{
    (void)fp;
}
