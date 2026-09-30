/* Minimal stand-ins for the agent runtime the parser logs and allocates
 * through, so the real parser can be driven from a test binary without
 * linking modulesd. Log lines are captured, not printed, so a case can
 * assert on what the operator would actually see. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CAP_MAX 64
#define CAP_LEN 512

char g_log[CAP_MAX][CAP_LEN];
int g_log_count = 0;
int g_error_count = 0;
int g_warn_count = 0;

static void capture(const char* level, const char* msg, va_list args)
{
    char body[CAP_LEN - 8]; /* room for the level prefix */
    vsnprintf(body, sizeof(body), msg, args);
    if (g_log_count < CAP_MAX)
    {
        snprintf(g_log[g_log_count], CAP_LEN, "%s %s", level, body);
        g_log_count++;
    }
}

void _merror(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file; (void)line; (void)func;
    va_list a; va_start(a, msg); capture("ERROR", msg, a); va_end(a);
    g_error_count++;
}

void _mwarn(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file; (void)line; (void)func;
    va_list a; va_start(a, msg); capture("WARN", msg, a); va_end(a);
    g_warn_count++;
}

void _minfo(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file; (void)line; (void)func;
    va_list a; va_start(a, msg); capture("INFO", msg, a); va_end(a);
}

void _mdebug1(const char* file, int line, const char* func, const char* msg, ...)
{ (void)file; (void)line; (void)func; (void)msg; }

void _mdebug2(const char* file, int line, const char* func, const char* msg, ...)
{ (void)file; (void)line; (void)func; (void)msg; }

void _merror_exit(const char* file, int line, const char* func, const char* msg, ...)
{
    (void)file; (void)line; (void)func;
    va_list a; va_start(a, msg); capture("FATAL", msg, a); va_end(a);
    exit(1);
}

void _mferror(const char* file, int line, const char* func, const char* msg, ...)
{ (void)file; (void)line; (void)func; (void)msg; }

void log_reset(void)
{
    g_log_count = 0;
    g_error_count = 0;
    g_warn_count = 0;
}

int log_contains(const char* needle)
{
    for (int i = 0; i < g_log_count; i++)
    {
        if (strstr(g_log[i], needle))
        {
            return 1;
        }
    }
    return 0;
}

void log_dump(void)
{
    for (int i = 0; i < g_log_count; i++)
    {
        printf("      | %s\n", g_log[i]);
    }
}

/* ---- symbols the parser links against, outside the unit under test ---- */

#include "wmodules.h"
#include "wm_container_instances.h"

/* Mirrors shared/src/string_op.c:733 exactly. Reimplemented rather than linked
 * because string_op.c drags in most of the shared library; the parser's own
 * true/false extension sits on top of this and IS under test. */
int w_parse_bool(const char* string)
{
    if (!string)
    {
        return -1;
    }
    return (strcmp(string, "yes") == 0) ? 1 : (strcmp(string, "no") == 0) ? 0 : -1;
}

/* Mirrors shared/src/string_op.c:738. Reimplemented for the same reason w_parse_bool
 * is: linking string_op.c drags in the shared library. */
long w_parse_time(const char* string)
{
    char* end;
    long seconds = strtol(string, &end, 10);

    if (seconds < 0)
    {
        return -1;
    }

    switch (*end)
    {
        case '\0':
        case 's': break;
        case 'w': seconds *= W_WEEK_SECONDS; break;
        case 'd': seconds *= W_DAY_SECONDS; break;
        case 'h': seconds *= W_HOUR_SECONDS; break;
        case 'm': seconds *= W_MINUTE_SECONDS; break;
        default: return -1;
    }

    return seconds >= 0 ? seconds : -1;
}

/* The parsers only store these pointers on the module; they never call through them. */
const wm_context WM_CONTAINER_INSTANCES_CONTEXT = {
    .name = "container-instances",
};

const wm_context WM_SYS_CONTEXT = {
    .name = "syscollector",
};

FILE* wfopen(const char* path, const char* mode)
{
    return fopen(path, mode);
}

void w_file_cloexec(FILE* fp)
{
    (void)fp;
}
