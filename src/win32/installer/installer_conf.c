/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Windows installer configuration. Ported from the former InstallerScripts.vbs and RemoveAllScript.vbs, producing the same files. */

#define PCRE2_CODE_UNIT_WIDTH 8
#define PCRE2_STATIC

/* PROC_THREAD_ATTRIBUTE_HANDLE_LIST */
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <pcre2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "installer_conf.h"

#define CRLF "\r\n"

/* (*LF): "." must match "\r" as it did in VBScript. */
#define ENDPOINT_RE "(*LF)\\s+<(server|manager)>(.|\\n)+?</\\1>"
#define COMMENT_RE "(*LF)<!--[\\s\\S]*?-->"
#define VM_TAG_RE "(*LF)<verification_mode(\\s*/)?>"
#define VM_SELF_CLOSING_RE "(*LF)<verification_mode\\s*/>"
#define VM_PAIR_RE "(*LF)<verification_mode>.*</verification_mode>"
#define PROFILE_ANCHOR_RE "(*LF)(</server>|</manager>)"

#define LOCAL_OPTIONS_HEADER                                    \
    "# local_internal_options.conf" CRLF                        \
    "#" CRLF                                                    \
    "# This file should be handled with care. It contains" CRLF \
    "# run time modifications that can affect the use" CRLF     \
    "# of OSSEC. Only change it if you know what you" CRLF      \
    "# are doing. Look first at ossec.conf" CRLF                \
    "# for most of the things you want to change." CRLF         \
    "#" CRLF                                                    \
    "# This file will not be overwritten during upgrades" CRLF  \
    "# but will be removed when the agent is un-installed."

typedef struct {
    char *data;
    size_t len;
    size_t size;
    int failed;
} buffer_t;

static void append_n(buffer_t *b, const char *s, size_t n)
{
    char *p;

    if (b->failed) {
        return;
    }
    if (!b->data || b->len + n + 1 > b->size) {
        size_t size = 2 * (b->len + n + 1);

        if (!(p = realloc(b->data, size))) {
            b->failed = 1;
            return;
        }
        b->data = p;
        b->size = size;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void append(buffer_t *b, const char *s)
{
    append_n(b, s, strlen(s));
}

static char *finish(buffer_t *b)
{
    append_n(b, "", 0);
    if (b->failed) {
        free(b->data);
        return NULL;
    }
    return b->data;
}

static char *concat(const char *first, ...)
{
    buffer_t b = {0};
    const char *s;
    va_list ap;

    va_start(ap, first);
    for (s = first; s; s = va_arg(ap, const char *)) {
        append(&b, s);
    }
    va_end(ap);
    return finish(&b);
}

wchar_t *installer_wconcat(const wchar_t *first, ...)
{
    const wchar_t *s;
    size_t n = 0;
    wchar_t *out;
    va_list ap;

    va_start(ap, first);
    for (s = first; s; s = va_arg(ap, const wchar_t *)) {
        n += wcslen(s);
    }
    va_end(ap);

    if (!(out = malloc((n + 1) * sizeof(*out)))) {
        return NULL;
    }
    *out = L'\0';

    va_start(ap, first);
    for (s = first; s; s = va_arg(ap, const wchar_t *)) {
        wcscat(out, s);
    }
    va_end(ap);
    return out;
}

/* Replaces the old text and returns -1 if the new one could not be built. */
static int set(char **text, char *value)
{
    free(*text);
    *text = value;
    return value ? 0 : -1;
}

static char *replace_all(const char *s, const char *from, const char *to)
{
    buffer_t b = {0};
    size_t n = strlen(from);
    const char *p;

    while ((p = strstr(s, from))) {
        append_n(&b, s, p - s);
        append(&b, to);
        s = p + n;
    }
    append(&b, s);
    return finish(&b);
}

static pcre2_code *compile(const char *pattern)
{
    PCRE2_SIZE erroff;
    int err;

    return pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, 0, &err, &erroff, NULL);
}

/* Returns 1 if pattern matches s, 0 if not, -1 on failure. */
static int regex_test(const char *s, const char *pattern)
{
    pcre2_code *re = compile(pattern);
    pcre2_match_data *md;
    int rc;

    if (!re) {
        return -1;
    }
    if (!(md = pcre2_match_data_create_from_pattern(re, NULL))) {
        pcre2_code_free(re);
        return -1;
    }
    rc = pcre2_match(re, (PCRE2_SPTR)s, strlen(s), 0, 0, md, NULL);
    pcre2_match_data_free(md);
    pcre2_code_free(re);
    return rc >= 0 ? 1 : rc == PCRE2_ERROR_NOMATCH ? 0 : -1;
}

/* The replacement is literal ("$" is not a group reference); keep_match puts the match back before it. */
static char *regex_replace_ex(const char *s, const char *pattern, const char *replacement, int global, int keep_match)
{
    pcre2_code *re;
    pcre2_match_data *md;
    PCRE2_SIZE *ov;
    buffer_t b = {0};
    size_t len = strlen(s);
    size_t start = 0;
    int rc;

    if (!(re = compile(pattern))) {
        return NULL;
    }
    if (!(md = pcre2_match_data_create_from_pattern(re, NULL))) {
        pcre2_code_free(re);
        return NULL;
    }

    for (;;) {
        if ((rc = pcre2_match(re, (PCRE2_SPTR)s, len, start, 0, md, NULL)) < 0) {
            b.failed |= rc != PCRE2_ERROR_NOMATCH;
            break;
        }
        ov = pcre2_get_ovector_pointer(md);
        append_n(&b, s + start, (keep_match ? ov[1] : ov[0]) - start);
        append(&b, replacement);
        start = ov[1];
        if (!global || ov[0] == ov[1]) {
            break;
        }
    }
    append(&b, s + start);

    pcre2_match_data_free(md);
    pcre2_code_free(re);
    return finish(&b);
}

static char *regex_replace(const char *s, const char *pattern, const char *replacement, int global)
{
    return regex_replace_ex(s, pattern, replacement, global, 0);
}

/* Every <tag>...</tag> on a line gets value, as RegExpReplaceTag() did. */
static int replace_tag(char **text, const char *tag, const char *value)
{
    char *pattern = concat("(*LF)<", tag, ">.*</", tag, ">", NULL);
    char *line = concat("<", tag, ">", value, "</", tag, ">", NULL);
    int rc = -1;

    if (pattern && line) {
        rc = set(text, regex_replace(*text, pattern, line, 1));
    }
    free(line);
    free(pattern);
    return rc;
}

static char *xml_escape(const char *s)
{
    buffer_t b = {0};

    for (; *s; s++) {
        append(&b, *s == '&' ? "&amp;" : *s == '<' ? "&lt;" : *s == '>' ? "&gt;" : (char[]){*s, '\0'});
    }
    return finish(&b);
}

static void log_msg(installer_log_fn log, void *ctx, const char *first, ...)
{
    buffer_t b = {0};
    const char *s;
    va_list ap;
    char *msg;

    va_start(ap, first);
    for (s = first; s; s = va_arg(ap, const char *)) {
        append(&b, s);
    }
    va_end(ap);
    if ((msg = finish(&b))) {
        log(ctx, msg);
        free(msg);
    }
}

/* Splits text at every CRLF, like VBScript Split(text, vbCrLf). The pieces point into text, which is modified. */
static char **split_lines(char *text, size_t *count)
{
    char **lines;
    size_t n = 1;
    char *p;

    for (p = text; (p = strstr(p, CRLF)); p += 2) {
        n++;
    }
    if (!(lines = malloc(n * sizeof(*lines)))) {
        return NULL;
    }
    lines[0] = text;
    for (n = 1, p = text; (p = strstr(p, CRLF)); p += 2) {
        *p = '\0';
        lines[n++] = p + 2;
    }
    *count = n;
    return lines;
}

/* VBScript Trim() removes spaces only. */
static int trimmed_equals(const char *line, const char *value)
{
    size_t n = strlen(value);

    while (*line == ' ') {
        line++;
    }
    if (strncmp(line, value, n)) {
        return 0;
    }
    for (line += n; *line == ' '; line++)
        ;
    return *line == '\0';
}

/* Writes mode into an existing <verification_mode>, skipping commented-out lines. */
static int pin_existing_mode(char **text, const char *mode, int *done)
{
    char *copy = _strdup(*text);
    char **lines = NULL;
    buffer_t b = {0};
    size_t n = 0;
    size_t i;
    int in_comment = 0;
    int rc = -1;

    *done = 0;
    if (!copy || !(lines = split_lines(copy, &n))) {
        goto end;
    }
    for (i = 0; i < n; i++) {
        char *line = lines[i];
        char *changed = NULL;

        if (in_comment) {
            if (strstr(line, "-->")) {
                in_comment = 0;
            }
        } else if (strstr(line, "<!--") && strstr(line, "-->")) {
            /* A one-line comment is left alone. */
        } else if (strstr(line, "<!--")) {
            in_comment = 1;
        } else if (!*done && strstr(line, "<verification_mode>") && strstr(line, "</verification_mode>")) {
            char *pair = concat("<verification_mode>", mode, "</verification_mode>", NULL);

            changed = pair ? regex_replace(line, VM_PAIR_RE, pair, 0) : NULL;
            free(pair);
            if (!changed) {
                goto end;
            }
            *done = 1;
        } else if (!*done && regex_test(line, VM_SELF_CLOSING_RE) == 1) {
            char *pair = concat("<verification_mode>", mode, "</verification_mode>", NULL);

            changed = pair ? regex_replace(line, VM_SELF_CLOSING_RE, pair, 0) : NULL;
            free(pair);
            if (!changed) {
                goto end;
            }
            *done = 1;
        }
        if (i > 0) {
            append(&b, CRLF);
        }
        append(&b, changed ? changed : line);
        free(changed);
    }
    rc = set(text, finish(&b));
    b.data = NULL;

end:
    free(b.data);
    free(lines);
    free(copy);
    return rc;
}

/* Inserts <verification_mode> after the first live "<ssl>" line. */
static int pin_mode_in_ssl(char **text, const char *mode, int *done)
{
    char *copy = _strdup(*text);
    char **lines = NULL;
    buffer_t b = {0};
    size_t n = 0;
    size_t i;
    int in_comment = 0;
    int rc = -1;

    *done = 0;
    if (!copy || !(lines = split_lines(copy, &n))) {
        goto end;
    }
    for (i = 0; i < n; i++) {
        if (in_comment) {
            if (strstr(lines[i], "-->")) {
                in_comment = 0;
            }
        } else if (strstr(lines[i], "<!--") && !strstr(lines[i], "-->")) {
            in_comment = 1;
        }
        if (i > 0) {
            append(&b, CRLF);
        }
        append(&b, lines[i]);
        if (!*done && !in_comment && trimmed_equals(lines[i], "<ssl>")) {
            append(&b, CRLF "      <verification_mode>");
            append(&b, mode);
            append(&b, "</verification_mode>");
            *done = 1;
        }
    }
    rc = set(text, finish(&b));
    b.data = NULL;

end:
    free(b.data);
    free(lines);
    free(copy);
    return rc;
}

static int apply_verification_mode(char **text, const char *mode, installer_log_fn log, void *ctx)
{
    char *live;
    int has_tag;
    int done = 0;

    if (strcmp(mode, "full") && strcmp(mode, "certificate") && strcmp(mode, "system") && strcmp(mode, "none")) {
        log_msg(log, ctx, "Invalid WAZUH_SSL_VERIFICATION '", mode,
                "': must be exactly one of full, certificate, system, none. Leaving <verification_mode> unset.", NULL);
        return 0;
    }
    if (!(live = regex_replace(*text, COMMENT_RE, "", 1))) {
        return -1;
    }
    has_tag = regex_test(live, VM_TAG_RE);

    if (has_tag < 0) {
        free(live);
        return -1;
    }
    if (has_tag) {
        free(live);
        if (pin_existing_mode(text, mode, &done)) {
            return -1;
        }
        if (!done) {
            log_msg(log, ctx,
                    "Could not pin WAZUH_SSL_VERIFICATION into <ssl><verification_mode>: expected the tag alone on its own line.",
                    NULL);
        }
        return 0;
    }
    if (strstr(live, "<ssl>")) {
        free(live);
        if (pin_mode_in_ssl(text, mode, &done)) {
            return -1;
        }
        if (!done) {
            log_msg(log, ctx,
                    "Could not pin WAZUH_SSL_VERIFICATION into an existing <ssl> block: expected the opening tag alone on its own line.",
                    NULL);
        }
        return 0;
    }
    free(live);
    {
        char *block = concat("    <ssl>" CRLF "      <verification_mode>", mode, "</verification_mode>" CRLF "    </ssl>" CRLF
                             "  </agent>" CRLF, NULL);
        int rc = block ? set(text, replace_all(*text, "  </agent>", block)) : -1;

        free(block);
        return rc;
    }
}

static int apply_enrollment(char **text, char *const value[CAD_FIELDS])
{
    static const struct {
        int field;
        const char *tag;
    } options[] = {
        {CAD_AGENT_NAME, "agent_name"},
        {CAD_AGENT_GROUP, "groups"},
        {CAD_ENROLLMENT_DELAY, "delay_after_enrollment"},
    };
    size_t i;

    if (!*value[CAD_AGENT_NAME] && !*value[CAD_AGENT_GROUP] && !*value[CAD_ENROLLMENT_DELAY]) {
        return 0;
    }
    if (!strstr(*text, "<enrollment>") &&
        set(text, replace_all(*text, "  </agent>",
                              "    <enrollment>" CRLF "      <enabled>yes</enabled>" CRLF "    </enrollment>" CRLF
                              "  </agent>" CRLF))) {
        return -1;
    }
    for (i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        char *line;
        int rc;

        if (!*value[options[i].field]) {
            continue;
        }
        if (!(line = concat("      <", options[i].tag, ">", value[options[i].field], "</", options[i].tag,
                            ">" CRLF "    </enrollment>", NULL))) {
            return -1;
        }
        rc = set(text, replace_all(*text, "    </enrollment>", line));
        free(line);
        if (rc) {
            return -1;
        }
    }
    return 0;
}

char *installer_apply_deployment(const char *conf, char *const value[CAD_FIELDS], const char *adr, installer_log_fn log,
                                 void *ctx)
{
    char *text = _strdup(conf);
    char *block = NULL;

    if (!text) {
        return NULL;
    }

    if (adr && *adr) {
        /* A 4.x file kept on upgrade is <client><server>, and the 5.x parser only reads it there as <server>. */
        const char *inner = strstr(text, "<agent>") ? "manager" : "server";
        char *escaped = xml_escape(adr);

        block = escaped ? concat(CRLF "    <", inner, ">" CRLF "      <endpoint>", escaped, "</endpoint>" CRLF "    </", inner,
                                 ">", NULL)
                        : NULL;
        free(escaped);
        if (!block || set(&text, regex_replace(text, ENDPOINT_RE, block, 0))) {
            goto fail;
        }
        free(block);
        block = NULL;
    }

    if (*value[CAD_KEEP_ALIVE]) {
        if (strstr(text, "<notify_time>")) {
            if (replace_tag(&text, "notify_time", value[CAD_KEEP_ALIVE])) {
                goto fail;
            }
        } else if (!(block = concat("    <notify_time>", value[CAD_KEEP_ALIVE], "</notify_time>" CRLF "  </agent>", NULL)) ||
                   set(&text, replace_all(text, "  </agent>", block))) {
            goto fail;
        }
        free(block);
        block = NULL;
    }

    if (*value[CAD_TIME_RECONNECT] && replace_tag(&text, "time-reconnect", value[CAD_TIME_RECONNECT])) {
        goto fail;
    }
    if (apply_enrollment(&text, value)) {
        goto fail;
    }
    if (*value[CAD_SSL_VERIFICATION] && apply_verification_mode(&text, value[CAD_SSL_VERIFICATION], log, ctx)) {
        goto fail;
    }
    return text;

fail:
    free(block);
    free(text);
    return NULL;
}

char *installer_apply_templates(const char *conf, const char *profile)
{
    char *text;
    char *line;

    if (!profile) {
        return _strdup(conf);
    }
    if (!(line = concat(CRLF "    ", profile, NULL))) {
        return NULL;
    }
    text = regex_replace_ex(conf, PROFILE_ANCHOR_RE, line, 0, 1);
    free(line);
    return text;
}

wchar_t *installer_cad_field(const wchar_t *cad, const wchar_t *sep, int index)
{
    const wchar_t *start = cad;
    const wchar_t *end;
    wchar_t *out;
    wchar_t *o;

    for (; index > 0; index--) {
        if (!sep || !(start = wcsstr(start, sep))) {
            return NULL;
        }
        start += wcslen(sep);
    }
    if (!sep || !(end = wcsstr(start, sep))) {
        end = start + wcslen(start);
    }
    if (!(out = o = malloc((end - start + 1) * sizeof(*out)))) {
        return NULL;
    }
    for (; start < end; start++) {
        if (*start != L'"') {
            *o++ = *start;
        }
    }
    *o = L'\0';
    return out;
}

static char *to_ansi(const wchar_t *s)
{
    int n = WideCharToMultiByte(CP_ACP, 0, s, -1, NULL, 0, NULL, NULL);
    char *out = n > 0 ? malloc(n) : NULL;

    if (out && !WideCharToMultiByte(CP_ACP, 0, s, -1, out, n, NULL, NULL)) {
        free(out);
        out = NULL;
    }
    return out;
}

static int file_exists(const wchar_t *home, const wchar_t *name)
{
    wchar_t *path = installer_wconcat(home, name, NULL);
    DWORD attr = path ? GetFileAttributesW(path) : INVALID_FILE_ATTRIBUTES;

    free(path);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static char *read_file(const wchar_t *home, const wchar_t *name)
{
    wchar_t *path = installer_wconcat(home, name, NULL);
    char *data = NULL;
    FILE *fp;
    long size;

    if (path && (fp = _wfopen(path, L"rb"))) {
        if (!fseek(fp, 0, SEEK_END) && (size = ftell(fp)) >= 0 && !fseek(fp, 0, SEEK_SET) &&
            (data = malloc(size + 1))) {
            if (fread(data, 1, size, fp) == (size_t)size) {
                data[size] = '\0';
            } else {
                free(data);
                data = NULL;
            }
        }
        fclose(fp);
    }
    free(path);
    return data;
}

/* NULL if the file does not exist; *failed is set if it exists but cannot be read. */
static char *read_optional(const wchar_t *home, const wchar_t *name, int *failed)
{
    char *data;

    if (!file_exists(home, name)) {
        return NULL;
    }
    *failed |= !(data = read_file(home, name));
    return data;
}

/* mode "wb" replaces the file, "ab" appends to it. eol adds the CRLF of a VBScript WriteLine. */
static int write_file_ex(const wchar_t *home, const wchar_t *name, const wchar_t *mode, const char *text, int eol)
{
    wchar_t *path = installer_wconcat(home, name, NULL);
    int rc = -1;
    FILE *fp;

    if (path && (fp = _wfopen(path, mode))) {
        rc = (text && fputs(text, fp) < 0) || (eol && fputs(CRLF, fp) < 0) ? -1 : 0;
        if (fclose(fp)) {
            rc = -1;
        }
    }
    free(path);
    return rc;
}

static int write_file(const wchar_t *home, const wchar_t *name, const char *text)
{
    return write_file_ex(home, name, L"wb", text, text != NULL);
}

/* Appends a line to ossec.log with the agent's own yyyy/mm/dd hh:mm:ss timestamp. */
static void install_log(void *ctx, const char *message)
{
    char stamp[32];
    SYSTEMTIME t;
    char *line;

    GetLocalTime(&t);
    snprintf(stamp, sizeof(stamp), "%04u/%02u/%02u %02u:%02u:%02u ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
             t.wSecond);
    if ((line = concat(stamp, message, NULL))) {
        write_file_ex((const wchar_t *)ctx, L"ossec.log", L"ab", line, 1);
        free(line);
    }
}

long installer_run(const wchar_t *app, const wchar_t *args)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = (DWORD)-1;
    wchar_t *cmd = installer_wconcat(L"\"", app, L"\" ", args, NULL);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (cmd && CreateProcessW(app, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        if (!GetExitCodeProcess(pi.hProcess, &code)) {
            code = (DWORD)-1;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    free(cmd);
    return (long)code;
}

long installer_run_system(const wchar_t *exe, const wchar_t *args)
{
    wchar_t sysdir[MAX_PATH];
    wchar_t *app;
    long rc = -1;
    UINT n = GetSystemDirectoryW(sysdir, MAX_PATH);

    if (n && n < MAX_PATH && (app = installer_wconcat(sysdir, L"\\", exe, NULL))) {
        rc = installer_run(app, args);
        free(app);
    }
    return rc;
}

/* The decoder's standard output, or NULL. Its standard error goes to NUL, and it inherits no other handle. */
static char *exchange(const wchar_t *app, const wchar_t *args, const char *input, DWORD *code)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE in_read = NULL, in_write = NULL, out_read = NULL, out_write = NULL, err = INVALID_HANDLE_VALUE;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    wchar_t *cmd = installer_wconcat(L"\"", app, L"\" ", args, NULL);
    buffer_t b = {0};
    char *output = NULL;
    HANDLE inherited[3];
    char chunk[4096];
    SIZE_T size = 0;
    int started = 0;
    DWORD done;

    *code = 127;
    if (!cmd || !CreatePipe(&in_read, &in_write, &sa, 65536) || !CreatePipe(&out_read, &out_write, &sa, 65536) ||
        !SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0) || !SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0) ||
        (err = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
        goto end;
    }
    inherited[0] = in_read;
    inherited[1] = out_write;
    inherited[2] = err;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    if (!(attrs = malloc(size)) || !InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
        free(attrs);
        attrs = NULL;
        goto end;
    }
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), NULL, NULL)) {
        goto end;
    }
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = in_read;
    si.StartupInfo.hStdOutput = out_write;
    si.StartupInfo.hStdError = err;
    si.lpAttributeList = attrs;
    started = CreateProcessW(app, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                             &si.StartupInfo, &pi);
    if (!started) {
        goto end;
    }
    CloseHandle(in_read);
    CloseHandle(out_write);
    CloseHandle(err);
    in_read = out_write = NULL;
    err = INVALID_HANDLE_VALUE;

    WriteFile(in_write, input, (DWORD)strlen(input), &done, NULL);
    CloseHandle(in_write);
    in_write = NULL;
    while (ReadFile(out_read, chunk, sizeof(chunk), &done, NULL) && done) {
        append_n(&b, chunk, done);
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    if (!GetExitCodeProcess(pi.hProcess, code)) {
        *code = 127;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    output = finish(&b);
    b.data = NULL;

end:
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        free(attrs);
    }
    free(b.data);
    if (in_read) CloseHandle(in_read);
    if (in_write) CloseHandle(in_write);
    if (out_read) CloseHandle(out_read);
    if (out_write) CloseHandle(out_write);
    if (err != INVALID_HANDLE_VALUE) CloseHandle(err);
    free(cmd);
    return output;
}

int installer_decode_token(const wchar_t *home, const char *token, char **adr)
{
    wchar_t *exe = installer_wconcat(home, L"wazuh-agent.exe", NULL);
    char *output = NULL;
    DWORD code = 127;
    char *line;
    char *next;

    *adr = NULL;
    if (!exe) {
        return 127;
    }
    if (file_exists(home, L"wazuh-agent.exe")) {
        output = exchange(exe, L"--show-token", token, &code);
    }
    for (line = output; line; line = next) {
        if ((next = strchr(line, '\n'))) {
            *next++ = '\0';
        }
        /* The last "adr: " line wins, as in the script. */
        if (!strncmp(line, "adr: ", 5)) {
            char *value = _strdup(line + 5);

            if (value) {
                char *w = value;
                const char *r;

                for (r = value; *r; r++) {
                    if (*r != '\r') {
                        *w++ = *r;
                    }
                }
                *w = '\0';
                free(*adr);
                *adr = value;
            }
        }
    }
    free(output);
    free(exe);
    return (int)code;
}

static const char *const REMOVED_NAMES[] = {
    "WAZUH_MANAGER", "WAZUH_MANAGER_PORT", "WAZUH_MANAGER_ENDPOINT", "WAZUH_REGISTRATION_SERVER",
    "WAZUH_REGISTRATION_PORT", "WAZUH_REGISTRATION_PASSWORD", "WAZUH_REGISTRATION_CA", "WAZUH_REGISTRATION_CERTIFICATE",
    "WAZUH_REGISTRATION_KEY", "ADDRESS", "SERVER_PORT", "AUTHD_SERVER", "AUTHD_PORT", "PASSWORD", "CERTIFICATE", "PEM", "KEY"};
static const int REMOVED_FIELDS[] = {CAD_MANAGER,      CAD_MANAGER_PORT, CAD_MANAGER_ENDPOINT, CAD_REG_SERVER, CAD_REG_PORT,
                                     CAD_REG_PASSWORD, CAD_REG_CA,       CAD_REG_CERT,         CAD_REG_KEY,    CAD_ADDRESS,
                                     CAD_SERVER_PORT,  CAD_AUTHD_SERVER, CAD_AUTHD_PORT,       CAD_PASSWORD,   CAD_CERTIFICATE,
                                     CAD_PEM,          CAD_KEY};

static int store_token(const wchar_t *home, const char *token, const char *adr)
{
    wchar_t *path = installer_wconcat(L"\"", home, L"enrollment_token\" /inheritance:r /grant *S-1-5-18:F /grant *S-1-5-32-544:F /q",
                                      NULL);

    /* Created empty and locked down before the credential is written. */
    if (!path || write_file_ex(home, L"enrollment_token", L"wb", NULL, 0)) {
        free(path);
        return -1;
    }
    if (installer_run_system(L"icacls.exe", path) == -1) {
        free(path);
        return -1;
    }
    free(path);
    if (write_file_ex(home, L"enrollment_token", L"wb", token, 0)) {
        return -1;
    }
    log_msg(install_log, (void *)home, "Enrollment token stored; the manager was set to '", adr,
            "' and the trust anchor will be bootstrapped at the first agent start.", NULL);
    return 0;
}

static int write_deployment(const wchar_t *home, char *const value[CAD_FIELDS], const char *adr, int token_ok)
{
    char *conf = NULL;
    char *text = NULL;
    int rc = -1;

    if (!(conf = read_file(home, L"ossec.conf")) ||
        !(text = installer_apply_deployment(conf, value, adr, install_log, (void *)home)) ||
        write_file(home, L"ossec.conf", text)) {
        goto end;
    }
    rc = token_ok ? store_token(home, value[CAD_ENROLLMENT_TOKEN], adr) : 0;

end:
    free(text);
    free(conf);
    return rc;
}

static int write_local_options(const wchar_t *home)
{
    char *defaults;
    int failed = 0;
    int rc;

    if (file_exists(home, L"local_internal_options.conf")) {
        return 0;
    }
    defaults = read_optional(home, L"default-local_internal_options.conf", &failed);
    rc = failed ? -1 : write_file(home, L"local_internal_options.conf", defaults ? defaults : LOCAL_OPTIONS_HEADER);
    free(defaults);
    return rc;
}

static int write_templates(const wchar_t *home, const wchar_t *os)
{
    wchar_t *name = installer_wconcat(L"profile-", os, L".template", NULL);
    char *profile = NULL;
    char *conf = NULL;
    char *text = NULL;
    int failed = 0;
    int rc = -1;

    if (!name) {
        return -1;
    }
    profile = read_optional(home, name, &failed);
    if (!failed && (conf = read_file(home, L"ossec.conf")) && (text = installer_apply_templates(conf, profile))) {
        rc = write_file(home, L"ossec.conf", text);
    }
    free(text);
    free(conf);
    free(profile);
    free(name);
    return rc;
}

int installer_config(const wchar_t *cad)
{
    wchar_t *field[CAD_FIELDS] = {NULL};
    char *value[CAD_FIELDS] = {NULL};
    char *adr = NULL;
    const wchar_t *home;
    int refused = 0;
    int token_ok = 0;
    int rc = -1;
    size_t i;

    for (i = 0; i < CAD_FIELDS; i++) {
        if (!(field[i] = installer_cad_field(cad, L"/+/", (int)i)) || !(value[i] = to_ansi(field[i]))) {
            goto end;
        }
    }
    home = field[CAD_HOME_DIR];

    if (!file_exists(home, L"client.keys") && write_file(home, L"client.keys", NULL)) {
        goto end;
    }
    for (i = 0; i < sizeof(REMOVED_FIELDS) / sizeof(REMOVED_FIELDS[0]); i++) {
        if (*value[REMOVED_FIELDS[i]]) {
            log_msg(install_log, (void *)home, REMOVED_NAMES[i],
                    " is not supported in 5.0 and was ignored: registration is configured by WAZUH_ENROLLMENT_TOKEN alone.", NULL);
        }
    }
    if (*value[CAD_SSL_VERIFICATION_OLD]) {
        install_log((void *)home, "SSL_VERIFICATION is not supported in 5.0 and was ignored: renamed to "
                                  "WAZUH_SSL_VERIFICATION; the old name is not read.");
    }

    if (!*value[CAD_ENROLLMENT_TOKEN]) {
        install_log((void *)home, "No manager configured [INFO_NO_MANAGER]: enroll the agent with Manage > Enroll in the agent "
                                  "GUI or with wazuh-agent-auth.exe, or reinstall with WAZUH_ENROLLMENT_TOKEN.");
    } else {
        int status = installer_decode_token(home, value[CAD_ENROLLMENT_TOKEN], &adr);

        if (status == 2) {
            install_log((void *)home, "Deployment variables refused [ERR_BAD_TOKEN]: WAZUH_ENROLLMENT_TOKEN was refused by the "
                                      "token decoder; no manager was configured from it and no token was stored.");
            refused = 1;
        } else if (status != 0) {
            char code[16];

            snprintf(code, sizeof(code), "%d", status);
            log_msg(install_log, (void *)home,
                    "Deployment variables refused [ERR_NO_DECODER]: could not run wazuh-agent.exe --show-token (exit ", code,
                    "); the enrollment token was left unread and no token was stored.", NULL);
            refused = 1;
        } else if (!adr || !*adr) {
            install_log((void *)home, "Deployment variables refused [ERR_BAD_TOKEN]: WAZUH_ENROLLMENT_TOKEN carries no address; "
                                      "no token was stored.");
            refused = 1;
        } else {
            token_ok = 1;
        }
        if (refused) {
            free(adr);
            adr = NULL;
        }
    }

    if (!refused && file_exists(home, L"ossec.conf") && write_deployment(home, value, adr, token_ok)) {
        goto end;
    }
    /* A refused token must not cost the install its internal options. */
    if (file_exists(home, L"ossec.conf") && write_local_options(home)) {
        goto end;
    }
    rc = write_templates(home, field[CAD_OS_VERSION]);

end:
    for (i = 0; i < CAD_FIELDS; i++) {
        free(field[i]);
        free(value[i]);
    }
    free(adr);
    return rc;
}

static wchar_t *upper_copy(const wchar_t *s)
{
    size_t n = wcslen(s);
    wchar_t *copy = malloc((n + 1) * sizeof(*copy));

    if (copy) {
        wmemcpy(copy, s, n + 1);
        CharUpperBuffW(copy, (DWORD)n);
    }
    return copy;
}

const wchar_t *installer_pending_conflict(const wchar_t *entries, size_t len, const wchar_t *dir)
{
    const wchar_t *end = entries + len;
    const wchar_t *hit = NULL;
    const wchar_t *p;
    wchar_t *needle;

    if (!(needle = upper_copy(dir))) {
        return NULL;
    }
    for (p = entries; p < end && !hit; p += wcslen(p) + 1) {
        wchar_t *entry = upper_copy(p);

        if (entry && wcsstr(entry, needle)) {
            hit = p;
        }
        free(entry);
    }
    free(needle);
    return hit;
}

int installer_is_drive_root(const wchar_t *dir)
{
    size_t len = wcslen(dir);

    if (len && dir[len - 1] == L'\\') {
        len--;
    }
    return !wmemchr(dir, L'\\', len);
}

static const wchar_t *const SAVED_FILES[] = {L"ossec.conf", L"client.keys", L"local_internal_options.conf", L"installer.log"};
static const wchar_t *const KEPT_FILES[] = {L"ossec.conf.save", L"client.keys.save", L"local_internal_options.conf.save",
                                            L"installer.log.save"};
static const wchar_t *const KEPT_FOLDERS[] = {L"backup", L"upgrade"};

static int is_listed(const wchar_t *name, const wchar_t *const *list, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (!_wcsicmp(name, list[i])) {
            return 1;
        }
    }
    return 0;
}

static void delete_tree(const wchar_t *path);

/* Calls delete_tree() on every entry of dir not listed in kept_files or kept_folders. */
static void delete_children(const wchar_t *dir, const wchar_t *const *kept_files, size_t n_files,
                            const wchar_t *const *kept_folders, size_t n_folders)
{
    wchar_t *pattern = installer_wconcat(dir, L"\\*", NULL);
    WIN32_FIND_DATAW fd;
    HANDLE h;

    if (!pattern || (h = FindFirstFileW(pattern, &fd)) == INVALID_HANDLE_VALUE) {
        free(pattern);
        return;
    }
    do {
        int folder = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        wchar_t *path;

        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..") ||
            (folder ? is_listed(fd.cFileName, kept_folders, n_folders) : is_listed(fd.cFileName, kept_files, n_files))) {
            continue;
        }
        if ((path = installer_wconcat(dir, L"\\", fd.cFileName, NULL))) {
            delete_tree(path);
            free(path);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    free(pattern);
}

static void delete_tree(const wchar_t *path)
{
    DWORD attr = GetFileAttributesW(path);

    if (attr == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    SetFileAttributesW(path, attr & ~FILE_ATTRIBUTE_READONLY);
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        DeleteFileW(path);
        return;
    }
    if (!(attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
        delete_children(path, NULL, 0, NULL, 0);
    }
    RemoveDirectoryW(path);
}

int installer_remove_all(const wchar_t *home)
{
    size_t n = sizeof(SAVED_FILES) / sizeof(SAVED_FILES[0]);
    size_t len = wcslen(home);
    wchar_t *dir;
    DWORD attr;
    size_t i;
    int rc = 0;

    if (!len) {
        return 0;
    }
    if (!(dir = installer_wconcat(home, NULL))) {
        return -1;
    }
    if (dir[len - 1] == L'\\') {
        dir[len - 1] = L'\0';
    }

    for (i = 0; i < n && !rc; i++) {
        wchar_t *file = installer_wconcat(dir, L"\\", SAVED_FILES[i], NULL);
        wchar_t *save = installer_wconcat(dir, L"\\", KEPT_FILES[i], NULL);

        if (!file || !save) {
            rc = -1;
        } else if (GetFileAttributesW(file) != INVALID_FILE_ATTRIBUTES) {
            if (GetFileAttributesW(save) != INVALID_FILE_ATTRIBUTES && !DeleteFileW(save)) {
                rc = -1;
            } else if (!MoveFileW(file, save)) {
                rc = -1;
            }
        }
        free(save);
        free(file);
    }

    attr = GetFileAttributesW(dir);
    /* Never empty a drive root. */
    if (!rc && !installer_is_drive_root(dir) && attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        delete_children(dir, KEPT_FILES, n, KEPT_FOLDERS, sizeof(KEPT_FOLDERS) / sizeof(KEPT_FOLDERS[0]));
    }
    free(dir);
    return rc;
}

static void force_delete(const wchar_t *path)
{
    DWORD attr = GetFileAttributesW(path);

    if (attr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(path, attr & ~FILE_ATTRIBUTE_READONLY);
        DeleteFileW(path);
    }
}

void installer_remove_fleet_password(const wchar_t *home)
{
    wchar_t *pass = installer_wconcat(home, L"authd.pass", NULL);
    wchar_t *exe = installer_wconcat(home, L"wazuh-agent.exe", NULL);
    long rc = -1;

    if (!pass || !exe || GetFileAttributesW(pass) == INVALID_FILE_ATTRIBUTES) {
        goto end;
    }
    if (GetFileAttributesW(exe) != INVALID_FILE_ATTRIBUTES) {
        rc = installer_run(exe, L"--shred-enrollment-password");
    }
    if (rc != 0 && GetFileAttributesW(pass) != INVALID_FILE_ATTRIBUTES) {
        /* Fallback: a same-length rewrite with NUL bytes, then the delete that takes the credential off the endpoint. */
        WIN32_FILE_ATTRIBUTE_DATA info;
        FILE *fp;

        if (GetFileAttributesExW(pass, GetFileExInfoStandard, &info) && info.nFileSizeLow && (fp = _wfopen(pass, L"wb"))) {
            DWORD i;

            for (i = 0; i < info.nFileSizeLow; i++) {
                fputc(0, fp);
            }
            fclose(fp);
        }
        force_delete(pass);
    }

end:
    free(exe);
    free(pass);
}

void installer_cleanup_legacy_databases(const wchar_t *home)
{
    static const wchar_t *const files[] = {L"queue\\syscollector\\db\\local.db", L"queue\\fim\\db\\fim.db"};
    size_t i;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        wchar_t *path = installer_wconcat(home, files[i], NULL);

        if (path) {
            force_delete(path);
            free(path);
        }
    }
}
