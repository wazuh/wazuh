/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Windows installer configuration. Ported from the former InstallerScripts.vbs and RemoveAllScript.vbs, producing the same files. */

#define PCRE2_CODE_UNIT_WIDTH 8

#include <windows.h>
#include <tlhelp32.h>
#include <pcre2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "installer_conf.h"

#define CRLF "\r\n"

/* (*LF): "." must match "\r" as it did in VBScript. */
#define SERVER_RE "(*LF)\\s+<server>(.|\\n)+?</server>"
#define PROTOCOL_RE "(*LF)<protocol>.*</protocol>"
#define NOTIFY_TIME_RE "(*LF)<notify_time>.*</notify_time>"
#define TIME_RECONNECT_RE "(*LF)<time-reconnect>.*</time-reconnect>"
#define SYSCHECK_RE "(*LF)  <syscheck>\\r\\n(.*\\r\\n)*  </syscheck>"
#define EVENTS_RE "(*LF)  <localfile>\\r\\n.*Application(.*\\r\\n)*.*Security(.*\\r\\n)*.*System.*\\r\\n.*\\r\\n  </localfile>"

#define LOCAL_OPTIONS_HEADER                                  \
    "# local_internal_options.conf" CRLF                      \
    "#" CRLF                                                  \
    "# This file should be handled with care. It contains" CRLF \
    "# run time modifications that can affect the use" CRLF   \
    "# of OSSEC. Only change it if you know what you" CRLF    \
    "# are doing. Look first at ossec.conf" CRLF              \
    "# for most of the things you want to change." CRLF       \
    "#" CRLF                                                  \
    "# This file will not be overwritten during upgrades" CRLF \
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
    if (b->len + n + 1 > b->size) {
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

/* The replacement is literal: unlike VBScript, "$" in a user value is not a group reference. */
static char *regex_replace(const char *s, const char *pattern, const char *replacement, int global)
{
    pcre2_code *re;
    pcre2_match_data *md;
    PCRE2_SIZE *ov;
    PCRE2_SIZE erroff;
    buffer_t b = {0};
    size_t len = strlen(s);
    size_t start = 0;
    int err;
    int rc;

    if (!(re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, 0, &err, &erroff, NULL))) {
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
        append_n(&b, s + start, ov[0] - start);
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

/* Splits s in place at every comma, like VBScript Split(). */
static char **split(char *s, size_t *count)
{
    char **items;
    size_t n = 1;
    char *p;

    for (p = s; *p; p++) {
        n += *p == ',';
    }
    if (!(items = malloc(n * sizeof(*items)))) {
        return NULL;
    }
    items[0] = s;
    for (n = 1, p = s; *p; p++) {
        if (*p == ',') {
            *p = '\0';
            items[n++] = p + 1;
        }
    }
    *count = n;
    return items;
}

static int seen_before(char *const *items, size_t i)
{
    size_t j;

    for (j = 0; j < i; j++) {
        if (!strcmp(items[j], items[i])) {
            return 1;
        }
    }
    return 0;
}

static size_t count_unique(char *const *items, size_t n)
{
    size_t i;
    size_t u = 0;

    for (i = 0; i < n; i++) {
        u += !seen_before(items, i);
    }
    return u;
}

/* Keeps the first occurrence of each item, in order. */
static size_t unique(char **items, size_t n)
{
    size_t i;
    size_t u = 0;

    for (i = 0; i < n; i++) {
        if (!seen_before(items, i)) {
            items[u++] = items[i];
        }
    }
    return u;
}

static char *server_block(char *const *ips, size_t n_ips, char *const *protocols, size_t n_protocols)
{
    buffer_t b = {0};
    size_t i;

    append(&b, CRLF);
    for (i = 0; i < n_ips; i++) {
        if (!*ips[i]) {
            continue;
        }
        append(&b, "    <server>" CRLF "      <address>");
        append(&b, ips[i]);
        append(&b, "</address>" CRLF "      <port>1514</port>" CRLF "      <protocol>");
        append(&b, i < n_protocols && *protocols[i] ? protocols[i] : "tcp");
        append(&b, "</protocol>" CRLF "    </server>");
        if (i + 1 < n_ips) {
            append(&b, CRLF);
        }
    }
    return finish(&b);
}

static int apply_client(char **text, char *const value[CAD_FIELDS])
{
    char *protocol = NULL;
    char *managers = NULL;
    char **protocols = NULL;
    char **ips = NULL;
    char *block = NULL;
    size_t n_protocols;
    size_t n_ips;
    int rc = -1;

    if (!(protocol = _strdup(value[CAD_PROTOCOL])) || !(protocols = split(CharLowerA(protocol), &n_protocols))) {
        goto end;
    }

    if (*value[CAD_MANAGER]) {
        size_t n_unique = count_unique(protocols, n_protocols);

        if (!(managers = _strdup(value[CAD_MANAGER])) || !(ips = split(managers, &n_ips))) {
            goto end;
        }
        if ((n_protocols >= n_ips && n_unique == 1) || !*value[CAD_PROTOCOL] ||
            (n_unique == 1 && !strcmp(protocols[0], "tcp"))) {
            n_ips = unique(ips, n_ips);
        }
        if (!(block = server_block(ips, n_ips, protocols, n_protocols)) ||
            set(text, regex_replace(*text, SERVER_RE, block, 0))) {
            goto end;
        }
    } else if (*value[CAD_PROTOCOL]) {
        if (!(block = concat("      <protocol>", protocols[0], "</protocol>", NULL)) ||
            set(text, regex_replace(*text, PROTOCOL_RE, block, 0))) {
            goto end;
        }
    }
    free(block);
    block = NULL;

    if (*value[CAD_MANAGER_PORT] && strstr(*text, "<port>")) {
        if (!(block = concat("<port>", value[CAD_MANAGER_PORT], "</port>", NULL)) ||
            set(text, replace_all(*text, "<port>1514</port>", block))) {
            goto end;
        }
        free(block);
        block = NULL;
    }

    if (*value[CAD_KEEP_ALIVE] && strstr(*text, "<notify_time>")) {
        if (!(block = concat("<notify_time>", value[CAD_KEEP_ALIVE], "</notify_time>", NULL)) ||
            set(text, regex_replace(*text, NOTIFY_TIME_RE, block, 1))) {
            goto end;
        }
        free(block);
        block = NULL;
    }

    if (*value[CAD_TIME_RECONNECT] && strstr(*text, "<time-reconnect>")) {
        if (!(block = concat("<time-reconnect>", value[CAD_TIME_RECONNECT], "</time-reconnect>", NULL)) ||
            set(text, regex_replace(*text, TIME_RECONNECT_RE, block, 1))) {
            goto end;
        }
    }
    rc = 0;

end:
    free(block);
    free(ips);
    free(managers);
    free(protocols);
    free(protocol);
    return rc;
}

static int apply_enrollment(char **text, char *const value[CAD_FIELDS])
{
    static const struct {
        int field;
        const char *tag;
    } options[] = {
        {CAD_REG_SERVER, "manager_address"},
        {CAD_REG_PORT, "port"},
        {CAD_REG_PASSWORD, "authorization_pass_path"},
        {CAD_REG_CA, "server_ca_path"},
        {CAD_REG_CERT, "agent_certificate_path"},
        {CAD_REG_KEY, "agent_key_path"},
        {CAD_AGENT_NAME, "agent_name"},
        {CAD_AGENT_GROUP, "groups"},
        {CAD_ENROLLMENT_DELAY, "delay_after_enrollment"},
    };
    size_t i;
    int any = 0;

    for (i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        any |= *value[options[i].field] != '\0';
    }
    if (!any) {
        return 0;
    }

    if (set(text, replace_all(*text, "  </client>",
                              "    <enrollment>" CRLF "      <enabled>yes</enabled>" CRLF "    </enrollment>" CRLF
                              "  </client>" CRLF))) {
        return -1;
    }

    for (i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        const char *v = options[i].field == CAD_REG_PASSWORD ? "authd.pass" : value[options[i].field];
        char *line;
        int rc;

        if (!*value[options[i].field]) {
            continue;
        }
        if (!(line = concat("      <", options[i].tag, ">", v, "</", options[i].tag, ">" CRLF "    </enrollment>", NULL))) {
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

char *installer_apply_deployment(const char *conf, char *const value[CAD_FIELDS])
{
    char *text = _strdup(conf);

    if (!text) {
        return NULL;
    }
    if ((*value[CAD_MANAGER] || *value[CAD_MANAGER_PORT] || *value[CAD_PROTOCOL] || *value[CAD_KEEP_ALIVE] ||
         *value[CAD_TIME_RECONNECT]) &&
        apply_client(&text, value)) {
        free(text);
        return NULL;
    }
    if (apply_enrollment(&text, value)) {
        free(text);
        return NULL;
    }
    return text;
}

char *installer_apply_templates(const char *conf, const char *profile, const char *syscheck, const char *events)
{
    char *text = _strdup(conf);
    const char *p;

    if (!text) {
        return NULL;
    }
    if (profile && (p = strstr(text, "</server>"))) {
        buffer_t b = {0};
        size_t at = p - text + strlen("</server>");

        append_n(&b, text, at);
        append(&b, CRLF "    ");
        append(&b, profile);
        append(&b, text + at);
        if (set(&text, finish(&b))) {
            return NULL;
        }
    }
    if (syscheck && set(&text, regex_replace(text, SYSCHECK_RE, syscheck, 0))) {
        return NULL;
    }
    if (events && set(&text, regex_replace(text, EVENTS_RE, events, 0))) {
        return NULL;
    }
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

/* Like the VBScript WriteLine: text followed by CRLF, or an empty file if text is NULL. */
static int write_file(const wchar_t *home, const wchar_t *name, const char *text)
{
    wchar_t *path = installer_wconcat(home, name, NULL);
    int rc = -1;
    FILE *fp;

    if (path && (fp = _wfopen(path, L"wb"))) {
        rc = text && (fputs(text, fp) < 0 || fputs(CRLF, fp) < 0) ? -1 : 0;
        if (fclose(fp)) {
            rc = -1;
        }
    }
    free(path);
    return rc;
}

static int write_deployment(const wchar_t *home, char *const value[CAD_FIELDS])
{
    char *conf;
    char *text = NULL;
    char *defaults = NULL;
    int failed = 0;
    int rc = -1;

    if (!(conf = read_file(home, L"ossec.conf")) || !(text = installer_apply_deployment(conf, value))) {
        goto end;
    }
    if (*value[CAD_REG_PASSWORD] && write_file(home, L"authd.pass", value[CAD_REG_PASSWORD])) {
        goto end;
    }
    if (write_file(home, L"ossec.conf", text)) {
        goto end;
    }
    if (!file_exists(home, L"local_internal_options.conf")) {
        defaults = read_optional(home, L"default-local_internal_options.conf", &failed);
        if (failed || write_file(home, L"local_internal_options.conf", defaults ? defaults : LOCAL_OPTIONS_HEADER)) {
            goto end;
        }
    }
    rc = 0;

end:
    free(defaults);
    free(text);
    free(conf);
    return rc;
}

static int write_templates(const wchar_t *home, const wchar_t *os)
{
    wchar_t *names[3] = {
        installer_wconcat(L"profile-", os, L".template", NULL),
        installer_wconcat(L"syscheck-", os, L".template", NULL),
        installer_wconcat(L"localfile-events-", os, L".template", NULL),
    };
    char *content[3] = {NULL, NULL, NULL};
    char *conf = NULL;
    char *text = NULL;
    int failed = 0;
    int rc = -1;
    int i;

    for (i = 0; i < 3; i++) {
        if (!names[i]) {
            goto end;
        }
        content[i] = read_optional(home, names[i], &failed);
    }
    if (failed || !(conf = read_file(home, L"ossec.conf")) ||
        !(text = installer_apply_templates(conf, content[0], content[1], content[2]))) {
        goto end;
    }
    rc = write_file(home, L"ossec.conf", text);

end:
    for (i = 0; i < 3; i++) {
        free(names[i]);
        free(content[i]);
    }
    free(text);
    free(conf);
    return rc;
}

int installer_config(const wchar_t *cad)
{
    wchar_t *field[CAD_FIELDS] = {NULL};
    char *value[CAD_FIELDS] = {NULL};
    const wchar_t *home;
    int rc = -1;
    int i;

    for (i = 0; i < CAD_FIELDS; i++) {
        if (!(field[i] = installer_cad_field(cad, L"/+/", i)) || !(value[i] = to_ansi(field[i]))) {
            goto end;
        }
    }
    home = field[CAD_HOME_DIR];

    if (!file_exists(home, L"client.keys") && write_file(home, L"client.keys", NULL)) {
        goto end;
    }
    if (file_exists(home, L"ossec.conf") && write_deployment(home, value)) {
        goto end;
    }
    rc = write_templates(home, field[CAD_OS_VERSION]);

end:
    for (i = 0; i < CAD_FIELDS; i++) {
        free(field[i]);
        free(value[i]);
    }
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

int installer_wait_exit(const wchar_t *name, unsigned long timeout_ms)
{
    DWORD deadline = GetTickCount() + timeout_ms;
    DWORD self = GetCurrentProcessId();
    PROCESSENTRY32W pe;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    int running = 0;

    if (snap == INVALID_HANDLE_VALUE) {
        return -1;
    }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            DWORD left = deadline - GetTickCount();
            HANDLE p;

            if (pe.th32ProcessID == self || _wcsicmp(pe.szExeFile, name)) {
                continue;
            }
            if (!(p = OpenProcess(SYNCHRONIZE, FALSE, pe.th32ProcessID))) {
                running += GetLastError() != ERROR_INVALID_PARAMETER;
                continue;
            }
            if (WaitForSingleObject(p, left > timeout_ms ? 0 : left) != WAIT_OBJECT_0) {
                running++;
            }
            CloseHandle(p);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return running;
}
