/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#include "shared.h"
#include "logcollector.h"
#include "os_net.h"
#include <poll.h>
#include <sys/socket.h>

#define HTTP_RECV_CHUNK   8192
#define HTTP_REQ_TEMPLATE "GET %s HTTP/1.1\r\n" \
                          "Host: localhost\r\n" \
                          "User-Agent: wazuh-logcollector\r\n" \
                          "Accept: */*\r\n" \
                          "Connection: keep-alive\r\n" \
                          "\r\n"

typedef enum {
    BODY_CHUNKED,
    BODY_LENGTH,
    BODY_UNTIL_CLOSE
} body_mode_t;

typedef struct {
    /* Raw bytes pending inspection (header parsing or chunk-size parsing). */
    char *header_buf;
    size_t header_len;
    size_t header_cap;

    /* Line accumulator: a partial trailing line carried across reads/chunks. */
    char *line_buf;
    size_t line_len;
    size_t line_cap;

    body_mode_t mode;
    size_t bytes_remaining;   /* For BODY_CHUNKED (current chunk) and BODY_LENGTH (whole body). */
} http_parse_ctx_t;

/* ------------------------------------------------------------------------- */
/* Stop-aware helpers                                                        */
/* ------------------------------------------------------------------------- */

static void http_unix_sleep_interruptible(const logreader *lf, int seconds) {
    for (int s = 0; s < seconds && !lf->http_stop; s++) {
        sleep(1);
    }
}

/* Poll fd for input with stop-flag awareness. Returns:
 *   1 = data ready
 *   0 = stop requested
 *  -1 = error or remote closed
 */
static int http_unix_wait_readable(int fd, const logreader *lf) {
    while (!lf->http_stop) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
        int r = poll(&pfd, 1, 1000);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            mdebug1("http-unix '%s': poll failed: %s", lf->file, strerror(errno));
            return -1;
        }
        if (r == 0) {
            continue;  /* timeout — re-check stop flag */
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            return -1;
        }
        if (pfd.revents & POLLIN) {
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Buffer helpers                                                            */
/* ------------------------------------------------------------------------- */

static void http_buf_append(char **buf, size_t *len, size_t *cap, const char *src, size_t n) {
    if (*len + n + 1 > *cap) {
        size_t new_cap = (*cap == 0) ? 1024 : *cap;
        while (new_cap < *len + n + 1) {
            new_cap *= 2;
        }
        os_realloc(*buf, new_cap, *buf);
        *cap = new_cap;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    (*buf)[*len] = '\0';
}

static void http_ctx_reset(http_parse_ctx_t *ctx) {
    if (ctx->header_buf) {
        ctx->header_buf[0] = '\0';
    }
    ctx->header_len = 0;
    if (ctx->line_buf) {
        ctx->line_buf[0] = '\0';
    }
    ctx->line_len = 0;
    ctx->mode = BODY_UNTIL_CLOSE;
    ctx->bytes_remaining = 0;
}

static void http_ctx_free(http_parse_ctx_t *ctx) {
    os_free(ctx->header_buf);
    os_free(ctx->line_buf);
    memset(ctx, 0, sizeof(*ctx));
}

/* ------------------------------------------------------------------------- */
/* Connection setup                                                          */
/* ------------------------------------------------------------------------- */

static int http_unix_connect(const logreader *lf) {
    int fd = OS_ConnectUnixDomain(lf->file, SOCK_STREAM, OS_MAXSTR);
    if (fd < 0) {
        return -1;
    }
    return fd;
}

static int http_unix_send_request(int fd, const logreader *lf) {
    char req[OS_SIZE_1024];
    int req_len = snprintf(req, sizeof(req), HTTP_REQ_TEMPLATE, lf->http_endpoint);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        merror("http-unix '%s': request line too long for endpoint '%s'", lf->file, lf->http_endpoint);
        return -1;
    }

    ssize_t off = 0;
    while (off < req_len) {
        ssize_t n = send(fd, req + off, (size_t)(req_len - off), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            mdebug1("http-unix '%s': send failed: %s", lf->file, strerror(errno));
            return -1;
        }
        off += n;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Line emission                                                             */
/* ------------------------------------------------------------------------- */

/* Push a single accumulated line through the standard validation+queue path. */
static void http_unix_emit_line(logreader *lf, char *line, size_t len) {
    size_t msg_len = len;

    if (!w_logcollector_validate_text_line(line, &msg_len, "http-unix", lf->file)) {
        return;
    }

    mdebug2("Reading http-unix message: '%.*s'%s", sample_log_length, line,
            (int)msg_len > sample_log_length ? "..." : "");

    if (!check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, line)) {
        w_msg_hash_queues_push(line, lf->file, msg_len + 1, lf->log_target, LOCALFILE_MQ);
    }
}

/* Feed body bytes to the line splitter; emit complete lines, retain partial tail. */
static void http_unix_feed_body(logreader *lf, http_parse_ctx_t *ctx, const char *data, size_t n) {
    size_t start = 0;
    for (size_t i = 0; i < n; i++) {
        if (data[i] == '\n') {
            if (i > start) {
                http_buf_append(&ctx->line_buf, &ctx->line_len, &ctx->line_cap, data + start, i - start);
            }
            if (ctx->line_len > 0) {
                http_unix_emit_line(lf, ctx->line_buf, ctx->line_len);
                ctx->line_len = 0;
                if (ctx->line_buf) {
                    ctx->line_buf[0] = '\0';
                }
            }
            start = i + 1;
        }
    }
    if (start < n) {
        if (ctx->line_len + (n - start) >= OS_MAXSTR) {
            mwarn("http-unix '%s': line exceeds %d bytes; dropping accumulated content.", lf->file, OS_MAXSTR);
            ctx->line_len = 0;
            if (ctx->line_buf) {
                ctx->line_buf[0] = '\0';
            }
        } else {
            http_buf_append(&ctx->line_buf, &ctx->line_len, &ctx->line_cap, data + start, n - start);
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Header / status / chunk parsing                                           */
/* ------------------------------------------------------------------------- */

/* Returns 0 on parse-incomplete (need more data), 1 on success, -1 on error. */
static int http_unix_parse_headers(logreader *lf, http_parse_ctx_t *ctx) {
    char *end = strstr(ctx->header_buf, "\r\n\r\n");
    if (end == NULL) {
        return 0;
    }

    /* Status line: "HTTP/1.1 200 OK\r\n" */
    char *status_end = strstr(ctx->header_buf, "\r\n");
    if (status_end == NULL || status_end >= end) {
        return -1;
    }

    int status_code = 0;
    if (sscanf(ctx->header_buf, "HTTP/1.%*d %d", &status_code) != 1) {
        merror("http-unix '%s': malformed status line.", lf->file);
        return -1;
    }
    if (status_code < 200 || status_code >= 300) {
        merror("http-unix '%s': server returned HTTP %d.", lf->file, status_code);
        return -1;
    }

    /* Default: read body until close, no length known */
    ctx->mode = BODY_UNTIL_CLOSE;
    ctx->bytes_remaining = 0;

    /* Inspect headers: case-insensitive search for Transfer-Encoding and Content-Length */
    char *line = status_end + 2;
    while (line < end) {
        char *eol = strstr(line, "\r\n");
        if (eol == NULL || eol > end) {
            break;
        }
        size_t line_len = (size_t)(eol - line);

        if (line_len > 18 && strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            /* Look for "chunked" anywhere in the value */
            char *value = line + 18;
            while (value < eol && (*value == ' ' || *value == '\t')) {
                value++;
            }
            if ((size_t)(eol - value) >= 7 && strncasecmp(value, "chunked", 7) == 0) {
                ctx->mode = BODY_CHUNKED;
            }
        } else if (line_len > 15 && strncasecmp(line, "Content-Length:", 15) == 0 && ctx->mode != BODY_CHUNKED) {
            char *value = line + 15;
            while (value < eol && (*value == ' ' || *value == '\t')) {
                value++;
            }
            char tmp[32] = {0};
            size_t tl = (size_t)(eol - value);
            if (tl == 0 || tl >= sizeof(tmp)) {
                return -1;
            }
            memcpy(tmp, value, tl);
            char *endp;
            long long cl = strtoll(tmp, &endp, 10);
            if (*endp != '\0' || cl < 0) {
                return -1;
            }
            ctx->mode = BODY_LENGTH;
            ctx->bytes_remaining = (size_t)cl;
        }

        line = eol + 2;
    }

    /* Shift any post-header bytes already in header_buf to be re-fed as body. */
    size_t header_total = (size_t)(end - ctx->header_buf) + 4;  /* include \r\n\r\n */
    size_t leftover = ctx->header_len - header_total;
    if (leftover > 0) {
        memmove(ctx->header_buf, ctx->header_buf + header_total, leftover);
    }
    ctx->header_len = leftover;
    if (ctx->header_buf) {
        ctx->header_buf[ctx->header_len] = '\0';
    }
    return 1;
}

/* Process body bytes according to ctx->mode.
 * Returns 0 on success (more data may be needed), -1 on parse error or end-of-body. */
static int http_unix_consume_body_bytes(logreader *lf, http_parse_ctx_t *ctx, const char *data, size_t n) {
    if (ctx->mode == BODY_LENGTH) {
        size_t take = n < ctx->bytes_remaining ? n : ctx->bytes_remaining;
        http_unix_feed_body(lf, ctx, data, take);
        ctx->bytes_remaining -= take;
        if (ctx->bytes_remaining == 0) {
            /* Flush any trailing partial line as a final message. */
            if (ctx->line_len > 0) {
                http_unix_emit_line(lf, ctx->line_buf, ctx->line_len);
                ctx->line_len = 0;
            }
            return -1;  /* signal: connection should be closed and re-established */
        }
        return 0;
    }

    if (ctx->mode == BODY_UNTIL_CLOSE) {
        http_unix_feed_body(lf, ctx, data, n);
        return 0;
    }

    /* BODY_CHUNKED: append to header_buf as the chunk-size scratch area, then drain. */
    http_buf_append(&ctx->header_buf, &ctx->header_len, &ctx->header_cap, data, n);

    while (ctx->header_len > 0) {
        if (ctx->bytes_remaining == 0) {
            /* Need to read a chunk size line: "<hex>[;ext]\r\n" */
            char *eol = NULL;
            for (size_t k = 0; k + 1 < ctx->header_len; k++) {
                if (ctx->header_buf[k] == '\r' && ctx->header_buf[k + 1] == '\n') {
                    eol = ctx->header_buf + k;
                    break;
                }
            }
            if (eol == NULL) {
                return 0;
            }
            char size_line[64] = {0};
            size_t sl = (size_t)(eol - ctx->header_buf);
            if (sl >= sizeof(size_line)) {
                merror("http-unix '%s': chunk size line too long.", lf->file);
                return -1;
            }
            memcpy(size_line, ctx->header_buf, sl);
            char *endp;
            long long cs = strtoll(size_line, &endp, 16);
            if (cs < 0 || (*endp != '\0' && *endp != ';')) {
                merror("http-unix '%s': malformed chunk size '%s'.", lf->file, size_line);
                return -1;
            }
            size_t consumed = sl + 2;
            memmove(ctx->header_buf, ctx->header_buf + consumed, ctx->header_len - consumed);
            ctx->header_len -= consumed;
            ctx->header_buf[ctx->header_len] = '\0';

            if (cs == 0) {
                /* Last chunk — flush any partial line and signal EOF. */
                if (ctx->line_len > 0) {
                    http_unix_emit_line(lf, ctx->line_buf, ctx->line_len);
                    ctx->line_len = 0;
                }
                return -1;
            }
            ctx->bytes_remaining = (size_t)cs + 2;  /* +2 for trailing \r\n */
        }

        /* Drain available chunk bytes. The trailing 2 bytes belong to \r\n delimiter. */
        size_t avail = ctx->header_len;
        size_t want = ctx->bytes_remaining;
        size_t take = avail < want ? avail : want;

        /* Of `take` bytes, the first (want - 2) are payload, the last belong to the trailing \r\n. */
        size_t payload_remaining = ctx->bytes_remaining > 2 ? ctx->bytes_remaining - 2 : 0;
        size_t payload_take = take < payload_remaining ? take : payload_remaining;
        if (payload_take > 0) {
            http_unix_feed_body(lf, ctx, ctx->header_buf, payload_take);
        }

        memmove(ctx->header_buf, ctx->header_buf + take, ctx->header_len - take);
        ctx->header_len -= take;
        ctx->header_buf[ctx->header_len] = '\0';
        ctx->bytes_remaining -= take;

        if (ctx->bytes_remaining > 0) {
            return 0;  /* need more bytes to finish this chunk */
        }
        /* chunk fully consumed; loop back to read next chunk size */
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Per-connection consumer                                                   */
/* ------------------------------------------------------------------------- */

static void http_unix_consume(logreader *lf, int fd, http_parse_ctx_t *ctx) {
    char buf[HTTP_RECV_CHUNK];
    bool headers_parsed = false;

    while (!lf->http_stop) {
        int wr = http_unix_wait_readable(fd, lf);
        if (wr <= 0) {
            return;  /* stopped or socket-level error */
        }

        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            mdebug1("http-unix '%s': recv failed: %s", lf->file, strerror(errno));
            return;
        }
        if (n == 0) {
            mdebug1("http-unix '%s': peer closed connection.", lf->file);
            if (headers_parsed && ctx->mode == BODY_UNTIL_CLOSE && ctx->line_len > 0) {
                http_unix_emit_line(lf, ctx->line_buf, ctx->line_len);
                ctx->line_len = 0;
            }
            return;
        }

        if (!headers_parsed) {
            http_buf_append(&ctx->header_buf, &ctx->header_len, &ctx->header_cap, buf, (size_t)n);
            int hr = http_unix_parse_headers(lf, ctx);
            if (hr < 0) {
                return;
            }
            if (hr == 0) {
                continue;  /* need more bytes for headers */
            }
            headers_parsed = true;

            /* Feed any post-header bytes already in header_buf as body. */
            if (ctx->header_len > 0) {
                size_t carry = ctx->header_len;
                /* Copy into a temp buffer because consume_body may reuse header_buf for chunks. */
                char *tmp;
                os_malloc(carry, tmp);
                memcpy(tmp, ctx->header_buf, carry);
                ctx->header_len = 0;
                ctx->header_buf[0] = '\0';
                int br = http_unix_consume_body_bytes(lf, ctx, tmp, carry);
                os_free(tmp);
                if (br < 0) {
                    return;
                }
            }
            continue;
        }

        if (http_unix_consume_body_bytes(lf, ctx, buf, (size_t)n) < 0) {
            return;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Worker thread                                                             */
/* ------------------------------------------------------------------------- */

static void *http_unix_worker(void *arg) {
    logreader *lf = (logreader *)arg;
    http_parse_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    bool first_failure_logged = false;

    while (!lf->http_stop) {
        int fd = http_unix_connect(lf);
        if (fd < 0) {
            if (!first_failure_logged) {
                mwarn("http-unix '%s': unable to connect (%s); will keep retrying every %ds.",
                      lf->file, strerror(errno), lf->http_reconnect_interval);
                first_failure_logged = true;
            } else {
                mdebug2("http-unix '%s': connect failed: %s", lf->file, strerror(errno));
            }
            http_unix_sleep_interruptible(lf, lf->http_reconnect_interval);
            continue;
        }

        if (first_failure_logged) {
            minfo("http-unix '%s': connection established.", lf->file);
            first_failure_logged = false;
        } else {
            mdebug1("http-unix '%s': connected.", lf->file);
        }

        if (http_unix_send_request(fd, lf) == 0) {
            http_ctx_reset(&ctx);
            http_unix_consume(lf, fd, &ctx);
        }

        OS_CloseSocket(fd);

        if (!lf->http_stop) {
            http_unix_sleep_interruptible(lf, lf->http_reconnect_interval);
        }
    }

    http_ctx_free(&ctx);
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Public entry                                                              */
/* ------------------------------------------------------------------------- */

int w_logcollector_http_unix_open(logreader *lf) {
    if (lf == NULL || lf->file == NULL || lf->http_endpoint == NULL) {
        return -1;
    }
    if (lf->http_thread_started) {
        return 0;
    }

    lf->http_stop = 0;

    if (CreateThreadJoinable(&lf->http_thread, http_unix_worker, lf) != 0) {
        merror("http-unix '%s': failed to spawn worker thread.", lf->file);
        return -1;
    }

    lf->http_thread_started = 1;
    return 0;
}

#endif
