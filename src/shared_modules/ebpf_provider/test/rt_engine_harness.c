/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Minimal consumer of rt_engine (#37396 validation build). Deliberately
 * tiny — this is the proof that a consumer needs nothing beyond rt_open/
 * rt_poll/rt_close plus its own interpretation of struct rt_file_event.
 *
 * Usage: rt_engine_harness <label> <open|attr|unlink|rename|all>[,...]
 *   e.g. rt_engine_harness A open,unlink
 *        rt_engine_harness B attr,rename
 *   Run two instances with disjoint filters concurrently to demonstrate
 *   #37396's extensibility/decoupling requirement: two independent
 *   consumers, distinct filters, one not stalling the other.
 */

#include "rt_engine.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

static unsigned int parse_mask(const char* spec)
{
    unsigned int mask = 0;
    char buf[256];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char* tok = strtok(buf, ",");
    while (tok)
    {
        if (strcmp(tok, "open") == 0)
            mask |= RT_FILE_OPEN_BIT;
        else if (strcmp(tok, "attr") == 0)
            mask |= RT_FILE_ATTR_BIT;
        else if (strcmp(tok, "unlink") == 0)
            mask |= RT_FILE_UNLINK_BIT;
        else if (strcmp(tok, "rename") == 0)
            mask |= RT_FILE_RENAME_BIT;
        else if (strcmp(tok, "all") == 0)
            mask |= RT_FILE_ALL_BITS;
        tok = strtok(NULL, ",");
    }
    return mask;
}

static const char* type_name(unsigned short t)
{
    switch (t)
    {
        case RT_EV_FILE_OPEN:
            return "OPEN";
        case RT_EV_FILE_ATTR:
            return "ATTR";
        case RT_EV_FILE_UNLINK:
            return "UNLINK";
        case RT_EV_FILE_RENAME:
            return "RENAME";
        default:
            return "?";
    }
}

struct sink_ctx
{
    const char* label;
    unsigned long count;
};

static void on_event(const struct rt_file_event* ev, void* user)
{
    struct sink_ctx* ctx = (struct sink_ctx*)user;
    ctx->count++;
    fprintf(stdout,
            "[%s] #%lu abi=%u type=%s pid=%u ppid=%u cgroup_id=%llu mnt_ns=%u dropped=%u "
            "flags=0x%x comm=%s path=%s cwd=%s parent_comm=%s parent_cwd=%s\n",
            ctx->label, ctx->count, ev->abi_major, type_name(ev->event_type), ev->pid, ev->ppid,
            (unsigned long long)ev->cgroup_id, ev->mnt_ns, ev->dropped, ev->flags, ev->comm, ev->filename,
            ev->cwd, ev->parent_comm, ev->parent_cwd);
    fflush(stdout);
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <label> <open|attr|unlink|rename|all>[,...]\n", argv[0]);
        return 2;
    }

    struct sink_ctx ctx = {.label = argv[1], .count = 0};
    struct rt_filter filter = {.type_mask = parse_mask(argv[2])};

    if (filter.type_mask == 0)
    {
        fprintf(stderr, "[%s] no recognized event classes in '%s'\n", ctx.label, argv[2]);
        return 2;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    fprintf(stderr, "[%s] opening engine with type_mask=0x%x\n", ctx.label, filter.type_mask);
    rt_handle_t h = rt_open(&filter);
    if (!h)
    {
        fprintf(stderr, "[%s] rt_open failed\n", ctx.label);
        return 1;
    }
    fprintf(stderr, "[%s] engine open, polling...\n", ctx.label);

    while (!g_stop)
    {
        int ret = rt_poll(h, on_event, &ctx, 500);
        if (ret < 0)
        {
            fprintf(stderr, "[%s] rt_poll error: %d\n", ctx.label, ret);
            break;
        }
    }

    fprintf(stderr, "[%s] shutting down, total events=%lu\n", ctx.label, ctx.count);
    rt_close(h);
    return 0;
}
