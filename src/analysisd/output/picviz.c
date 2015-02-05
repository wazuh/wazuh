/* Copyright (C) 2009 Sebastien Tricaud
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef PICVIZ_OUTPUT_ENABLED

#include "picviz.h"

#include "shared.h"

static FILE *picviz_fp;

static const char *(ossec2picviz[]) = {"blue", "blue", "blue", "blue",
                                 "green", "green", "green", "green",
                                 "orange", "orange", "orange", "orange",
                                 "red", "red", "red", "red", "red"
                                };


void OS_PicvizOpen(const char *socket)
{
    picviz_fp = fopen(socket, "a");
    if (!picviz_fp) {
        merror("%s: Unable to open picviz socket file '%s'.",
               ARGV0, socket);
    }
}

void OS_PicvizLog(const Eventinfo *lf)
{
    if (!picviz_fp) {
        return;
    }

    const char *color = (lf->generated_rule->level > 15) ? "red" : ossec2picviz[lf->generated_rule->level];
    const char *hostname = lf->hostname ? lf->hostname : "";
    const char *location = lf->location ? lf->location : "";
    const char *srcip = lf->srcip ? lf->srcip : "";
    const char *dstip = lf->dstip ? lf->dstip : "";
    const char *srcuser = lf->srcuser ? lf->srcuser : "";
    const char *dstuser = lf->dstuser ? lf->dstuser : "";
    const char *prgname = lf->program_name ? lf->program_name : "";
    const char *comment = lf->generated_rule->comment ? lf->generated_rule->comment : "";

    fprintf(picviz_fp,
            "time=\"%s\", host=\"%s\", file=\"%s\", sip=\"%s\", dip=\"%s\""
            ", srcuser=\"%s\", dstuser=\"%s\", prgnme=\"%s\", alert=\"%s\" [color=\"%s\"];\n",
            lf->hour,
            hostname, location, srcip, dstip, srcuser, dstuser, prgname, comment, color);

    fflush(picviz_fp);
}

void OS_PicvizClose(void)
{
    if (picviz_fp) {
        fclose(picviz_fp);
    }
}

#endif

