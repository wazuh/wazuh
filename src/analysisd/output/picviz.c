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

#include "shared.h"
#include "eventinfo.h"

static FILE *picviz_fp;

static char *(ossec2picviz[]) = {"blue", "blue", "blue", "blue",
                                 "green", "green", "green", "green",
                                 "orange", "orange", "orange", "orange",
                                 "red", "red", "red", "red", "red"
                                };


void OS_PicvizOpen(char *socket)
{
    picviz_fp = fopen(socket, "a");
    if (!picviz_fp) {
        merror("%s: Unable to open picviz socket file '%s'.",
               ARGV0, socket);
    }
}

void OS_PicvizLog(Eventinfo *lf)
{
    char *color = (lf->generated_rule->level > 15) ? "red" : ossec2picviz[lf->generated_rule->level];
    char *hostname;
    char *location;
    char *srcip;
    char *dstip;
    char *srcuser;
    char *dstuser;
    char *prgname;
    char *comment;

    if (!picviz_fp) {
        return;
    }

    hostname = lf->hostname ? lf->hostname : "";
    location = lf->location ? lf->location : "";
    srcip = lf->srcip ? lf->srcip : "";
    dstip = lf->dstip ? lf->dstip : "";
    srcuser = lf->srcuser ? lf->srcuser : "";
    dstuser = lf->dstuser ? lf->dstuser : "";
    prgname = lf->program_name ? lf->program_name : "";
    comment = lf->generated_rule->comment ? lf->generated_rule->comment : "";

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

