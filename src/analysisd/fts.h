/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __FTS_H
#define __FTS_H

/* FTS queues */
#ifdef TESTRULE
#define FTS_QUEUE "queue/fts/fts-queue"
#define IG_QUEUE  "queue/fts/ig-queue"
#else
#define FTS_QUEUE "/queue/fts/fts-queue"
#define IG_QUEUE  "/queue/fts/ig-queue"
#endif

#endif /* __FTS_H */

