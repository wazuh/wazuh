/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __PLUGINDECODER_H
#define __PLUGINDECODER_H

#include "eventinfo.h"

/* Plugin decoder for OpenBSD PF */
void *PF_Decoder_Init(void);
void *PF_Decoder_Exec(Eventinfo *lf);

/* Plugin for Symantec Web Security */
void *SymantecWS_Decoder_Init(void);
void *SymantecWS_Decoder_Exec(Eventinfo *lf);

/* Plugin for Sonicwall */
void *SonicWall_Decoder_Init(void);
void *SonicWall_Decoder_Exec(Eventinfo *lf);

/* Plugin for OSSEC alert */
void *OSSECAlert_Decoder_Init(void);
void *OSSECAlert_Decoder_Exec(Eventinfo *lf);

/* List of plugins. All three lists must be in the same order */
extern const char *(plugin_decoders[]);
extern void *(plugin_decoders_init[]);
extern void *(plugin_decoders_exec[]);

#endif /* __PLUGINDECODER_H */

