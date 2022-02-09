/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef PLUGINDECODER_H
#define PLUGINDECODER_H

#include "../eventinfo.h"

/* Plugin decoder for OpenBSD PF */
void *PF_Decoder_Init(void);
void *PF_Decoder_Exec(Eventinfo *lf, regex_matching *decoder_match);

/* Plugin for Symantec Web Security */
void *SymantecWS_Decoder_Init(void);
void *SymantecWS_Decoder_Exec(Eventinfo *lf, regex_matching *decoder_match);

/* Plugin for Sonicwall */
void *SonicWall_Decoder_Init(void);
void *SonicWall_Decoder_Exec(Eventinfo *lf, regex_matching *decoder_match);

/* Plugin for OSSEC alert */
void *OSSECAlert_Decoder_Init(void);
void *OSSECAlert_Decoder_Exec(Eventinfo *lf, OSHash *rules_hash, regex_matching *decoder_match);

/* Plugin for JSON */
void *JSON_Decoder_Init(void);
void *JSON_Decoder_Exec(Eventinfo *lf, regex_matching *decoder_match);
void fillData(Eventinfo *lf, const char *key, const char *value);

/* List of plugins. All three lists must be in the same order */
extern const char *(plugin_decoders[]);
extern void *(plugin_decoders_init[]);
extern void *(plugin_decoders_exec[]);

#endif /* PLUGINDECODER_H */
