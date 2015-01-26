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

/* Plugin decoder for OpenBSD PF */
void *PF_Decoder_Init(char *p_name);
void *PF_Decoder_Exec(void *lf);

/* Plugin for Symantec Web Security */
void *SymantecWS_Decoder_Init(char *p_name);
void *SymantecWS_Decoder_Exec(void *lf);

/* Plugin for Sonicwall */
void *SonicWall_Decoder_Init(char *p_name);
void *SonicWall_Decoder_Exec(void *lf);

/* Plugin for OSSEC alert */
void *OSSECAlert_Decoder_Init(char *p_name);
void *OSSECAlert_Decoder_Exec(void *lf);

/* List of plugins. All three lists must be in the same order */
char *(plugin_decoders[]) = {"PF_Decoder",
                             "SymantecWS_Decoder",
                             "SonicWall_Decoder",
                             "OSSECAlert_Decoder",
                             NULL
                            };
void *(plugin_decoders_init[]) = {PF_Decoder_Init,
                                  SymantecWS_Decoder_Init,
                                  SonicWall_Decoder_Init,
                                  OSSECAlert_Decoder_Init,
                                  NULL
                                 };
void *(plugin_decoders_exec[]) = {PF_Decoder_Exec,
                                  SymantecWS_Decoder_Exec,
                                  SonicWall_Decoder_Exec,
                                  OSSECAlert_Decoder_Exec,
                                  NULL
                                 };

#endif

