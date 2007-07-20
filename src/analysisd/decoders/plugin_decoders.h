/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifndef __PLUGINDECODER_H
#define __PLUGINDECODER_H


/* Plugin decoder for OpenBSD PF */
void *PF_Decoder_Init(char *p_name);
void *PF_Decoder_Exec(void *lf);

/* Plugin for Symantec Web Security */
void *SymantecWS_Decoder_Exec(Eventinfo *lf);
void *SymantecWS_Decoder_Init(char *p_name);


/* List of plugins. All three lists must be in the same order */
char *(plugin_decoders[])={"PF_Decoder",
                           "SymantecWS_Decoder", 
                           NULL};
void *(plugin_decoders_init[]) = {PF_Decoder_Init, 
                                  SymantecWS_Decoder_Init, 
                                  NULL};
void *(plugin_decoders_exec[]) = {PF_Decoder_Exec, 
                                  SymantecWS_Decoder_Exec,
                                  NULL};

                    


#endif

/* EOF */
