/* @(#) $Id$ */

/* Copyright (C) 2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __PLUGINDECODER_H
#define __PLUGINDECODER_H


/* Plugin decoder for OpenBSD PF */
void *PF_Decoder_Init(char *p_name);
void *PF_Decoder_Exec(void *lf);


char *(plugin_decoders[])={"PF_Decoder",NULL};
void *(plugin_decoders_init[]) = {PF_Decoder_Init, NULL};
void *(plugin_decoders_exec[]) = {PF_Decoder_Exec, NULL};

                    


#endif

/* EOF */
