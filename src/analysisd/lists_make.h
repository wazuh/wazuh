/* @(#) $Id: ./src/analysisd/lists_make.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


void makelist_help(const char *prog);
void Lists_OP_MakeCDB(char *txt_filename, char *cdb_filename, int force);
void Lists_OP_MakeAll(int force);
