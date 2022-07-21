/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#ifndef LISTSMAKE_H
#define LISTSMAKE_H

/**
 * @brief Compile a CDB list
 * @param txt_filename File which has the CDB list
 * @param cdb_filename File which saves the CDB list compile
 * @param force determine if overwrite cdb_filename although txt_filename haven't changed
 * @show_message determine if print  '* CDB list %s has been updated successfully' message
 */
void Lists_OP_MakeCDB(const char *txt_filename, const char *cdb_filename, const int force, const int show_message);

/**
 * @brief Call the Lists_OP_MakeCDB function for each CDB list.
 * @param force parameter for Lists_OP_MakeCDB
 * @param show_message parameter for Lists_OP_MakeCDB
 * @param lnode list of CDB lists
 */
void Lists_OP_MakeAll(int force, int show_message, ListNode **lnode);

#endif /* LISTSMAKE_H */
