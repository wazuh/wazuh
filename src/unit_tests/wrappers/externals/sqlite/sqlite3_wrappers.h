/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SQLITE3_WRAPPERS_H
#define SQLITE3_WRAPPERS_H

#include "external/sqlite/sqlite3.h"

int __wrap_sqlite3_bind_int(sqlite3_stmt *stmt,
                            int index,
                            int value);

int __wrap_sqlite3_bind_int64(sqlite3_stmt *stmt,
                              int index,
                              sqlite3_int64 value);

int __wrap_sqlite3_bind_text(sqlite3_stmt* pStmt,
                             int pos,
                             const char* buffer,
                             int length,
                             void *mem_callback);

int __wrap_sqlite3_clear_bindings(sqlite3_stmt* pStmt);

int __wrap_sqlite3_close_v2();

double __wrap_sqlite3_column_double(sqlite3_stmt *pStmt,
                                    int iCol);

int __wrap_sqlite3_column_int(sqlite3_stmt *pStmt,
                              int iCol);

sqlite3_int64 __wrap_sqlite3_column_int64(sqlite3_stmt* stmt,
                                          int iCol);

const unsigned char *__wrap_sqlite3_column_text(sqlite3_stmt *pStmt,
                                                int iCol);

const char *__wrap_sqlite3_errmsg(sqlite3* db);

int __wrap_sqlite3_exec(sqlite3* db,                                 /* An open database */
                        const char *sql,                             /* SQL to be evaluated */
                        int (*callback)(void*,int,char**,char**),    /* Callback function */
                        void *arg,                                   /* 1st argument to callback */
                        char **errmsg);                              /* Error msg written here */

int __wrap_sqlite3_finalize(sqlite3_stmt *pStmt);

void __wrap_sqlite3_free(void* ptr);

int __wrap_sqlite3_last_insert_rowid(sqlite3* db);

int __wrap_sqlite3_open_v2(const char *filename,   /* Database filename (UTF-8) */
                           sqlite3 **ppDb,         /* OUT: SQLite db handle */
                           int flags,              /* Flags */
                           const char *zVfs);      /* Name of VFS module to use */

int __wrap_sqlite3_prepare_v2(sqlite3 *db,            /* Database handle */
                              const char *zSql,       /* SQL statement, UTF-8 encoded */
                              int nByte,              /* Maximum length of zSql in bytes. */
                              sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
                              const char **pzTail);    /* OUT: Pointer to unused portion of zSql */

int __wrap_sqlite3_reset(sqlite3_stmt *pStmt);

int __wrap_sqlite3_step(sqlite3_stmt * stmt);

#endif
