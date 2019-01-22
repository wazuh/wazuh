/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle operation with files */

#ifndef __FILE_H
#define __FILE_H

#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <external/cJSON/cJSON.h>

#define OS_PIDFILE  "/var/run"

#ifdef WIN32
typedef uint64_t wino_t;
#else
typedef ino_t wino_t;
#endif

typedef struct File {
    char *name;
    FILE *fp;
} File;

/* Set the program name - must be done before *anything* else */
void OS_SetName(const char *name) __attribute__((nonnull));

cJSON* getunameJSON();

time_t File_DateofChange(const char *file) __attribute__((nonnull));

ino_t File_Inode(const char *file) __attribute__((nonnull));

off_t FileSize(const char * path);

int IsDir(const char *file) __attribute__((nonnull));

int check_path_type(const char *dir) __attribute__((nonnull));

int IsFile(const char *file) __attribute__((nonnull));

int IsSocket(const char * file) __attribute__((nonnull));

#ifndef WIN32
int IsLink(const char * file) __attribute__((nonnull));
#endif

int CreatePID(const char *name, int pid) __attribute__((nonnull));

char *GetRandomNoise();

int DeletePID(const char *name) __attribute__((nonnull));

void DeleteState();

int MergeFiles(const char *finalpath, char **files, const char *tag) __attribute__((nonnull(1, 2)));

int MergeAppendFile(const char *finalpath, const char *files, const char *tag, int path_offset) __attribute__((nonnull(1)));

int UnmergeFiles(const char *finalpath, const char *optdir, int mode) __attribute__((nonnull(1)));

int TestUnmergeFiles(const char *finalpath, int mode) __attribute__((nonnull(1)));

/* Daemonize a process */
void goDaemon(void);

/* Daemonize a process without closing stdin/stdout/stderr */
void goDaemonLight(void);

/* Not really a file operation, but returns the uname */
const char *getuname(void);

/* Return basename of path */
char *basename_ex(char *path) __attribute__((nonnull));

/* Rename file or directory */
int rename_ex(const char *source, const char *destination) __attribute__((nonnull));

/* Create temporary file */
int mkstemp_ex(char *tmp_path) __attribute__((nonnull));

int TempFile(File *file, const char *source, int copy);
int OS_MoveFile(const char *src, const char *dst);
int w_copy_file(const char *src, const char *dst,char mode,char * message,int silent);

/* Checks for Windows Vista */
#ifdef WIN32
int checkVista();
int isVista;
int get_creation_date(char *dir, SYSTEMTIME *utc);

// Move to the directory where this executable lives in
void w_ch_exec_dir();
#endif

/* Delete directory recursively */
int rmdir_ex(const char *path);

// Delete directory content
int cldir_ex(const char *name);

// Delete directory content with exception list
int cldir_ex_ignore(const char * name, const char ** ignore);

// Make directory recursively
int mkdir_ex(const char * path);

int w_ref_parent_folder(const char * path);

wino_t get_fp_inode(FILE * fp);

long get_fp_size(FILE * fp);

// Read directory and return an array of contained files, sorted alphabetically.
char ** wreaddir(const char * name);

// Open file normally in Linux, allow read/write/delete in Windows
FILE * wfopen(const char * pathname, const char * mode);

/* Delete a line from a file */
int w_remove_line_from_file(char *file, int line);

// To compress an decompress a file in gzip
int w_compress_gzfile(const char *filesrc, const char *filedst);
int w_uncompress_gzfile(const char *gzfilesrc, const char *gzfiledst);

#endif /* __FILE_H */
