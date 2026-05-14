/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STDIO_WRAPPERS_MACOS_H
#define STDIO_WRAPPERS_MACOS_H

#undef fprintf
#define fprintf wrap_fprintf
#undef snprintf
#define snprintf wrap_snprintf
#undef fstat
#define fstat wrap_fstat
#undef fileno
#define fileno wrap_fileno
#undef fclose
#define fclose wrap_fclose
#undef fwrite
#define fwrite wrap_fwrite
#undef fseek
#define fseek wrap_fseek
#undef fgets
#define fgets wrap_fgets
#undef mmap
#define mmap wrap_mmap
#undef munmap
#define munmap wrap_munmap
#undef tmpfile
#define tmpfile wrap_tmpfile
#undef fopen
#define fopen wrap_fopen


char * wrap_fgets(char * __s, int __n, FILE * __stream);
int wrap_fprintf(FILE *__stream, const char *__format, ...);
int wrap_snprintf(char * s, size_t n, const char *__format, ...);
int wrap_fstat (int __fd, struct stat *__buf);
int wrap_fileno(FILE *fp);
int wrap_fclose(FILE *fp);
int wrap_fwrite(char *src, int n, size_t size, FILE *fp);
int wrap_fseek(FILE *fp, int seek,  int flag);
void * wrap_mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);
int wrap_munmap (void *mem, size_t size);
FILE * wrap_tmpfile();
FILE * wrap_fopen (const char* path, const char* mode);

#endif
