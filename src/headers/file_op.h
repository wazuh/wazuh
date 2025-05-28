/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle operation with files */

#ifndef FILE_OP_H
#define FILE_OP_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <cJSON.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef __MACH__
#include <libproc.h>
#endif

#define OS_PIDFILE  "var/run"
#define UCS2_LE 1
#define UCS2_BE 2

#ifdef WIN32
#define PATH_SEP '\\'
typedef uint64_t wino_t;
extern int isVista;
#else
#define PATH_SEP '/'
typedef ino_t wino_t;
#endif

typedef struct File {
    char *name;
    FILE *fp;
} File;

/**
 * @brief Set the program name. Must be done before *anything* else.
 *
 * @param name Program name.
 */
void OS_SetName(const char *name) __attribute__((nonnull));


/**
 * @brief Get the information of the operating system version in JSON format.
 *
 * @return Pointer to JSON object.
 */
cJSON* getunameJSON();


/**
 * @brief Get the time of the last modification of the specified file.
 *
 * @param file File name.
 * @return Time of last modification or -1 on error.
 */
time_t File_DateofChange(const char *file) __attribute__((nonnull));


/**
 * @brief Get the inode number of the specified file.
 *
 * @param file File name.
 * @return File inode or 0 on error.
 */
ino_t File_Inode(const char *file) __attribute__((nonnull));


/**
 * @brief Get the inode number of the specified file pointer.
 *
 * @param fp File pointer.
 * @return File inode or -1 on error.
 */
wino_t get_fp_inode(FILE * fp);


#ifdef WIN32
/**
 * @brief Get the file information of the specified file pointer.
 *
 * @param fp File pointer.
 * @param fileInfo Pointer to file information.
 * @return 0 in case of error, not 0 in success.
 */
int get_fp_file_information(FILE * fp, LPBY_HANDLE_FILE_INFORMATION fileInfo);
#endif


/**
 * @brief Get the size of the specified file.
 *
 * @param path File name.
 * @return File size or -1 on error.
 */
off_t FileSize(const char * path);


/**
 * @brief Get the size of a folder.
 *
 * @param path Folder path
 *
 * @return Size of folder in bytes
 */
float DirSize(const char *path);


/**
 * @brief Get the size of the specified file pointer.
 *
 * @param fp File pointer.
 * @return File size or -1 on error.
 */
long get_fp_size(FILE * fp);


/**
 * @brief Check if the specified file is a directory or a symbolic link to a directory.
 *
 * @param file File path.
 * @return 0 if it is a directory, -1 otherwise.
 */
int IsDir(const char *file) __attribute__((nonnull));


/**
 * @brief Check if the specified file is a regular file or a symbolic link to a regular file.
 *
 * @param file File path.
 * @return 0 if it is a regular file, -1 otherwise.
 */
int IsFile(const char *file) __attribute__((nonnull));


/**
 * @brief Check if the specified file is a socket.
 *
 * @param file File path.
 * @return 0 if it is a socket, -1 otherwise.
 */
int IsSocket(const char * file) __attribute__((nonnull));


/**
 * @brief Get the type of the specified file.
 *
 * @param dir File path.
 * @return 1 if it is a file, 2 if it is a directory, 0 otherwise.
 */
int check_path_type(const char *dir) __attribute__((nonnull));


#ifndef WIN32
/**
 * @brief Check if the specified file is a link.
 *
 * @param file File path.
 * @return 0 if it is a link, -1 otherwise.
 */
int IsLink(const char * file) __attribute__((nonnull));

/**
 * Check if a program is available in the system PATH.
 *
 * @param program The name of the program to check.
 * @return true if the program is available, false otherwise.
 */
bool is_program_available(const char *program);

#endif


/**
 * @brief Get random data from `/dev/urandom`.
 *
 * @return Pointer to random data array.
 */
char *GetRandomNoise();


/**
 * @brief Creates a PID file for the specified service name.
 *
 * @param name Service name.
 * @param pid Service PID.
 * @return 0 if the file was created, -1 on error.
 */
int CreatePID(const char *name, int pid) __attribute__((nonnull));


/**
 * @brief Deletes the PID file for the specified service name.
 *
 * @param name Service name.
 * @return 0 if the file was deleted, -1 on error.
 */
int DeletePID(const char *name) __attribute__((nonnull));


/**
 * @brief Deletes the service state file.
 *        The state file is defined by the __local_name value.
 *
 */
void DeleteState();


/**
 * @brief Merge files recursively into one single file.
 *
 * @param finalfp Handler of the file.
 * @param files Files to be merged.
 * @param path_offset Offset for recursion.
 * @return 1 if the merged file was created, 0 on error.
 */
int MergeAppendFile(FILE *finalfp, const char *files, int path_offset) __attribute__((nonnull(1, 2)));


/**
 * @brief Unmerge file.
 *
 * @param finalpath Path of the merged file.
 * @param optdir Path of the folder to unmerge the files. If not specified, the files will be unmerged in the current working directory.
 * @param mode Indicates if the merged file must be readed as a binary file  or not. Use `#OS_TEXT`, `#OS_BINARY`.
 * @return 1 if the file was unmerged, 0 on error.
 */
int UnmergeFiles(const char *finalpath, const char *optdir, int mode, char ***unmerged_files) __attribute__((nonnull(1)));


/**
 * @brief Check if the merged file is valid.
 *
 * @param finalpath Path of the merged file.
 * @param mode Indicates if the merged file must be readed as a binary file  or not. Use `#OS_TEXT`, `#OS_BINARY`.
 * @return 1 if the merged file is valid, 0 if not.
 */
int TestUnmergeFiles(const char *finalpath, int mode) __attribute__((nonnull(1)));


/**
 * @brief Daemonize a process.
 *
 */
void goDaemon(void);


/**
 * @brief Daemonize a process without closing stdin/stdout/stderr.
 *
 */
void goDaemonLight(void);


/**
 * @brief Get the OS information.
 *
 * @return OS uname.
 */
const char *getuname(void);


/**
 * @brief Get the basename of a path.
 *
 * @bug There is a bug in the `basename()` function.
 *      In the glibc implementation, the POSIX versions of these functions
 *      modify the path argument, and segfault when called with a static
 *      string such as "/usr/".
 * @return Pointer to the path basename.
 */
char *basename_ex(char *path) __attribute__((nonnull));


/**
 * @brief Rename file or directory.
 *
 * @param source Path of the file/folder to be renamed.
 * @param destination Path of the renamed file/folder.
 * @return 0 on success and -1 on error.
 */
int rename_ex(const char *source, const char *destination) __attribute__((nonnull));


/**
 * @brief Create temporary file.
 *
 * @param tmp_path Temporary file path.
 * @return 0 on success and -1 on error.
 */
int mkstemp_ex(char *tmp_path) __attribute__((nonnull));


/**
 * @brief Create temporary file.
 *
 * @param [out] file Pointer to File object.
 * @param [in] source Source path.
 * @param [in] copy Copy file.
 * @return 0 on success and -1 on error.
 */
int TempFile(File *file, const char *source, int copy);


/**
 * @brief Move file.
 *
 * @param src Source path.
 * @param dst Destination path.
 * @return 0 on success and -1 on error.
 */
int OS_MoveFile(const char *src, const char *dst);


/**
 * @brief Copy file.
 *
 * @param src Source path.
 * @param dst Destination path.
 * @param mode Mode: `a` to append, `w` to write.
 * @param message Write message to the destination file.
 * @param silent Do not show errors.
 * @return 0 on success and -1 on error.
 */
int w_copy_file(const char *src, const char *dst, char mode, char * message, int silent);


/**
 * @brief Delete directory recursively.
 *
 * @param path Path of the folder to be removed.
 * @return 0 on success. On error, -1 is returned, and errno is set appropriately.
 */
int rmdir_ex(const char *path);


/**
 * @brief Delete directory content.
 *
 * @param name Path of the folder.
 * @return 0 on success. On error, -1 is returned, and errno is set appropriately.
 */
int cldir_ex(const char *name);


/**
 * @brief Delete directory content with exception list.
 *
 * @param name Path of the folder.
 * @param ignore Array of files to be ignored. This array must be NULL terminated.
 * @return 0 on success. On error, -1 is returned, and errno is set appropriately.
 */
int cldir_ex_ignore(const char * name, const char ** ignore);


/**
 * @brief Create directory recursively.
 *
 * @param path Path of the folder.
 * @return 0 on success, -1 on error.
 */
int mkdir_ex(const char * path);


/**
 * @brief Check the path for preventing directory transversal attacks.
 *
 * @param path Path to be checked.
 * @return 0 if the path is safe, 1 otherwise.
 */
int w_ref_parent_folder(const char * path);


/**
 * @brief Read directory and return an array of contained files and folders, sorted alphabetically.
 *
 * @param name Path of the directory.
 * @return Array of filenames.
 */
char ** wreaddir(const char * name);


/**
 * @brief Open file normally in Linux, allow read/write/delete in Windows.
 *
 * @param pathname Path of the file.
 * @param mode Open mode.
 * @return File pointer.
 */
FILE * wfopen(const char * pathname, const char * mode);


/**
 * @brief Compress a file in GZIP.
 *
 * @param filesrc Source file.
 * @param filedst Compressed file path.
 * @return 0 on success, -1 on error.
 */
int w_compress_gzfile(const char *filesrc, const char *filedst);


/**
 * @brief Uncompress GZIP file.
 *
 * @param gzfilesrc GZIP file path.
 * @param gzfiledst Uncompressed file pah.
 * @return 0 on success, -1 on error.
 */
int w_uncompress_gzfile(const char *gzfilesrc, const char *gzfiledst);


/**
 * @brief Check if a file is ASSCI or UTF8.
 *
 * @param file File to be checked.
 * @param max_lines Max line to be processed.
 * @param max_chars_utf8 Max number of UTF8 characters to be processed.
 * @return 0 if the file is ASSCI or UTF8, 1 if not.
 */
int is_ascii_utf8(const char * file, unsigned int max_lines, unsigned int max_chars_utf8);


/**
 * @brief Check if a file is USC2.
 *
 * @param file File to be checked.
 * @return 0 if the file is USC2, 1 if not.
 */
int is_usc2(const char * file);


/**
 * @brief Checks if the specified file is binary.
 *
 * @param f_name File to be checked.
 * @return 0 if the file is binary, 1 if not.
 */
int checkBinaryFile(const char *f_name);


/**
 * @brief Returns the current file position of the given stream.
 *        This is a wrapper for `ftell()` in UNIX and `_ftelli64()` in Windows.
 *
 * @param x File pointer.
 * @return File position.
 */
int64_t w_ftell (FILE *x);

/**
 * @brief Set the current file position of the given stream.
*        This is a wrapper for `fseek()` in UNIX and `_fseeki64()` in Windows.
 * @param x File pointer.
 * @param pos File position.
 * @param mode Position used as reference for the offset: SEEK_SET, SEEK_CURRENT, SEEK_END
 * @return  If successful, the function returns zero. Otherwise, it returns -1.
 */
int w_fseek(FILE *x, int64_t pos, int mode);

/**
 * @brief Prevent children processes from inheriting a file pointer.
 *
 * @param File pointer.
 */
void w_file_cloexec(FILE * fp);


/**
 * @brief Prevent children processes from inheriting a file descriptor.
 *
 * @param File descriptor.
 */
void w_descriptor_cloexec(int fd);


#ifdef WIN32
/**
 * @brief Check if the Windows version is Vista or newer. (Windows)
 *
 * @return 1 if version is 6.0 or newer, 0 otherwise.
 */
int checkVista();


/**
 * @brief Get the creation date object. (Windows)
 *
 * @param [in] dir Path of the file/folder.
 * @param [out] utc Pointer to SYSTEMTIME object.
 * @return 0 on success, 1 on error.
 */
int get_creation_date(char *dir, SYSTEMTIME *utc);


/**
 * @brief Get the modification date object. (Windows)
 *
 * @param file Path of the file.
 * @return time_t date of modification format.
 */
time_t get_UTC_modification_time(const char *file);


/**
 * @brief Move to the directory where this executable lives in. (Windows)
 *
 */
void w_ch_exec_dir();


/**
 * @brief Get the size of a file. (Windows)
 *
 * @param file Path of the file.
 * @return File size or -1 on error.
 */
DWORD FileSizeWin(const char * file);

/**
 * @brief Open a file
 *
 * This mode of opening the file allows reading \r\n instead of \n.
 *
 * @param file pathfile to open
 * @param[out] lpFileInformation  pointer to a BY_HANDLE_FILE_INFORMATION structure that receives the file information
 * @return file descriptor on success, otherwise null.
 */
FILE * w_fopen_r(const char *file, const char * mode, BY_HANDLE_FILE_INFORMATION * lpFileInformation);

/**
 * @brief Expands wildcards for Windows (using FindFirstFile and FindNexFile)
 *
 * @param path Path containing the wildcards to expand.
 * @return char** Vector with the expanded paths.
 */
char **expand_win32_wildcards(const char *path);

#endif // Windows

/**
 * @brief Add a trailing separator to a path string
 *
 * The trailing separator ('/' on UNIX, '\ ' on Windows) is only added if the source string does not end with such character.
 *
 * @param dest Destination string.
 * @param src Source path string.
 * @param n Size of the destination string.
 * @return int number of bytes written in the string. If is greater or equal than n, the string remained truncated.
 */
int trail_path_separator(char * dest, const char * src, size_t n);


/**
 * @brief Check if a path is absolute
 *
 * A path on UNIX is absolute if it starts with /.
 *
 * A path on Windows is absolute if it starts with X:\ , being X any alphabetic character.
 *
 * @param path Input path.
 * @return true if the path is absolute.
 * @return false if the path is relative.
 */
bool isabspath(const char * path);


/**
 * @brief Unify path separators (slashes) for Windows paths
 *
 * Let all path separators be backslashes.
 *
 * @param path A string containing a path.
 */
void win_path_backslash(char * path);


/**
 * @brief Get an absolute path
 *
 * @param path Input path (absolute or relative).
 * @param buffer Destination string.
 * @param size Size of buffer.
 * @return Pointer to buffer on success, or NULL on error.
 */
char * abspath(const char * path, char * buffer, size_t size);


/**
 * @brief Get the content of a given file
 *
 * @param path File location
 * @param max_size Maximum allowed file size
 * @return The content of the file
 * @retval NULL The file doesn't exist or its size exceeds the maximum allowed
 */
char * w_get_file_content(const char * path, unsigned long max_size);


/**
 * @brief Get the pointer to a given file
 *
 * @param path File location
 * @return The pointer to the file
 * @retval NULL The file doesn't exist
 */
FILE * w_get_file_pointer(const char * path);

/**
 * @brief Check if a file is gzip compressed
 *
 * @param path File location
 * @retval 0 The file is not gzip compressed
 * @retval 1 The file is gzip compressed
 */
int w_is_compressed_gz_file(const char * path);

/**
 * @brief Check if a file is bzip2 compressed
 *
 * @param path File location
 * @retval 0 The file is not bzip2 compressed
 * @retval 1 The file is bzip2 compressed
 */
int w_is_compressed_bz2_file(const char * path);

#ifndef CLIENT
/**
 * @brief Check if a file from a path is compressed in bunzip2 or gzip and uncompressed it
 *
 * @param path File location
 * @retval -1 The file cannot be uncompressed
 * @retval 0 The file has been uncompressed (.gz or .bz2)
 */
int w_uncompress_bz2_gz_file(const char * path, const char * dest);
#endif /* CLIENT */

/**
 * @brief Get the Wazuh installation directory
 *
 * It is obtained from the /proc directory, argv[0], or the env variable WAZUH_HOME
 *
 * @param arg ARGV0 - Program name
 * @return Pointer to the Wazuh installation path on success
 */
char *w_homedir(char *arg);
#endif /* FILE_OP_H */
