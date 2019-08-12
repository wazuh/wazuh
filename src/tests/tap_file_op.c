#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stddef.h>
#include <locale.h>

#include "../headers/file_op.h"
#include "../os_net/os_net.h"
#include "tap.h"

#define FPATH "/tmp/test/tap_tests"

const char* mergedpath = FPATH "/merged_file";
char* merge_files[] = {FPATH "/mergefile1", FPATH "/mergefile2", FPATH "/mergefile3", FPATH "/mergefile4", 0};

static void _error_creating(const char* err) { printf("Error creating '%s'.\n", err); }

int create_dummy_file(const char* filename) {
    FILE *fp;
    fp = fopen(filename, "w");
    if (!fp) {
        _error_creating(filename);
        return -1;
    }
    fprintf(fp, "TEST\n");
    fclose(fp);
    return 0;
}

int setup() {
    // Create folder
    if (mkdir_ex(FPATH)) {
        printf("Error creating tap_tests folder.\n");
        return -1;
    }
    return 0;
}


void clean() {
    cldir_ex("/tmp/test/");
}


int test_isType(const char* path) {
    int ret = 0;

    if (!IsDir(path)) {
        ret += 1;
    }

    if (!IsFile(path)) {
        ret += 2;
    }

    if (!IsLink(path)) {
        ret += 4;
    }

    if (!IsSocket(path)) {
        ret += 8;
    }
    return ret;
}

// Check file type: directory
int test_isdir() {
    const char* folderpath = FPATH "/tap_folder";
    if (mkdir_ex(folderpath)) {
        _error_creating(folderpath);
        return 0;
    }
    return (test_isType(folderpath) == 1);
}

// Check file type: regular file
int test_isfile() {
    const char* filepath = FPATH "/tap_file";
    if (create_dummy_file(filepath)) {
        return 0;
    }
    return (test_isType(filepath) == 2);
}

// Check file type: symbolic link
int test_islink() {
    const char* filepath = FPATH "/tap_myfile";
    if (create_dummy_file(filepath)) {
        _error_creating(filepath);
        return 0;
    }
    const char* sympath = FPATH "/tap_symlink";
    // Create symbolic link
    if (symlink(filepath, sympath)) {
        _error_creating(sympath);
        return 0;
    }
    return (test_isType(sympath) == 6);
}

// Check file type: socket
int test_issocket() {
    const char* sockpath = FPATH "/tap_socket";
    // Create socket
    int sock;
    if (sock = OS_BindUnixDomain(sockpath, SOCK_STREAM, 512), sock < 0) {
        _error_creating(sockpath);
        close(sock);
        return 0;
    }
    int ret = 0;
    if ((test_isType(sockpath) == 8)) {
        ret = 1;
    }
    close(sock);
    return ret;
}

// Check file type: directory.
int test_isdir_check_path_type() {
    const char* folderpath = FPATH "/tap_type_folder";
    if (mkdir_ex(folderpath)) {
        _error_creating(folderpath);
        return 0;
    }
    return (check_path_type(folderpath) == 2);
}

// Check file type: regular file
int test_isfile_check_path_type() {
    const char* filepath = FPATH "/tap_type_file";
    if (create_dummy_file(filepath)) {
        return 0;
    }
    return (check_path_type(filepath) == 1);
}

// Check file type: invalid regular file
int test_nok_check_path_type() {
    return (check_path_type(FPATH "/invalid") == 0);
}

// Create new folder
int test_add_folder_ok() {
    const char* folderpath = FPATH "/tap_newfolder";
    if (mkdir_ex(folderpath)) {
        _error_creating(folderpath);
        return 0;
    }
    return (test_isType(folderpath) == 1);
}

// Create folder with an invalid file path
int test_add_folder_nok() {
    const char* filepath = FPATH "/tap_newfile";
    if (create_dummy_file(filepath)) {
        return 0;
    }
    return (mkdir_ex(filepath) == -1);
}

// Clean folder content
int test_cldir() {
    if (cldir_ex(FPATH) == 0) {
        return 1;
    }
    return 0;
}

// Remove folder
int test_rmdir_ex_ok() {

    if (rmdir_ex("/tmp/test") == 0) {
        return 1;
    }
    return 0;
}

// Remove invalid folder
int test_rmdir_ex_nok() {
    if (rmdir_ex("/tmp/test") == -1) {
        return 1;
    }
    return 0;
}

// Create new PID
int test_create_pid() {
    return (CreatePID("tap-test", (int)getpid()) == 0);
}

// Delete created PID
int test_delete_pid_ok() {
    return (DeletePID("tap-test") == 0);
}

// Delete invalid PID
int test_delete_pid_nok() {
    return (DeletePID("test-tap") == -1);
}

// Get random noise
int test_random_noise() {
    char * _ramdom_noise = NULL;
    _ramdom_noise = GetRandomNoise();
    if (!_ramdom_noise) {
        return 0;
    }
    /*
    int i;
    for (i = 0; i < 2048; i++) {
        if (_ramdom_noise[i] == '\0') {
            free(_ramdom_noise);
            return 0;
        }
    }
    */
    free(_ramdom_noise);
    return 1;
}

// List folder content
int test_wreaddir() {
    // Create dummy files
    const char* listedfolderpath = FPATH "/tap_listed";
    if (mkdir_ex(listedfolderpath)) {
        printf("Error creating tap_listed folder.\n");
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed/file")) {
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed/file.txt")) {
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed/_file")) {
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed/zfile")) {
        return 0;
    }
    int i = 0;
    int ret = 1;
    const char* files[] = {"_file", "file", "file.txt", "zfile"};
    char **content;
    content = wreaddir(listedfolderpath);
    if (!content) {
        return 0;
    }
    while (content[i] && i < 4) {
        if (strcmp(content[i], files[i])) {
            ret = 0;
        }
        free(content[i]);
        i++;
    }

    free(content);
    return ret;
}

// Clean directory ignoring files
int test_w_ref_parent_folder() {
    int i = 0;
    const char* paths[] = {
        "/var/test/folder",
        "./etc/folder",
        "/etc/folder/./folder2/./folder3/./folder4",
        "folder1/folder2/"
    };
    while (i < 4) {
        if (w_ref_parent_folder(paths[i])) {
            return 0;
        }
        i++;
    }
    return 1;
}

int test_w_ref_parent_folder_nok() {
    int i = 0;
    const char* paths[] = {
        "/var/test/../../../folder",
        "../etc/folder",
        "./etc/folder/../folder2/./folder3/../../folder4/../../../folder5",
        "/../../folder1/folder2/"
    };
    while (i < 4) {
        if (!w_ref_parent_folder(paths[i])) {
            return 0;
        }
        i++;
    }
    return 1;
}

int test_cldir_ex_ignore() {
    // Create dummy files
    const char* folderpath = FPATH "/tap_listed_ignore";
    if (mkdir_ex(folderpath)) {
        printf("Error creating tap_listed_ignore folder.\n");
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed_ignore/file1")) {
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed_ignore/file2")) {
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed_ignore/file3")) {
        return 0;
    }
    if (create_dummy_file(FPATH "/tap_listed_ignore/file4")) {
        return 0;
    }
    const char* files[] = {"file2", "file4", NULL};
    if (cldir_ex_ignore(folderpath, files)) {
        return 0;
    }
    char **content;
    content = wreaddir(folderpath);
    if (!content) {
        return 0;
    }
    int i = 0;
    int ret = 1;
    while (content[i]) {
        if ((strcmp(content[i], files[0]) && strcmp(content[i], files[1]))) {
            ret = 0;
        }
        free(content[i]);
        i++;
    }
    free(content);
    return ret;
}

// Get date of change
int test_File_DateofChange() {
    time_t date = 0;
    if (create_dummy_file(FPATH "/test_date")) {
        return 0;
    }
    time_t now = time(NULL);
    return (date = File_DateofChange(FPATH "/test_date"), (date - now) <= 1 );
}

// Check file inode
int test_File_Inode() {
    const char* checkinode = FPATH "/test_inode";
    if (create_dummy_file(checkinode)) {
        return 0;
    }
    ino_t inode = 0;
    return (inode = File_Inode(checkinode), inode > 0);
}

// Check file inode
int test_File_Inode_nok() {
    ino_t inode = 0;
    return (inode = File_Inode(FPATH "/bad_inode"), inode <= 0);
}

// Check file inode
int test_get_fp_inode() {
    const char* checkinode = FPATH "/test_fpinode";
    if (create_dummy_file(checkinode)) {
        return 0;
    }
    ino_t inode = 0;
    int ret = 0;
    FILE *fp;
    fp = fopen(checkinode, "r");
    if (!fp) {
        return 0;
    }
    if (inode = get_fp_inode(fp), inode == File_Inode(checkinode)) {
        ret = 1;
    }
    fclose(fp);
    return ret;
}

// Check file size
int test_FileSize() {
    const char* checksize = FPATH "/test_size";
    if (create_dummy_file(checksize)) {
        return 0;
    }
    off_t size = 0;
    return (size = FileSize(checksize), size > 0);
}

// Check file size
int test_FileSize_nok() {
    return (FileSize(FPATH "/bad_file") < 0);
}

// Check file size
int test_get_fp_size() {
    const char* checksize = FPATH "/test_fpsize";
    if (create_dummy_file(checksize)) {
        return 0;
    }
    off_t size = 0;
    int ret = 0;
    FILE *fp;
    fp = fopen(checksize, "r");
    if (!fp) {
        return 0;
    }
    if (size = get_fp_size(fp), size == FileSize(checksize)) {
        ret = 1;
    }
    fclose(fp);
    return ret;
}

// Merge files
int test_MergeFiles() {
    // Create merge files
    int i = 0;
    while (merge_files[i]) {
        if (create_dummy_file(merge_files[i])) {
            return 0;
        }
        i++;
    }
    // Merging files
    if (!MergeFiles(mergedpath, merge_files, "test_tag")) {
        return 0;
    }
    return !IsFile(mergedpath);
}

// Unmerge files
int test_UnmergeFiles() {
    // Create unmerge folder
    const char* ufolder = FPATH "/unmerge_folder";
    if (mkdir_ex(ufolder)) {
        printf("Error creating unmerge_folder folder.\n");
        return 0;
    }
    if (!UnmergeFiles(mergedpath, ufolder, 1)) {
        return 0;
    }
    char **content;
    content = wreaddir(ufolder);
    if (!content) {
        return 0;
    }
    int i = 0;
    int ret = 1;
    while (content[i]) {
        if (strcmp(content[i], basename_ex(merge_files[i]))) {
            ret = 0;
        }
        free(content[i]);
        i++;
    }

    free(content);
    return ret;
}

// Test merge files
int test_TestUnmergeFiles() {
    return TestUnmergeFiles(mergedpath, 1);
}

// Test merge files
int test_TestUnmergeFiles_nok() {
    char * mcopy = FPATH "merged_copy";
    if (w_copy_file(mergedpath, mcopy , 'w', NULL, 0)) {
        return 0;
    }
    if (w_remove_line_from_file(mcopy, 3)) {
        return 0;
    }
    return !TestUnmergeFiles(mcopy, 1);
}

const char* gzfile = FPATH "/merged.gz";
// Compress file
int test_w_compress_gzfile() {
    if (w_compress_gzfile(mergedpath, gzfile)) {
        return 0;
    }
    return !IsFile(gzfile);
}

// Uncompress file
int test_w_uncompress_gzfile() {
    const char* uncomppressed_file = FPATH "/uncompressed_merged";
    if (w_uncompress_gzfile(gzfile, uncomppressed_file)) {
        return 0;
    }
    return TestUnmergeFiles(uncomppressed_file, 1);
}

// Check paths basename
int test_basename_ex() {
    int i = 0;
    char* paths[] = {
        "/var/test/folder1",
        "./etc/folder2",
        "/etc/folder/./folder2/../folder3",
        "folder1/folder4"
    };
    char* basenames[] = {
        "folder1",
        "folder2",
        "folder3",
        "folder4"
    };
    int ret = 1;
    while (i < 4) {
        if (strcmp(basename_ex(paths[i]), basenames[i])) {
            ret = 0;
        }
        i++;
    }
    return ret;
}

// Rename file
int test_rename_ex() {
    if (rename_ex(mergedpath, FPATH "/merged_renamed")) {
        return 0;
    }
    return TestUnmergeFiles(FPATH "/merged_renamed", 1);
}

// Copy file
int test_w_copy_file() {
    char * wcopy = FPATH "/merged_wcopy";
    if (w_copy_file(mergedpath, wcopy, 'w', NULL, 0)) {
        return 0;
    }
    return TestUnmergeFiles(wcopy, 1);
}

// Remove line from file
int test_w_remove_line_from_file() {
    // Create file
    FILE *fp;
    char* filename = FPATH "/test_remove_line";
    fp = fopen(filename, "w");
    if (!fp) {
        _error_creating(filename);
        return 0;
    }
    fprintf(fp, "line_0\n");
    fprintf(fp, "line_1\n");
    fprintf(fp, "line_2\n");
    fprintf(fp, "line_3\n");
    fprintf(fp, "line_4\n");
    fprintf(fp, "line_5\n");
    fprintf(fp, "line_6\n");
    fprintf(fp, "line_7\n");
    fprintf(fp, "line_8\n");
    fprintf(fp, "line_9\n");
    fclose(fp);
    // Remove lines
    int i;
    for (i = 8; i >= 0; i--) {
        if (w_remove_line_from_file(filename, i)) {
            return 0;
        }
    }
    // Parse line
    int ret = 1;
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    fp = fopen(filename, "r");
    if (!fp) {
        return 0;
    }
    getline(&line_buf, &line_buf_size, fp);
    if (strcmp(line_buf, "line_9\n")) {
        ret = 0;
    }
    fclose(fp);
    free(line_buf);
    return ret;
}

// check UTF-8 file.
int test_is_utf8() {
    int ret = 1;
    // Save locale
    char *old_locale, *saved_locale;
    old_locale = setlocale(LC_ALL, NULL);
    saved_locale = strdup(old_locale);
    // Change locale
    setlocale(LC_ALL, "en_US.UTF-8");
    // Create file
    const char* filename = FPATH "/utf8_file";
    FILE *fp;
    fp = fopen(filename, "w");
    if (!fp) {
        _error_creating(filename);
        return 0;
    }
    fprintf(fp, "ñü\n");
    fclose(fp);
    // Check file
    if (is_ascii_utf8(filename, 100, 100)) {
        ret = 0;
    }
    // Restore locale
    setlocale(LC_ALL, saved_locale);
    free(saved_locale);
    return ret;
}

// check UTF-8 file.
int test_is_ascii() {
    int ret = 1;
    // Save locale
    char *old_locale, *saved_locale;
    old_locale = setlocale(LC_ALL, NULL);
    saved_locale = strdup(old_locale);
    // Change locale
    setlocale(LC_ALL, "en_US.UTF-8");
    // Create file
    const char* filename = FPATH "/ascii_file";
    if (create_dummy_file(filename)) {
        return 0;
    }
    // Check file
    if (is_ascii_utf8(filename, 100, 100)) {
        ret = 0;
    }
    // Restore locale
    setlocale(LC_ALL, saved_locale);
    free(saved_locale);
    return ret;
}

// Check binary file.
int test_checkBinaryFile() {
    // Create file
    unsigned int buffer[10];
    int i;
    for(i = 0; i<10; i++) {
        buffer[i] = i*16;
    }
    const char* filename = FPATH "/binary_file";
    FILE *fp;
    fp = fopen(filename, "wb");
    if (!fp) {
        _error_creating(filename);
        return 0;
    }
    fwrite(buffer, sizeof(buffer), 1, fp);
    fclose(fp);

    return (checkBinaryFile(filename) == 0);
}

// Check binary file.
int test_checkBinaryFile_nok() {
    const char* filename = FPATH "/non_binary_file";
    if (create_dummy_file(filename)) {
        return 0;
    }

    return checkBinaryFile(filename);
}

int main(void) {

    clean();
    if (setup()) {
        printf("\n\n   FAILED TEST - FILE_OP   \n\n");
        return 1;
    }

    printf("\n\n   STARTING TEST - FILE_OP   \n\n");

    TAP_TEST_MSG(test_add_folder_ok(), "mkdir_ex(): Create new folder.");

    TAP_TEST_MSG(test_add_folder_ok(), "mkdir_ex(): Create duplicated folder.");

    TAP_TEST_MSG(test_add_folder_nok(), "mkdir_ex(): Create folder with an invalid file path.");

    TAP_TEST_MSG(test_isdir(), "IsDir(): Check file type: directory.");

    TAP_TEST_MSG(test_isfile(), "IsFile(): Check file type: regular file.");

    TAP_TEST_MSG(test_islink(), "IsLink(): Check file type: symbolic link.");

    TAP_TEST_MSG(test_issocket(), "IsSocket(): Check file type: socket.");

    TAP_TEST_MSG(test_isdir_check_path_type(), "check_path_type(): Check file type: directory.");

    TAP_TEST_MSG(test_isfile_check_path_type(), "check_path_type(): Check file type: regular file.");

    TAP_TEST_MSG(test_nok_check_path_type(), "check_path_type(): Check file type: invalid file.");

    TAP_TEST_MSG(test_wreaddir(), "test_wreaddir(): List folder content.");

    TAP_TEST_MSG(test_File_DateofChange(), "File_DateofChange(): Get date of change.");

    TAP_TEST_MSG(test_File_Inode(), "File_Inode(): Check file inode.");

    TAP_TEST_MSG(test_File_Inode_nok(), "File_Inode(): Check invalid file inode.");

    TAP_TEST_MSG(test_get_fp_inode(), "get_fp_inode(): Check file inode.");

    TAP_TEST_MSG(test_FileSize(), "get_FileSize(): Check file size.");

    TAP_TEST_MSG(test_FileSize_nok(), "get_FileSize(): Check invalid file size.");

    TAP_TEST_MSG(test_get_fp_size(), "get_fp_size(): Check file size.");

    TAP_TEST_MSG(test_MergeFiles(), "MergeFiles(): Merge files.");

    TAP_TEST_MSG(test_TestUnmergeFiles(), "TestUnmergeFiles(): Check merged file.");

    TAP_TEST_MSG(test_TestUnmergeFiles_nok(), "TestUnmergeFiles(): Check invalid merged file.");

    TAP_TEST_MSG(test_UnmergeFiles(), "UnmergeFiles(): Unmerge files.");

    TAP_TEST_MSG(test_w_compress_gzfile(), "w_compress_gzfile(): Compress gzfile.");

    TAP_TEST_MSG(test_w_uncompress_gzfile(), "w_uncompress_gzfile(): Uncompress gzfile.");

    TAP_TEST_MSG(test_w_copy_file(), "w_copy_file(): Copy file.");

    TAP_TEST_MSG(test_rename_ex(), "rename_ex(): Rename file.");

    TAP_TEST_MSG(test_is_ascii(), "is_ascii_utf8(): Check ASCII file.");

    TAP_TEST_MSG(test_is_utf8(), "is_ascii_utf8(): Check UTF-8 file.");

    TAP_TEST_MSG(test_checkBinaryFile(), "checkBinaryFile(): Check binary file.");

    TAP_TEST_MSG(test_checkBinaryFile(), "checkBinaryFile(): Check non binary file.");

    TAP_TEST_MSG(test_w_remove_line_from_file(), "w_remove_line_from_file(): Remove line from file.");

    TAP_TEST_MSG(test_cldir_ex_ignore(), "cldir_ex_ignore(): Clean directory ignoring files.");

    TAP_TEST_MSG(test_cldir(), "test_cldir(): Clean folder content.");

    TAP_TEST_MSG(test_rmdir_ex_ok(), "rmdir_ex(): Remove folder.");

    TAP_TEST_MSG(test_rmdir_ex_nok(), "rmdir_ex(): Remove invalid folder.");

    TAP_TEST_MSG(test_create_pid(), "CreatePID(): Create new PID.");

    TAP_TEST_MSG(test_delete_pid_ok(), "DeletePID(): Delete created PID.");

    TAP_TEST_MSG(test_delete_pid_nok(), "DeletePID(): Delete invalid PID.");

    TAP_TEST_MSG(test_random_noise(), "GetRandomNoise(): Get random data from /dev/urandom.");

    TAP_TEST_MSG(test_w_ref_parent_folder(), "w_ref_parent_folder(): Check valid paths.");

    TAP_TEST_MSG(test_w_ref_parent_folder_nok(), "w_ref_parent_folder(): Check invalid paths.");

    clean();

    TAP_PLAN;
    TAP_SUMMARY;
    printf("\n   ENDING TEST - FILE_OP   \n\n");
    return 0;

}
