#ifndef WM_EXEC_STUB_H
#define WM_EXEC_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

// Stub declarations for testing
int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);
void _merror(const char* msg, ...);
void _mdebug1(const char* msg, ...);
void _mwarn(const char* msg, ...);
void _merror_exit(const char* msg, ...);
int w_descriptor_cloexec(int fd);
char* w_strtok(char* str, const char* delim);
int wm_task_nice(int nice);
int wm_append_sid(int sid);
int wm_remove_sid(int sid);
long long gettime();

#ifdef __cplusplus
}
#endif

#endif /* WM_EXEC_STUB_H */
