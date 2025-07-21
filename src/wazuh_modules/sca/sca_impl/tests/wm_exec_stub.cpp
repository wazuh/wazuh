// Stub implementation of wm_exec for SCA tests
#include <cstring>
#include <cstdlib>

// Don't use extern "C" since the header doesn't wrap the declaration in extern "C"
// This ensures C++ linkage matches the header expectation

int wm_exec(char* command, char** output, int* status, int secs, const char* add_path) {
    // Simple stub implementation for testing
    if (!command || !output || !status) {
        return -1;
    }
    
    // For testing purposes, simulate a successful command execution
    *output = strdup("test output");
    *status = 0;
    return 0;
}

// Other required stubs that might be needed
extern "C" {
void _merror(const char* msg, ...) {}
void _mdebug1(const char* msg, ...) {}
void _mwarn(const char* msg, ...) {}
void _merror_exit(const char* msg, ...) { exit(1); }
int w_descriptor_cloexec(int fd) { return 0; }
char* w_strtok(char* str, const char* delim) { return strtok(str, delim); }
int wm_task_nice(int nice) { return 0; }
int wm_append_sid(int sid) { return 0; }
int wm_remove_sid(int sid) { return 0; }
long long gettime() { return 0; }
}
