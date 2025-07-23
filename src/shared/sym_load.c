#include <stdio.h>
#include "sym_load.h"

#ifndef WIN32
#ifdef RTLD_NOLOAD
#define W_RTLD_NOLOAD RTLD_NOLOAD
#else
#define W_RTLD_NOLOAD 0x0
#endif // RTLD_NOLOAD
#endif // WIN32

void* so_get_module_handle_on_path(const char *path, const char *so){
#ifdef WIN32
    char file_name[MAX_PATH] = { 0 };
    snprintf(file_name, MAX_PATH-1, "%s%s.dll", path, so);
    return LoadLibrary(file_name);
#else
    char file_name[4096] = { 0 };
#if defined(__MACH__)
    snprintf(file_name, 4096-1, "%slib%s.dylib", path, so);
#else
    snprintf(file_name, 4096-1, "%slib%s.so", path, so);
#endif
    return dlopen(file_name, RTLD_LAZY);
#endif
}

void* so_get_module_handle(const char *so){
#ifdef WIN32
    char file_name[MAX_PATH] = { 0 };
    snprintf(file_name, MAX_PATH-1, "%s.dll", so);

    HMODULE handle = NULL;
    char full_path[MAX_PATH] = { 0 };

    // Get full path to the module's file.
    // If the function succeeds, the return value is the length of the string that is copied to the buffer,
    // in characters, not including the terminating null character.
    // If the function fails, the return value is NULL.

    if (GetFullPathName(file_name, MAX_PATH, full_path, NULL)) {
        handle = LoadLibrary(full_path);
    }

    return handle;
#else
    char file_name[4096] = { 0 };
#if defined(__MACH__)
    snprintf(file_name, 4096-1, "lib%s.dylib", so);
#else
    snprintf(file_name, 4096-1, "lib%s.so", so);
#endif
    return dlopen(file_name, RTLD_LAZY);
#endif
}

void* so_check_module_loaded(const char *so){
#ifdef WIN32
    char file_name[MAX_PATH] = { 0 };
    snprintf(file_name, MAX_PATH-1, "%s.dll", so);
    return GetModuleHandle(file_name);
#else
    char file_name[4096] = { 0 };
#if defined(__MACH__)
    snprintf(file_name, 4096-1, "lib%s.dylib", so);
#else
    snprintf(file_name, 4096-1, "lib%s.so", so);
#endif
    return dlopen(file_name, W_RTLD_NOLOAD | RTLD_LAZY);
#endif
}

void* so_get_function_sym(void *handle, const char *function_name){
#ifndef WIN32
    if (!handle) {
        printf("DEBUG: so_get_function_sym called with NULL handle for %s\n", function_name);
        return NULL;
    }
    if (!function_name) {
        printf("DEBUG: so_get_function_sym called with NULL function_name\n");
        return NULL;
    }
    
    printf("DEBUG: About to call dlsym(handle=%p, function_name='%s')\n", handle, function_name);
    fflush(stdout);
    
    void *result = dlsym(handle, function_name);
    
    printf("DEBUG: dlsym returned %p for %s\n", result, function_name);
    fflush(stdout);
    
    if (!result) {
        const char *error = dlerror();
        printf("DEBUG: dlsym error for %s: %s\n", function_name, error ? error : "unknown");
        fflush(stdout);
    }
    
    return result;
#else
    return (void *)(intptr_t)GetProcAddress((HINSTANCE)handle, function_name);
#endif
}


int so_free_library(void *handle){
#ifndef WIN32
    return dlclose(handle);
#else
    return FreeLibrary((HINSTANCE)handle);
#endif
}
