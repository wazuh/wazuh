#include <stdio.h>
#include "sym_load.h"
#include "debug_op.h"

void* so_get_module_handle_on_path(const char *path, const char *so){
#ifdef WIN32
    char file_name[MAX_PATH] = { 0 };
    snprintf(file_name, MAX_PATH-1, "%s%s.dll", path, so);
    return LoadLibrary(file_name);
#else
    char file_name[4096] = { 0 };
    void* result = NULL;
#if defined(__MACH__)
    snprintf(file_name, 4096-1, "%slib%s.dylib", path, so);
#else
    snprintf(file_name, 4096-1, "%slib%s.so", path, so);
#endif
    result = dlopen(file_name, RTLD_LAZY);
    if(result == NULL){
        mdebug1("Unable to load shared library '%s': %s", file_name, dlerror());
    }
    return result;
#endif
}

void* so_get_module_handle(const char *so){
#ifdef WIN32
    char file_name[MAX_PATH] = { 0 };
    snprintf(file_name, MAX_PATH-1, "%s.dll", so);
    return LoadLibrary(file_name);
#else
    char file_name[4096] = { 0 };
    void* result = NULL;
#if defined(__MACH__)
    snprintf(file_name, 4096-1, "lib%s.dylib", so);
#else
    snprintf(file_name, 4096-1, "lib%s.so", so);
#endif
    result = dlopen(file_name, RTLD_LAZY);
    if(result == NULL){
        mdebug1("Unable to load shared library '%s': %s", file_name, dlerror());
    }
    return result;
#endif
}

void* so_get_function_sym(void *handle, const char *function_name){
#ifndef WIN32
    void* result = dlsym(handle, function_name);
    if(result == NULL){
        mdebug1("Unable to load symbol '%s': %s", function_name, dlerror());
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
