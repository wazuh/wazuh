#include <stdio.h>
#include "sym_load.h"


void* so_get_module_handle(const char *so){
#ifndef WIN32
    char file_name[4096] = { 0 };
    snprintf(file_name, 4096-1, "lib%s.so", so);
    return dlopen(file_name, RTLD_LAZY);
#else
    char file_name[MAX_PATH] = { 0 };
    snprintf(file_name, MAX_PATH-1, "%s.dll", so);
    return LoadLibrary(file_name);
#endif
}

void* so_get_function_sym(void *handle, const char *function_name){
#ifndef WIN32
    return dlsym(handle, function_name);
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