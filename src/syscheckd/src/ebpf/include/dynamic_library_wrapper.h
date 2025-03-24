#ifndef DYNAMIC_LIBRARY_WRAPPER_H
#define DYNAMIC_LIBRARY_WRAPPER_H

#include "sym_load.h"

#ifdef __cplusplus

class DynamicLibraryWrapper {
public:
    virtual ~DynamicLibraryWrapper() = default;
    virtual void* getModuleHandle(const char* so) = 0;
    virtual void* getFunctionSymbol(void* handle, const char* function_name) = 0;
    virtual int freeLibrary(void* handle) = 0;
};

class DefaultDynamicLibraryWrapper : public DynamicLibraryWrapper {
public:
    void* getModuleHandle(const char* so) override {
        return so_get_module_handle(so);
    }

    void* getFunctionSymbol(void* handle, const char* function_name) override {
        return so_get_function_sym(handle, function_name);
    }

    int freeLibrary(void* handle) override {
        return so_free_library(handle);
    }
};

#endif // __cplusplus

#endif // DYNAMIC_LIBRARY_WRAPPER_H
