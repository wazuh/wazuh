#ifndef _BASE_LIBWAZUHSHARED_HPP
#define _BASE_LIBWAZUHSHARED_HPP

#include <stdexcept>
#include <string>
#include <string_view>

#include <dlfcn.h>

#include <fmt/format.h>

namespace base::libwazuhshared
{

// Initialize the shared library
void init();

// Cleanup the shared library
void shutdown();

void* getLibPtr(); // Avoid using this directly, use getFunction instead

void getFunction(std::string_view name) = delete; // Prevent usage without template argument

// Get a raw pointer to a function in the shared library
template<typename FuncType>
FuncType getFunction(std::string_view name)
{
    if (!getLibPtr())
    {
        throw std::runtime_error("libwazuhshared is not initialized.");
    }

    // The name should be a null-terminated string
    if (name.empty())
    {
        throw std::invalid_argument("Function name cannot be empty.");
    }

    auto* func = reinterpret_cast<FuncType>(dlsym(getLibPtr(), name.data()));
    if (!func)
    {
        throw std::runtime_error(fmt::format("dlsym {} failed: {}", name.data(), dlerror()));
    }
    return func;
}


/* Wrappers */
void setLoggerTag(std::string_view tag);

std::string getJsonIndexerCnf();


}

#endif // _BASE_LIBWAZUHSHARED_HPP
