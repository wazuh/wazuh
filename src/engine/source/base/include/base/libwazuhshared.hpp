#ifndef _BASE_LIBWAZUHSHARED_HPP
#define _BASE_LIBWAZUHSHARED_HPP

#include <stdexcept>
#include <string>
#include <string_view>

#include <dlfcn.h>

#include <fmt/format.h>

/**
 * @brief Namespace for managing the libwazuhshared dynamic library and its functions.
 *
 * This namespace provides utilities to initialize, manage, and access functions from
 * the libwazuhshared dynamic library. It includes functionality for library lifecycle
 * management, dynamic function loading, and wrapper functions for common operations.
 */
namespace base::libwazuhshared
{

/**
 * @brief Initialize the shared library.
 *
 * This function must be called before using any other functions in this namespace.
 * It loads the libwazuhshared dynamic library and prepares it for use.
 */
void init();

/**
 * @brief Cleanup and shutdown the shared library.
 *
 * This function should be called when the shared library is no longer needed.
 * It properly unloads the library and cleans up associated resources.
 */
void shutdown();

/**
 * @brief Get a raw pointer to the loaded library.
 * @return void* Pointer to the loaded library handle.
 *
 * @warning Avoid using this function directly. Use getFunction() instead for safer
 * function loading and better error handling.
 */
void* getLibPtr();

/**
 * @brief Deleted function to prevent usage without template argument.
 *
 * This overload is explicitly deleted to force users to specify the function
 * type when calling getFunction().
 */
void getFunction(std::string_view name) = delete;

/**
 * @brief Get a typed function pointer from the shared library.
 * @tparam FuncType The function pointer type to cast the loaded function to.
 * @param name The name of the function to load from the shared library.
 * @return FuncType A function pointer of the specified type.
 *
 * @throws std::runtime_error If the library is not initialized or if dlsym fails.
 * @throws std::invalid_argument If the function name is empty.
 *
 * This template function provides type-safe access to functions in the shared library.
 * It performs validation and error checking before returning the function pointer.
 */
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


/**
 * @brief Set the logger tag for the shared library.
 * @param tag The tag string to set for logging purposes.
 *
 * This wrapper function configures the logging tag used by the shared library
 * for identifying log messages.
 */
void setLoggerTag(std::string_view tag);

/**
 * @brief Get the JSON indexer configuration.
 * @return std::string The JSON configuration string for the indexer.
 *
 * This wrapper function retrieves the current JSON indexer configuration
 * from the shared library.
 */
std::string getJsonIndexerCnf();

} // namespace base::libwazuhshared

#endif // _BASE_LIBWAZUHSHARED_HPP
