#pragma once

#include <deque>
#include <string>

/// @brief Interface for file system utils.
class IFileSystemUtils
{
public:
    /// @brief Virtual destructor for IFileSystemUtils.
    ///
    /// Ensures that any derived classes with their own resources are correctly cleaned up.
    virtual ~IFileSystemUtils() = default;

    /// @brief Expands the absolute path of a file or directory.
    /// @param path The path to expand.
    /// @param output The deque to store the expanded path.
    virtual void expand_absolute_path(const std::string& path, std::deque<std::string>& output) const = 0;
};
