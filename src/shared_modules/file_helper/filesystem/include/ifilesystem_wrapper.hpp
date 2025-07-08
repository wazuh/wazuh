#pragma once

#include <filesystem>
#include <vector>

/// @brief Interface for file system operations.
///
/// This interface is a wrapper for a set of file system operations such as checking if a file exists,
/// removing files or directories, creating directories, and renaming files. Any concrete class
/// that implements this interface will be expected to provide the actual functionality for these
/// operations. This allows for abstraction and easier testing or swapping of file system implementations.
class IFileSystemWrapper
{
public:
    /// @brief Virtual destructor for IFileSystemWrapper.
    ///
    /// Ensures that any derived classes with their own resources are correctly cleaned up.
    virtual ~IFileSystemWrapper() = default;

    /// @brief Checks if the specified path exists in the file system.
    /// @param path The path to check.
    /// @return Returns true if the path exists, otherwise false.
    virtual bool exists(const std::filesystem::path& path) const = 0;

    /// @brief Checks if the specified path is a directory.
    /// @param path The path to check.
    /// @return Returns true if the path is a directory, otherwise false.
    virtual bool is_directory(const std::filesystem::path& path) const = 0;

    /// @brief Checks if the specified path is a regular file.
    /// @param path The path to check.
    /// @return Returns true if the path is a regular file, otherwise false.
    virtual bool is_regular_file(const std::filesystem::path& path) const = 0;

    /// @brief Checks if the specified path is a socket.
    /// @param path The path to check.
    /// @return Returns true if the path is a socket, otherwise false.
    virtual bool is_socket(const std::filesystem::path& path) const = 0;

    /// @brief Checks if the specified path is a symbolic link.
    /// @param path The path to check.
    /// @return Returns true if the path is a symbolic link, otherwise false.
    virtual bool is_symlink(const std::filesystem::path& path) const = 0;

    /// @brief Converts the specified path to a canonical absolute path, i.e. an absolute path that has no dot, dot-dot
    /// elements or symbolic links in its generic format representation.
    /// @param path The path to convert.
    /// @return Returns the canonical absolute path.
    virtual std::filesystem::path canonical(const std::filesystem::path& path) const = 0;

    /// @brief Removes all files and subdirectories in the specified directory.
    /// @param path The directory path to remove.
    /// @return Returns the number of files and directories removed.
    virtual std::uintmax_t remove_all(const std::filesystem::path& path) const = 0;

    /// @brief Retrieves the system's temporary directory path.
    /// @return Returns the path of the system's temporary directory.
    virtual std::filesystem::path temp_directory_path() const = 0;

    /// @brief Creates a new directory at the specified path.
    /// @param path The path of the directory to create.
    /// @return Returns true if the directory was successfully created, otherwise false.
    virtual bool create_directories(const std::filesystem::path& path) const = 0;

    /// @brief Returns a vector containing the elements of a directory
    /// @param path Path to the directory
    /// @return The vector containing the elements of the directory
    virtual std::vector<std::filesystem::path> list_directory(const std::filesystem::path& path) const = 0;

    /// @brief Renames a file or directory from the 'from' path to the 'to' path.
    /// @param from The current path of the file or directory.
    /// @param to The new path for the file or directory.
    virtual void rename(const std::filesystem::path& from, const std::filesystem::path& to) const = 0;

    /// @brief Removes the specified file or directory.
    /// @param path The file or directory to remove.
    /// @return Returns true if the file or directory was successfully removed, otherwise false.
    virtual bool remove(const std::filesystem::path& path) const = 0;

    /// @brief Opens a file
    /// @param path The file to open
    /// @param flags Flags to use when opening the file
    /// @param mode Mode to use when opening the file
    /// @return File descriptor or -1 on error
    virtual int open(const char* path, int flags, int mode) const = 0;

    /// @brief Applies or removes a lock on an open file descriptor
    /// @param fd File descriptor
    /// @param operation Lock operation
    /// @return 0 on success, -1 on error
    virtual int flock(int fd, int operation) const = 0;

    /// @brief Closes a file descriptor
    /// @param fd File descriptor
    /// @return 0 on success, -1 on error
    virtual int close(int fd) const = 0;
};
