#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

// LCOV_EXCL_START

/// @brief Outcome of IFileIOUtils::getRegularFileContent.
enum class RegularFileStatus
{
    /// The path is a regular file and its whole content was read.
    Read,
    /// The path is not a regular file (named pipe, device, socket, directory), or it is a symbolic
    /// link and links were not to be followed. Nothing was read.
    NotRegular,
    /// The file could not be opened or read (missing, permission denied, I/O error).
    OpenFailed
};

/// @brief Interface for file IO operations.
///
/// This interface defines a set of file IO operations such as reading lines from a file,
/// getting the content of a file, and getting the binary content of a file.
class IFileIOUtils
{
    public:
        /// @brief Virtual destructor for IFileIOUtils.
        ///
        /// Ensures that any derived classes with their own resources are correctly cleaned up.
        virtual ~IFileIOUtils() = default;

        /// @brief Reads lines from a file and calls a callback for each line.
        /// @param filePath The path to the file to read.
        /// @param callback The callback function to call for each line.
        virtual void readLineByLine(const std::filesystem::path& filePath,
                                    const std::function<bool(const std::string&)>& callback) const = 0;

        /// @brief Gets the content of a file as a string.
        /// @param filePath The path to the file to read.
        /// @return The content of the file as a string.
        virtual std::string getFileContent(const std::string& filePath) const = 0;

        /// @brief Gets the binary content of a file as a vector of bytes.
        /// @param filePath The path to the file to read.
        /// @return The binary content of the file as a vector of bytes.
        virtual std::vector<char> getBinaryContent(const std::string& filePath) const = 0;

        /// @brief Reads the whole content of a file only if it is a regular file.
        ///
        /// The file is opened first and its type is checked on the opened file, so the check applies to
        /// the file that is actually read even if the path is replaced in between. Opening never waits
        /// for a writer, so a named pipe is rejected instead of blocking the caller.
        /// @param filePath The path to the file to read.
        /// @param followSymlinks When false, a path whose last component is a symbolic link (or, on
        /// Windows, a junction or other name-redirecting reparse point) is rejected as not regular.
        /// @param content Receives the content when RegularFileStatus::Read is returned; cleared otherwise.
        /// @return Whether the file was read, was rejected as not regular, or could not be opened or read.
        virtual RegularFileStatus getRegularFileContent(const std::filesystem::path& filePath,
                                                        bool followSymlinks,
                                                        std::string& content) const = 0;
};
// LCOV_EXCL_STOP
