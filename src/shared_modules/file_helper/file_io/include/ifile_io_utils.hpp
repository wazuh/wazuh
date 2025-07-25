#pragma once

#include <filesystem>
#include <functional>
#include <string>

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
};
