#pragma once

#include <fstream>
#include <memory>
#include <string>

/// @brief Wrapper Interface for file IO operations.
///
/// This interface wraps a set of file IO operations such as reading lines from a file,
/// getting the content of a file, and getting the binary content of a file.
class IFileIOWrapper
{
public:
    /// @brief Virtual destructor for IFileIOWrapper.
    ///
    /// Ensures that any derived classes with their own resources are correctly cleaned up.
    virtual ~IFileIOWrapper() = default;

    /// @brief Creates an ifstream for a file.
    /// @param filePath The path to the file.
    /// @param mode The mode to open the file.
    /// @return An ifstream for the file.
    virtual std::unique_ptr<std::ifstream> create_ifstream(const std::string& filePath,
                                                           std::ios_base::openmode mode = std::ios_base::in) const = 0;

    /// @brief Gets the stream buffer for a file.
    /// @param file The file to get the stream buffer for.
    /// @return The stream buffer for the file.
    virtual std::streambuf* get_rdbuf(const std::ifstream& file) const = 0;

    /// @brief Checks if a file is open.
    /// @param file The file to check.
    /// @return True if the file is open, false otherwise.
    virtual bool is_open(const std::ifstream& file) const = 0;

    /// @brief Reads a line from a file.
    /// @param file The file to read from.
    /// @param line A reference to a string where the read line will be stored.
    /// @return True if a line was read, false otherwise.
    virtual bool get_line(std::istream& file, std::string& line) const = 0;
};
