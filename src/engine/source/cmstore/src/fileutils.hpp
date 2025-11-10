#ifndef _CMSTORE_FILEUTILS_HPP
#define _CMSTORE_FILEUTILS_HPP

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>

#include <base/json.hpp>
#include <yml/yml.hpp>

namespace fileutils
{

constexpr std::string_view INVALID_FILENAME_CHARS = R"(\ / : * ? " < > | )";

/**
 * @brief Set file permissions to 0640 (owner: rw-, group: r--, others: ---)
 * @param filePath Path to the file
 * @return std::optional<std::string> Return error message if operation fails, std::nullopt otherwise
 */
std::optional<std::string> setFilePermissions(const std::filesystem::path& filePath)
{
    try
    {
        // Set permissions to 0640 (owner: rw-, group: r--, others: ---)
        std::error_code ec;
        std::filesystem::permissions(filePath,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
                                         | std::filesystem::perms::group_read,
                                     std::filesystem::perm_options::replace,
                                     ec);

        if (ec)
        {
            return "Failed to set file permissions: " + ec.message();
        }

        return std::nullopt;
    }
    catch (const std::exception& e)
    {
        return "Exception occurred: " + std::string(e.what());
    }
}

/**
 * @brief Set directory permissions to 0750 (owner: rwx, group: r-x, others: ---)
 * @param dirPath Path to the directory
 * @return std::optional<std::string> Return error message if operation fails, std::nullopt otherwise
 */
std::optional<std::string> setDirectoryPermissions(const std::filesystem::path& dirPath)
{
    try
    {
        // Set permissions to 0750 (owner: rwx, group: r-x, others: ---)
        std::error_code ec;
        std::filesystem::permissions(dirPath,
                                     std::filesystem::perms::owner_all | std::filesystem::perms::group_read
                                         | std::filesystem::perms::group_exec,
                                     std::filesystem::perm_options::replace,
                                     ec);

        if (ec)
        {
            return "Failed to set directory permissions: " + ec.message();
        }

        return std::nullopt;
    }
    catch (const std::exception& e)
    {
        return "Exception occurred: " + std::string(e.what());
    }
}

/**
 * @brief Create or update a file with the given content.
 *
 * If file not exists, it will be created. If file exists, its content will be updated.
 * The permissions will be set to 0640.
 * The function not creates parent directories, they must exist.
 * @param filePath Path to the file
 * @param content Content to write in the file
 * @return std::optional<std::string> Return error message if operation fails, std::nullopt otherwise
 */
inline std::optional<std::string> upsertFile(const std::filesystem::path& filePath, const std::string& content)
{
    try
    {
        // Check if parent directory exists, if not create with 0640 permissions
        const auto parentPath = filePath.parent_path();
        if (!std::filesystem::exists(parentPath))
        {
            std::error_code ec;
            std::filesystem::create_directories(parentPath, ec);
            if (ec)
            {
                return "Failed to create parent directories: " + ec.message();
            }
            // Set permissions to 0750 (owner: rwx, group: r-x, others: ---)
            auto dirPermErr = setDirectoryPermissions(parentPath);
            if (dirPermErr)
            {
                return dirPermErr;
            }
        }

        // Create/update file
        std::ofstream file(filePath, std::ios::out | std::ios::trunc);
        if (!file.is_open())
        {
            return "Failed to open file for writing: " + filePath.string();
        }

        file << content;
        file.close();

        if (file.fail())
        {
            return "Failed to write content to file: " + filePath.string();
        }

        // Set permissions to 0640 (owner: rw-, group: r--, others: ---)
        auto filePermErr = setFilePermissions(filePath);
        if (filePermErr)
        {
            return filePermErr;
        }

        return std::nullopt;
    }
    catch (const std::exception& e)
    {
        return "Exception occurred: " + std::string(e.what());
    }
}

/**
 * @brief Delete a file at the given path.
 * @param filePath Path to the file
 * @return std::optional<std::string> Return error message if operation fails, std::nullopt otherwise
 */
inline std::optional<std::string> deleteFile(const std::filesystem::path& filePath)
{
    try
    {
        std::error_code ec;
        std::filesystem::remove(filePath, ec);
        if (ec)
        {
            return "Failed to delete file: " + ec.message();
        }
        return std::nullopt;
    }
    catch (const std::exception& e)
    {
        return "Exception occurred: " + std::string(e.what());
    }
}

/**
 * @brief Validate a filename to prevent path traversal and invalid characters.
 * @param name Filename to validate
 * @return true if the filename is valid, false otherwise
 */
inline bool isValidFileName(std::string_view name)
{
    if (name.empty())
    {
        return false;
    }

    // Check for invalid characters
    if (name.find_first_of(INVALID_FILENAME_CHARS) != std::string_view::npos)
    {
        return false;
    }

    // Check for relative paths
    if (name == "." || name == ".." || name.find('/') != std::string::npos || name.find('\\') != std::string::npos)
    {
        return false;
    }

    // Check for control characters (0-31) and DEL (127)
    for (char c : name)
    {
        if (static_cast<unsigned char>(c) < 32 || c == 127)
        {
            return false;
        }
    }

    // Check maximum filename length (TODO: Maybe we should test the full path length instead)
    if (name.length() > 255)
    {
        return false;
    }

    return true;
}

/**
 * @brief Read a JSON file and return a json::Json document.
 *
 * @param filePath Path to the JSON file
 * @return json::Json Parsed JSON document
 * @throw std::runtime_error if file cannot be opened, read or parsed
 */
json::Json readJsonFile(const std::filesystem::path& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file for reading: " + filePath.string());
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (file.fail())
    {
        throw std::runtime_error("Failed to read content from file: " + filePath.string());
    }

    return json::Json(content.c_str());
}

/**
 * @brief Read a YAML file and return a json::Json document.
 *
 * @param filePath Path to the YAML file
 * @return json::Json Parsed JSON document
 * @throw std::runtime_error if file cannot be opened, read or parsed
 */
json::Json readYMLFileAsJson(const std::filesystem::path& filePath)
{

    std::ifstream file(filePath);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file for reading: " + filePath.string());
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (file.fail())
    {
        throw std::runtime_error("Failed to read content from file: " + filePath.string());
    }

    return json::Json {yml::Converter::loadYMLfromString(content)};
}

/**
 * @brief Read a file and return its content as a string.
 *
 * @param filePath Path to the file
 * @return std::string File content
 * @throw std::runtime_error if file cannot be opened or read
 */
std::string readFileAsString(const std::filesystem::path& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file for reading: " + filePath.string());
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (file.fail())
    {
        throw std::runtime_error("Failed to read content from file: " + filePath.string());
    }

    return content;
}
} // namespace fileutils

#endif //_CMSTORE_FILEUTILS_HPP
