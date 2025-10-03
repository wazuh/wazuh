#ifndef CM_SYNC_COREOUTPUT_HPP
#define CM_SYNC_COREOUTPUT_HPP

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include <api/catalog/icatalog.hpp>
#include <base/logging.hpp>

namespace cm::sync
{

/**
 * @brief Helper class for reading and managing core output configuration files
 *
 * This class validates the output directory structure and provides methods to:
 * - Extract output content from individual YAML files
 * - List all available output configuration files
 * - Generate proper asset names from file names
 *
 * @note All output files must have .yml extension to be processed
 * @note The output path must be a valid directory that exists on the filesystem
 */
class CoreOutputReader
{

private:
    std::filesystem::path m_outputPath {}; ///< Path of directory to load YML output files.

public:
    CoreOutputReader() = delete;

    /**
     * @brief Constructs a CoreOutputReader with the specified output directory path
     *
     * @param outputPath Path to the directory containing YAML output configuration files
     * @throws std::runtime_error If the path doesn't exist or is not a directory
     */
    explicit CoreOutputReader(const std::string& outputPath);

    /**
     * @brief Default destructor
     */
    ~CoreOutputReader() = default;

    /**
     * @brief Reads and parses the content of a specific output configuration file
     *
     * This method reads a YAML file and extracts both its content and generates
     * an appropriate asset name based on the filename. The asset name follows
     * the pattern "output/{filename}/0" where {filename} is the file name without
     * the .yml extension.
     *
     * @param filePath Path to the YAML output configuration file to read
     * @return std::tuple<base::Name, std::string> A tuple containing the generated asset name and file content
     * @throws std::runtime_error If the file doesn't exist, is not a regular file, or cannot be opened
     * @todo: Should we validate the YAML and extract the name from there instead
     */
    std::tuple<base::Name, std::string> getOutputContent(const std::filesystem::path& filePath) const;

    /**
     * @brief Retrieves all YAML output configuration files from the configured directory
     *
     * Scans the output directory and returns a list of all files with .yml extension.
     * Non-YAML files are ignored and logged at debug level.
     *
     * @return std::vector<std::filesystem::path> Vector containing paths to all found YAML files
     */
    std::vector<std::filesystem::path> getAllOutputFiles() const;

    /**
     * @brief Gets the configured output directory path
     *
     * @return const std::filesystem::path& Reference to the output directory path
     */
    const std::filesystem::path& outputPath() const { return m_outputPath; }

    /**
     * @brief Gets the configured output directory path as a string
     *
     * This method uses a static variable to cache the string representation
     * for performance optimization.
     *
     * @return const std::string& Reference to the output directory path as string
     */
    const std::string& outputPathStr() const
    {
        const static std::string str = [&]()
        {
            return m_outputPath.string();
        }();
        return str;
    }
};
} // namespace cm::sync

#endif // CM_SYNC_COREOUTPUT_HPP
