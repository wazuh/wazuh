#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include <base/logging.hpp>

#include "coreoutput.hpp"

namespace cm::sync
{

CoreOutputReader::CoreOutputReader(const std::string& outputPath)
    : m_outputPath(outputPath)
{
    if (!std::filesystem::exists(m_outputPath))
    {
        throw std::runtime_error(fmt::format("Output configuration path '{}' does not exist", outputPath));
    }

    // Check if output path is a directory
    if (!std::filesystem::is_directory(m_outputPath))
    {
        throw std::runtime_error(
            fmt::format("Output configuration path '{}' is not a directory", m_outputPath.string()));
    }

    m_outputPath = std::filesystem::canonical(m_outputPath);
}

std::tuple<base::Name, std::string> CoreOutputReader::getOutputContent(const std::filesystem::path& filePath) const
{
    if (!std::filesystem::exists(filePath))
    {
        throw std::runtime_error(fmt::format("Output configuration file '{}' does not exist", filePath.string()));
    }

    if (!std::filesystem::is_regular_file(filePath) || filePath.extension() != ".yml")
    {
        throw std::runtime_error(fmt::format("Output configuration file '{}' is not a .yml file", filePath.string()));
    }

    // Load file content
    std::ifstream fileStream(filePath);
    if (!fileStream.is_open())
    {
        throw std::runtime_error(fmt::format("Could not open output configuration file '{}'", filePath.string()));
    }

    std::string fileContent((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
    fileStream.close();

    // Get the asset name from the file name TODO: Read from file content?
    // TODO Validate the name should be only alphanumeric and dashes/underscores (asset name validate)
    // Remove .yml extension
    const auto fileName = filePath.filename().string().substr(0, filePath.filename().string().size() - 4);
    const auto assetName = base::Name(fmt::format("output/{}/0", fileName));

    return {assetName, fileContent};
}

std::vector<std::filesystem::path> CoreOutputReader::getAllOutputFiles() const
{
    // Filter ouput in outputPath
    std::vector<std::filesystem::path> ymlFiles;
    ymlFiles.reserve(32); // Prevent multiple allocations

    for (const auto& entry : std::filesystem::directory_iterator(m_outputPath))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".yml")
        {
            ymlFiles.push_back(entry.path());
            LOG_TRACE("Found output file: {}", entry.path().string());
        }
        else
        {
            LOG_DEBUG("Ignoring non-yml file: {}", entry.path().string());
        }
    }

    return ymlFiles;
}

} // namespace cm::sync
