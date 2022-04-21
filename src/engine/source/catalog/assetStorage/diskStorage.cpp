#include <filesystem>
#include <fstream>

#include <fmt/format.h>

#include "diskStorage.hpp"

namespace fs = std::filesystem;

DiskStorage::DiskStorage(std::string const& baseDir)
    : mBaseDir(baseDir)
{
}

std::vector<std::string> DiskStorage::getFileList(std::string const& folder)
{
    std::vector<std::string> assetList;
    for (const auto& entry : fs::directory_iterator({mBaseDir / folder}))
    {
        if (entry.is_regular_file())
        {
            assetList.push_back({entry.path().stem().string()});
        }
    }
    return assetList;
}

std::string DiskStorage::getFileContents(std::string const& file)
{
    fs::path assetPath {mBaseDir / file};
    std::ifstream in(assetPath, std::ios::in | std::ios::binary);
    if (in)
    {
        std::string contents;
        in.seekg(0, std::ios::end);
        contents.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&contents[0], contents.size());
        in.close();
        return contents;
    }

    throw std::runtime_error(fmt::format(
        "Error oppening asset [{}]. Error [{}]", assetPath.string(), errno));
}
