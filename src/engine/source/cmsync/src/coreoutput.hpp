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

class CoreOutputReader
{

private:
    std::filesystem::path m_outputPath {}; ///< Path of directory to load YML output files.

public:
    CoreOutputReader() = delete;
    explicit CoreOutputReader(const std::string& outputPath);
    ~CoreOutputReader() = default;

    std::tuple<base::Name, std::string> getOutputContent(const std::filesystem::path& filePath) const;
    std::vector<std::filesystem::path> getAllOutputFiles() const;
    const std::filesystem::path& outputPath() const { return m_outputPath; }
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
