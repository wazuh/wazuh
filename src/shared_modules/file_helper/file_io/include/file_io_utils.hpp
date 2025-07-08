#pragma once

#include <ifile_io_utils.hpp>
#include <ifile_io_wrapper.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <string>

namespace file_io
{
    /// @copydoc IFileIOUtils
    class FileIOUtils : public IFileIOUtils
    {
    public:
        /// @brief  FileIOUtils constructor
        FileIOUtils(std::shared_ptr<IFileIOWrapper> fileIOWrapper = nullptr);

        /// @copydoc IFileIOUtils::readLineByLine
        void readLineByLine(const std::filesystem::path& filePath,
                            const std::function<bool(const std::string&)>& callback) const override;

        /// @copydoc IFileIOUtils::getFileContent
        std::string getFileContent(const std::string& filePath) const override;

        /// @copydoc IFileIOUtils::getBinaryContent
        std::vector<char> getBinaryContent(const std::string& filePath) const override;

    private:
        std::shared_ptr<IFileIOWrapper> m_fileIOWrapper;
    };
} // namespace file_io
