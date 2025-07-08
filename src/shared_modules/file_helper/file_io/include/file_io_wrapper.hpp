#pragma once

#include <ifile_io_wrapper.hpp>

#include <string>

namespace file_io
{
    /// @copydoc IFileIOWrapper
    class FileIOWrapper : public IFileIOWrapper
    {
    public:
        /// @copydoc IFileIOWrapper::get_line
        bool get_line(std::istream& file, std::string& line) const override;

        /// @copydoc IFileIOWrapper::create_ifstream
        std::unique_ptr<std::ifstream> create_ifstream(const std::string& filePath,
                                                       std::ios_base::openmode mode = std::ios_base::in) const override;

        /// @copydoc IFileIOWrapper::get_rdbuf
        std::streambuf* get_rdbuf(const std::ifstream& file) const override;

        /// @copydoc IFileIOWrapper::is_open
        bool is_open(const std::ifstream& file) const override;
    };
} // namespace file_io
