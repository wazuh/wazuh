#include <gmock/gmock.h>

#include <ifile_io_wrapper.hpp>

class MockFileIOWrapper : public IFileIOWrapper
{
public:
    MOCK_METHOD(std::unique_ptr<std::ifstream>,
                create_ifstream,
                (const std::string& filePath, std::ios_base::openmode mode),
                (const, override));
    MOCK_METHOD(std::streambuf*, get_rdbuf, (const std::ifstream& file), (const, override));
    MOCK_METHOD(bool, is_open, (const std::ifstream& file), (const, override));
    MOCK_METHOD(bool, get_line, (std::istream & file, std::string& line), (const, override));
};
