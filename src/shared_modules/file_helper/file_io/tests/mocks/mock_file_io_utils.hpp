#include <gmock/gmock.h>

#include <ifile_io_utils.hpp>

class MockFileIOUtils : public IFileIOUtils
{
public:
    MOCK_METHOD(void,
                readLineByLine,
                (const std::filesystem::path& filePath, const std::function<bool(const std::string&)>& callback),
                (const, override));
    MOCK_METHOD(std::string, getFileContent, (const std::string& filePath), (const, override));
    MOCK_METHOD(std::vector<char>, getBinaryContent, (const std::string& filePath), (const, override));
};
