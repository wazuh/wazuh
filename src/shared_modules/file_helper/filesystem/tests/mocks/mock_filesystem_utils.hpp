#include <gmock/gmock.h>

#include <ifilesystem_utils.hpp>

class MockFileSystemUtils : public IFileSystemUtils
{
public:
    MOCK_METHOD(void,
                expand_absolute_path,
                (const std::string& path, std::deque<std::string>& output),
                (const, override));
};
