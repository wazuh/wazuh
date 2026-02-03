#ifndef _KVDBIOC_MOCK_READONLY_HANDLER_HPP
#define _KVDBIOC_MOCK_READONLY_HANDLER_HPP

#include <gmock/gmock.h>
#include <kvdbioc/iReadOnlyHandler.hpp>

namespace kvdbioc
{

class MockReadOnlyKVDBHandler : public IReadOnlyKVDBHandler
{
public:
    MOCK_METHOD(const DbName&, name, (), (const, noexcept, override));

    MOCK_METHOD(std::optional<json::Json>, get, (std::string_view key), (const, override));

    MOCK_METHOD(std::vector<std::optional<json::Json>>,
                multiGet,
                (const std::vector<std::string_view>& keys),
                (const, override));

    MOCK_METHOD(bool, hasInstance, (), (const, noexcept, override));
};

} // namespace kvdbioc

#endif // _KVDBIOC_MOCK_READONLY_HANDLER_HPP
