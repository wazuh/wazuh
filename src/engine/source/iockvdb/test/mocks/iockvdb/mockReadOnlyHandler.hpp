#ifndef IOCKVDB_MOCK_READONLY_HANDLER_HPP
#define IOCKVDB_MOCK_READONLY_HANDLER_HPP

#include <gmock/gmock.h>
#include <iockvdb/iReadOnlyHandler.hpp>

namespace ioc::kvdb
{

class MockReadOnlyKVDBHandler : public IReadOnlyKVDBHandler
{
public:
    MOCK_METHOD(const std::string&, name, (), (const, noexcept, override));

    MOCK_METHOD(std::optional<json::Json>, get, (std::string_view key), (const, override));

    MOCK_METHOD(std::vector<std::optional<json::Json>>,
                multiGet,
                (const std::vector<std::string_view>& keys),
                (const, override));

    MOCK_METHOD(bool, hasInstance, (), (const, noexcept, override));
};

} // namespace ioc::kvdb

#endif // IOCKVDB_MOCK_READONLY_HANDLER_HPP
