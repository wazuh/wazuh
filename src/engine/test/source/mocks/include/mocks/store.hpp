#ifndef _STORE_HPP
#define _STORE_HPP

#include <store/istore.hpp>
#include <gmock/gmock.h>

class MockStoreRead : public store::IStoreRead
{
public:
    MOCK_CONST_METHOD1(get, std::variant<json::Json, base::Error>(const base::Name& name));
};

class MockStore : public store::IStore
{
public:
    MOCK_METHOD2(add, std::optional<base::Error>(const base::Name& name, const json::Json& content));
    MOCK_METHOD1(del, std::optional<base::Error>(const base::Name& name));
    MOCK_METHOD2(update, std::optional<base::Error>(const base::Name& name, const json::Json& content));
    MOCK_METHOD2(addUpdate, std::optional<base::Error>(const base::Name& name, const json::Json& content));
    MOCK_CONST_METHOD1(get, std::variant<json::Json, base::Error>(const base::Name& name));
};

#endif // _STORE_HPP
