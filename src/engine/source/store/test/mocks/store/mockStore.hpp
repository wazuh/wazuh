#ifndef _STORE_MOCK_STORE_H
#define _STORE_MOCK_STORE_H

#include <gmock/gmock.h>

#include <store/istore.hpp>

namespace store::mocks
{

inline std::variant<json::Json, base::Error> getJson(const char* jsonStr)
{
    return json::Json(jsonStr);
}

inline std::variant<json::Json, base::Error> getJson(const json::Json& json)
{
    return json;
}

inline std::variant<json::Json, base::Error> getError(const std::string& errorStr = "")
{
    return base::Error {errorStr};
}

inline std::optional<base::Error> errorRes(const std::string& errorStr = "")
{
    return base::Error {errorStr};
}

inline std::optional<base::Error> okRes()
{
    return std::nullopt;
}

class MockStoreRead : public IStoreRead
{
public:
    MOCK_METHOD((std::variant<json::Json, base::Error>), get, (const base::Name&), (const, override));
};

class MockStore : public IStore
{
public:
    MOCK_METHOD((std::variant<json::Json, base::Error>), get, (const base::Name&), (const, override));
    MOCK_METHOD(std::optional<base::Error>, add, (const base::Name&, const json::Json&), (override));
    MOCK_METHOD(std::optional<base::Error>, del, (const base::Name&), (override));
    MOCK_METHOD(std::optional<base::Error>, update, (const base::Name&, const json::Json&), (override));
};

} // namespace store::mocks

#endif // _STORE_MOCK_STORE_H
