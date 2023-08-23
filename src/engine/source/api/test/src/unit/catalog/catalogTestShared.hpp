#ifndef _CATALOG_TEST_SHARED_HPP
#define _CATALOG_TEST_SHARED_HPP

#include <memory>

#include <fmt/format.h>

#include <api/catalog/catalog.hpp>
#include <store/mockStore.hpp>
#include <rbac/mockRbac.hpp>

using namespace store::mocks;

const base::Name successName({"decoder", "name", "ok"});
const base::Name failName {{"decoder", "name", "fail"}};
const store::Doc successJsonOriginal(fmt::format("{{\"name\": \"{}\"}}", successName.fullName()).c_str());
const store::Doc successJson(fmt::format("{{\"name\": \"{}\"}}", successName.fullName()).c_str());
const store::Col successCollection {successName};
const std::string successCollectionJson(fmt::format("[\"{}\"]", successName.fullName()));
const std::string successYml(fmt::format("name: {}", successName.fullName()).c_str());
const std::string successCollectionYml(fmt::format("- {}", successName.fullName()));
const store::Doc validJson(R"({})");
const store::Doc invalidJson(R"([])");
const std::string schema {R"({"type": "object"})"};
const base::Name successSchemaName({"schema", "name", "ok"});
const base::Name failSchemaName({"schema", "name", "fail"});

const api::catalog::Resource successResourceAssetJson {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                successName.parts()[1],
                successName.parts()[2]}),
    api::catalog::Resource::Format::json};

const api::catalog::Resource successResourceAssetYml {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                successName.parts()[1],
                successName.parts()[2]}),
    api::catalog::Resource::Format::yaml};

const api::catalog::Resource failResourceAsset {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                failName.parts()[1],
                failName.parts()[2]}),
    api::catalog::Resource::Format::json};

const api::catalog::Resource successCollectionAssetJson {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder)}),
    api::catalog::Resource::Format::json};

const api::catalog::Resource successCollectionAssetYml {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder)}),
    api::catalog::Resource::Format::yaml};

// class FakeStore : public store::IStore
// {
// public:
//     std::shared_ptr<json::Json> lastAdded;

//     ~FakeStore() = default;

//     std::variant<json::Json, base::Error> get(const base::Name& name) const override
//     {
//         if (name.parts()[2] == successName.parts()[2])
//         {
//             return successJson;
//         }
//         if (name == successCollectionAssetJson.m_name)
//         {
//             return successCollectionJson;
//         }

//         return base::Error {"error"};
//     }

//     std::optional<base::Error> add(const base::Name& name, const json::Json& content) override
//     {
//         if (name.parts()[2] == successName.parts()[2])
//         {
//             lastAdded = std::make_shared<json::Json>(content);
//             return std::nullopt;
//         }

//         return base::Error {"error"};
//     }

//     std::optional<base::Error> del(const base::Name& name) override
//     {
//         if (name.parts()[2] == successName.parts()[2])
//         {
//             lastAdded.reset();
//             return std::nullopt;
//         }

//         if (name == successCollectionAssetJson.m_name)
//         {
//             lastAdded.reset();
//             return std::nullopt;
//         }

//         return base::Error {"error"};
//     }

//     std::optional<base::Error> update(const base::Name& name, const json::Json& content) override
//     {
//         if (name.parts()[2] == successName.parts()[2])
//         {
//             return std::nullopt;
//         }

//         return base::Error {"error"};
//     }

//     std::optional<base::Error> addUpdate(const base::Name& name, const json::Json& content) override
//     {
//         if (name.parts()[2] == successName.parts()[2])
//         {
//             return std::nullopt;
//         }

//         return base::Error {"error"};
//     }
// };

class FakeValidator : public builder::IValidator
{
public:
    ~FakeValidator() = default;

    std::optional<base::Error> validatePolicy(const json::Json& json) const override
    {
        if (json.isObject())
        {
            return std::nullopt;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> validateIntegration(const json::Json& json) const override
    {
        if (json.isObject())
        {
            return std::nullopt;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> validateAsset(const json::Json& json) const override
    {
        if (json.isObject())
        {
            return std::nullopt;
        }

        return base::Error {"error"};
    }
};

inline api::catalog::Config getConfig(bool schemaOk = true)
{
    api::catalog::Config config;
    auto mockStore = std::make_shared<MockStore>();
    config.store = mockStore;
    config.validator = std::make_shared<FakeValidator>();

    EXPECT_CALL(*mockStore, readDoc(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name) -> base::RespOrError<store::Doc>
            {
                if (name.parts()[2] == successName.parts()[2])
                {
                    return successJson;
                }

                return base::Error {"error"};
            }));

    EXPECT_CALL(*mockStore, readCol(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name, const store::NamespaceId& namespaceId) -> base::RespOrError<store::Col>
            {
                if (name == successCollectionAssetJson.m_name)
                {
                    return storeReadColResp(successCollection);
                }

                return base::Error {"error"};
            }));

    EXPECT_CALL(*mockStore, createDoc(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name, const store::NamespaceId& namespaceId, const store::Doc& content)
                -> base::OptError
            {
                if (name.parts()[2] == successName.parts()[2])
                {
                    return base::noError();
                }

                return base::Error {"error"};
            }));

    EXPECT_CALL(*mockStore, updateDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name, const store::Doc& content) -> base::OptError
            {
                if (name.parts()[2] == successName.parts()[2])
                {
                    return base::noError();
                }

                return base::Error {"error"};
            }));

    EXPECT_CALL(*mockStore, upsertDoc(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name, const store::NamespaceId& namespaceId, const store::Doc& content)
                -> base::OptError
            {
                if (name.parts()[2] == successName.parts()[2])
                {
                    return base::noError();
                }

                return base::Error {"error"};
            }));

    EXPECT_CALL(*mockStore, deleteDoc(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name) -> base::OptError
            {
                if (name.parts()[2] == successName.parts()[2])
                {
                    return base::noError();
                }

                return base::Error {"error"};
            }));

    EXPECT_CALL(*mockStore, deleteCol(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name, const store::NamespaceId& namespaceId) -> base::OptError
            {
                if (name == successCollectionAssetJson.m_name)
                {
                    return base::noError();
                }

                return base::Error {"error"};
            }));

    if (schemaOk)
    {
        config.assetSchema = successSchemaName.fullName();
        config.environmentSchema = successSchemaName.fullName();
    }
    else
    {
        config.assetSchema = failSchemaName.fullName();
        config.environmentSchema = failSchemaName.fullName();
    }

    return config;
}

#endif // _CATALOG_TEST_SHARED_HPP
