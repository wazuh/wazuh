#ifndef _STORE_MOCK_STORE_HPP
#define _STORE_MOCK_STORE_HPP

#include <gmock/gmock.h>

#include <store/istore.hpp>

namespace store::mocks
{

/******************************************************************************/
// Helper functions to mock method responses
/******************************************************************************/
inline base::OptError storeError()
{
    return base::Error {"Mocked store error"};
}

inline base::OptError storeOk()
{
    return std::nullopt;
}

template<typename T>
inline base::RespOrError<T> storeReadError()
{
    return base::Error {"Mocked store read error"};
}

template<typename... Names>
inline base::RespOrError<Col> storeReadColResp(Names&&... names)
{
    return Col {std::forward<Names>(names)...};
}

inline base::RespOrError<Col> storeReadColResp(const Col& col)
{
    return col;
}

inline base::RespOrError<Doc> storeReadDocResp(const Doc& doc)
{
    return doc;
}

template<typename... Names>
inline std::vector<NamespaceId> storeListNamespacesResp(Names&&... namespaces)
{
    return std::vector<NamespaceId> {std::forward<Names>(namespaces)...};
}

inline std::vector<NamespaceId> storeListNamespacesResp(const std::vector<NamespaceId>& namespaces)
{
    return namespaces;
}

inline std::optional<NamespaceId> storeGetNamespaceError()
{
    return std::nullopt;
}

inline std::optional<NamespaceId> storeGetNamespaceResp(const NamespaceId& namespaceId)
{
    return namespaceId;
}

/******************************************************************************/
// Mock classes
/******************************************************************************/
class MockStoreRead : public store::IStoreReader
{
public:
    MOCK_METHOD((base::RespOrError<Doc>), readDoc, (const base::Name&), (const, override));
    MOCK_METHOD((base::RespOrError<Col>), readCol, (const base::Name&, const NamespaceId&), (const, override));
    MOCK_METHOD((bool), existsDoc, (const base::Name&), (const, override));
    MOCK_METHOD((bool), existsCol, (const base::Name&, const NamespaceId& namespaceId), (const, override));
    MOCK_METHOD((std::vector<NamespaceId>), listNamespaces, (), (const, override));
    MOCK_METHOD((std::optional<NamespaceId>), getNamespace, (const base::Name&), (const, override));
};

class MockStoreInternal : public store::IStoreInternal
{
public:
    MOCK_METHOD((base::OptError), createInternalDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::RespOrError<Doc>), readInternalDoc, (const base::Name&), (const, override));
    MOCK_METHOD((base::OptError), updateInternalDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::OptError), upsertInternalDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::OptError), deleteInternalDoc, (const base::Name&), (override));
    MOCK_METHOD((base::RespOrError<Col>), readInternalCol, (const base::Name&), (const, override));
    MOCK_METHOD((bool), existsInternalDoc, (const base::Name&), (const, override));
};

class MockStore : public store::IStore
{
public:
    MOCK_METHOD((base::RespOrError<Doc>), readDoc, (const base::Name&), (const, override));
    MOCK_METHOD((base::RespOrError<Col>), readCol, (const base::Name&, const NamespaceId&), (const, override));
    MOCK_METHOD((bool), existsDoc, (const base::Name&), (const, override));
    MOCK_METHOD((bool), existsCol, (const base::Name&, const NamespaceId& namespaceId), (const, override));
    MOCK_METHOD((std::vector<NamespaceId>), listNamespaces, (), (const, override));
    MOCK_METHOD((std::optional<NamespaceId>), getNamespace, (const base::Name&), (const, override));

    MOCK_METHOD((base::OptError), createInternalDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::RespOrError<Doc>), readInternalDoc, (const base::Name&), (const, override));
    MOCK_METHOD((base::OptError), updateInternalDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::OptError), upsertInternalDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::OptError), deleteInternalDoc, (const base::Name&), (override));
    MOCK_METHOD((base::RespOrError<Col>), readInternalCol, (const base::Name&), (const, override));
    MOCK_METHOD((bool), existsInternalDoc, (const base::Name&), (const, override));

    MOCK_METHOD((base::OptError), createDoc, (const base::Name&, const NamespaceId&, const Doc&), (override));
    MOCK_METHOD((base::OptError), updateDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::OptError), upsertDoc, (const base::Name&, const NamespaceId&, const Doc&), (override));
    MOCK_METHOD((base::OptError), deleteDoc, (const base::Name&), (override));
    MOCK_METHOD((base::OptError), deleteCol, (const base::Name&, const NamespaceId&), (override));
};

} // namespace store::mocks

#endif // _STORE_MOCK_STORE_HPP
