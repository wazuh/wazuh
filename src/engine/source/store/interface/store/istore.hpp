#ifndef _STORE_ISTORE_HPP
#define _STORE_ISTORE_HPP

#include <list>
#include <string>
#include <utility>

#include <store/idriver.hpp>
#include <store/namespaceId.hpp>

namespace store
{

class IStoreReader
{
public:
    virtual ~IStoreReader() = default;

    virtual base::RespOrError<Doc> readDoc(const base::Name& name) const = 0;
    virtual base::RespOrError<Col> readCol(const base::Name& name, const NamespaceId& NamespaceId) const = 0;
    virtual bool exists(const base::Name& name) const = 0;
    virtual bool existsDoc(const base::Name& name) const = 0;
    virtual bool existsCol(const base::Name& name) const = 0;

    virtual std::vector<NamespaceId> listNamespaces() const = 0;

    virtual base::OptError getNamespace(const base::Name& name) const = 0;

    virtual base::RespOrError<Col> list(const NamespaceId& namespaceId) const = 0;
    virtual base::RespOrError<Col> listDoc(const NamespaceId& namespaceId) const = 0;
    virtual base::RespOrError<Col> listCol(const NamespaceId& namespaceId) const = 0;
    // decoder
    // filter


};

class IStore : public IStoreReader
{
public:
    virtual ~IStore() = default;

    virtual base::OptError createDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content) = 0;
    virtual base::OptError updateDoc(const base::Name& name, const Doc& content) = 0;
    virtual base::OptError upsertDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content) = 0;
    virtual base::OptError deleteDoc(const base::Name& name) = 0;
    virtual base::OptError deleteCol(const base::Name& name) = 0;

    virtual base::OptError createNamespace(const NamespaceId& namespaceId) = 0;
    virtual base::OptError deleteNamespace(const NamespaceId& namespaceId) = 0;
};

} // namespace store

#endif // _STORE_ISTORE_HPP
