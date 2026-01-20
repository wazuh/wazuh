#include <store/store.hpp>

#include <base/logging.hpp>

namespace store
{

Store::Store(std::shared_ptr<IDriver> driver)
    : m_driver(std::move(driver))
{
    if (m_driver == nullptr)
    {
        throw std::runtime_error("Store driver cannot be null");
    }
}

Store::~Store() = default;

base::OptError Store::createDoc(const base::Name& name, const Doc& content)
{
    return m_driver->createDoc(name, content);
}

base::RespOrError<Doc> Store::readDoc(const base::Name& name) const
{
    return m_driver->readDoc(name);
}

base::OptError Store::updateDoc(const base::Name& name, const Doc& content)
{
    return m_driver->updateDoc(name, content);
}

base::OptError Store::upsertDoc(const base::Name& name, const Doc& content)
{
    if (!m_driver->existsDoc(name))
    {
        return m_driver->createDoc(name, content);
    }

    return m_driver->updateDoc(name, content);
}

base::OptError Store::deleteDoc(const base::Name& name)
{
    return m_driver->deleteDoc(name);
}

base::RespOrError<Col> Store::readCol(const base::Name& name) const
{
    return m_driver->readCol(name);
}

bool Store::existsDoc(const base::Name& name) const
{
    return m_driver->existsDoc(name);
}

} // namespace store
