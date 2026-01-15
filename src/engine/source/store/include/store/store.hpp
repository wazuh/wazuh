#ifndef _STORE_HPP
#define _STORE_HPP

#include <memory>

#include <store/idriver.hpp>
#include <store/istore.hpp>

namespace store
{

class Store : public IStore
{
private:
    std::shared_ptr<IDriver> m_driver; ///< Store driver.

public:
    /**
     * @brief Construct a new Doc Namespace Manager object using the store.
     */
    Store(std::shared_ptr<IDriver> driver);

    ~Store();

    /**
     * @copydoc IStoreInternal::createInternalDoc
     */
    base::OptError createInternalDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::readInternalDoc
     */
    base::RespOrError<Doc> readInternalDoc(const base::Name& name) const override;

    /**
     * @copydoc IStoreInternal::updateInternalDoc
     */
    base::OptError updateInternalDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::upsertInternalDoc
     */
    base::OptError upsertInternalDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::deleteInternalDoc
     */
    base::OptError deleteInternalDoc(const base::Name& name) override;

    /**
     * @copydoc IStoreInternal::readInternalCol
     */
    base::RespOrError<Col> readInternalCol(const base::Name& name) const override;

    /**
     * @copydoc IStoreInternal::existsInternalDoc
     */
    bool existsInternalDoc(const base::Name& name) const override;
};

} // namespace store
#endif // _STORE_HPP
