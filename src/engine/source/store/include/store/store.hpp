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
     * @copydoc IStoreInternal::createDoc
     */
    base::OptError createDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::readDoc
     */
    base::RespOrError<Doc> readDoc(const base::Name& name) const override;

    /**
     * @copydoc IStoreInternal::updateDoc
     */
    base::OptError updateDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::upsertDoc
     */
    base::OptError upsertDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::deleteDoc
     */
    base::OptError deleteDoc(const base::Name& name) override;

    /**
     * @copydoc IStoreInternal::readCol
     */
    base::RespOrError<Col> readCol(const base::Name& name) const override;

    /**
     * @copydoc IStoreInternal::existsDoc
     */
    bool existsDoc(const base::Name& name) const override;
};

} // namespace store
#endif // _STORE_HPP
