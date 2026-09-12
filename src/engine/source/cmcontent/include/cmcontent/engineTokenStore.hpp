#ifndef CMCONTENT_ENGINE_TOKEN_STORE_HPP
#define CMCONTENT_ENGINE_TOKEN_STORE_HPP

#include <functional>
#include <string>
#include <string_view>

#include <contentTokenStore.hpp>

namespace cmcontent
{

/**
 * @brief The Engine's change-detection token store, backed by the sync services' own state.
 *
 * The token this library needs per topic is exactly the hash the Engine already persists: a
 * space's `space.hash.sha256` in `cmsync/status/0`, an IOC type's `last_data_hash` in
 * `iocsync/status/0`. Those documents keep their existing shape and field names, so there is no
 * state migration and a downgrade reads them back unchanged.
 *
 * It is deliberately an adapter over two callbacks rather than a second writer into
 * `store::IStore`. `CMSync` and `IocSync` each hold their state in memory, mutate it under their
 * own mutex and dump the whole document in one write; a token store that also wrote that document
 * would be a second writer racing the first, and would have to re-read and merge an array it does
 * not own. Delegating keeps a single writer and one flush per cycle.
 */
class EngineTokenStore final : public content_manager::IContentTokenStore
{
public:
    /// Reads the token a topic is currently at. Returns "" when there is none.
    using Loader = std::function<std::string(std::string_view topic)>;

    /// Persists a topic's token. Returns false when it could not be written.
    using Storer = std::function<bool(std::string_view topic, std::string_view token)>;

    /**
     * @brief Build the adapter.
     *
     * @param loader Reads a topic's token from the owning service's state.
     * @param storer Writes a topic's token through the owning service.
     */
    EngineTokenStore(Loader loader, Storer storer);

    /**
     * @copydoc content_manager::IContentTokenStore::load
     */
    std::string load(std::string_view topic) noexcept override;

    /**
     * @copydoc content_manager::IContentTokenStore::store
     */
    bool store(std::string_view topic, std::string_view token) noexcept override;

    /**
     * @copydoc content_manager::IContentTokenStore::clear
     */
    bool clear(std::string_view topic) noexcept override;

private:
    Loader m_loader;
    Storer m_storer;
};

} // namespace cmcontent

#endif // CMCONTENT_ENGINE_TOKEN_STORE_HPP
