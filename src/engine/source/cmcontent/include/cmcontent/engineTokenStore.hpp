// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMCONTENT_ENGINE_TOKEN_STORE_HPP
#define CMCONTENT_ENGINE_TOKEN_STORE_HPP

#include <functional>
#include <string>
#include <string_view>

#include <contentTokenStore.hpp>

namespace cmcontent
{

/**
 * @brief A change-detection token store over its owner's state, through two callbacks.
 *
 * For a token that lives in state the owner already persists — an IOC type's `last_data_hash` in
 * `iocsync/status/0` — so the owner stays its single writer and flushes it once per cycle.
 * A clear is a store of "": an empty hash is what "nothing committed" looks like there.
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
