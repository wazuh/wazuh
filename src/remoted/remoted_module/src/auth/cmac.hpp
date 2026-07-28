/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace remoted::auth
{

    /**
     * @brief One agent's key is unusable (wrong length for AES-128/192/256).
     *
     * Per-agent and expected in normal operation (a corrupted key column in client.keys), so the
     * caller answers that one agent 401 and does not raise an alarm.
     */
    struct CmacKeyError : std::invalid_argument
    {
        using std::invalid_argument::invalid_argument;
    };

    /**
     * @brief AES-CMAC itself is unavailable (OpenSSL provider failure).
     *
     * Distinct from CmacKeyError on purpose: this is global and permanent -- EVERY agent will fail
     * to authenticate until it is fixed (a missing/misconfigured OpenSSL provider, FIPS mode, etc.).
     * Without the distinction it was indistinguishable from an ordinary bad key, so a
     * manager-wide outage looked like routine per-agent noise and was logged nowhere.
     */
    struct CmacProviderError : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    /**
     * @brief Incremental AES-CMAC.
     *
     * The payload requires only one cryptographic pass, computed incrementally
     * as body chunks arrive via update().
     */
    class Cmac
    {
    public:
        static constexpr std::size_t kMacSize = 16; ///< AES-CMAC output size, in bytes.

        /**
         * @brief Initialize AES-CMAC with a pre-shared key.
         *
         * @param key Must be 16, 24 or 32 bytes (AES-128/192/256).
         * @throws CmacKeyError if key's size is not 16, 24 or 32 (per-agent, expected).
         * @throws CmacProviderError if the underlying cryptographic calls fail (global, alarming).
         */
        explicit Cmac(const std::vector<std::uint8_t>& key);
        ~Cmac();

        Cmac(const Cmac&) = delete;
        Cmac& operator=(const Cmac&) = delete;
        Cmac(Cmac&&) = delete;
        Cmac& operator=(Cmac&&) = delete;

        /// Feed one more chunk of message bytes into the running MAC.
        void update(const std::uint8_t* data, std::size_t len);
        /// @copydoc update(const std::uint8_t*, std::size_t)
        void update(std::string_view data);

        /**
         * @brief Finalize the MAC over everything fed via update() so far.
         *
         * May only be called once; consumes the underlying context.
         *
         * @return The kMacSize-byte MAC.
         * @throws std::logic_error if called twice.
         * @throws std::runtime_error if the underlying finalize call fails.
         */
        std::array<std::uint8_t, kMacSize> finalize();

    private:
        struct Impl;
        // Defaulted to nullptr: if the constructor's cipherNameFor() validation throws before
        // m_impl is ever allocated, this is never read (construction aborts, ~Cmac() never runs) --
        // the default is defensive hygiene, not load-bearing.
        Impl* m_impl {nullptr};
    };

    /// Render bytes as lowercase hex, two characters per byte.
    std::string toLowerHex(const std::uint8_t* data, std::size_t len);

    /**
     * @brief Parse a lowercase hex string into raw bytes.
     *
     * @param hex    Input string; must be exactly outLen * 2 lowercase hex characters.
     * @param out    Buffer to write outLen decoded bytes into.
     * @param outLen Number of bytes expected/written.
     * @return false if hex is the wrong length or contains a non-hex/uppercase character.
     */
    bool fromLowerHex(std::string_view hex, std::uint8_t* out, std::size_t outLen);

    /**
     * @brief Constant-time byte comparison.
     *
     * Required to avoid leaking, via timing, how much of a MAC matched.
     *
     * @param a,b Buffers to compare; both must be at least len bytes.
     * @param len Number of bytes to compare.
     * @return Whether the two buffers are byte-for-byte equal.
     */
    bool constantTimeEquals(const std::uint8_t* a, const std::uint8_t* b, std::size_t len);

} // namespace remoted::auth
