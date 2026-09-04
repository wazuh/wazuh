/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CREDENTIAL_PROVIDER_HPP
#define _CREDENTIAL_PROVIDER_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <utility>

namespace containerimages
{
    /// @brief A credential value that clears its storage when it goes out of scope.
    ///
    /// This does not make a secret unrecoverable from a core dump, and it is not claimed
    /// to: it narrows the window in which a freed heap block still holds the value, and it
    /// makes every place that handles one visible in the type system. Deliberately not
    /// convertible to std::string, so a secret cannot reach a log line by being appended
    /// to a message; the only way out is value(), which is easy to grep for in review.
    class Secret final
    {
        public:
            Secret() = default;

            explicit Secret(std::string value)
                : m_value {std::move(value)}
            {
            }

            ~Secret()
            {
                scrub();
            }

            Secret(const Secret&) = delete;
            Secret& operator=(const Secret&) = delete;

            Secret(Secret&& other) noexcept
                : m_value {std::move(other.m_value)}
            {
                other.scrub();
            }

            Secret& operator=(Secret&& other) noexcept
            {
                if (this != &other)
                {
                    scrub();
                    m_value = std::move(other.m_value);
                    other.scrub();
                }

                return *this;
            }

            /// @brief The secret itself. Every call site is a place to review.
            const std::string& value() const
            {
                return m_value;
            }

            bool empty() const
            {
                return m_value.empty();
            }

        private:
            void scrub()
            {
                // volatile so the writes are not optimized away as dead stores, which is
                // exactly what a compiler is entitled to do to a buffer about to be freed.
                volatile char* data {const_cast<volatile char*>(m_value.data())};

                for (std::size_t index = 0; index < m_value.size(); ++index)
                {
                    data[index] = '\0';
                }

                m_value.clear();
            }

            std::string m_value;
    };

    /// @brief Source of the credentials the module authenticates with.
    ///
    /// The registry reader depends on this rather than on any store, so it is testable
    /// with a stub and the storage backend stays replaceable.
    class ICredentialProvider
    {
        public:
            virtual ~ICredentialProvider() = default;

            /// @brief Look a credential up by family and key name.
            /// @return The value, or nothing when the family or the key is not present.
            ///
            /// A missing credential is an ordinary outcome, not an error: a public
            /// repository is pulled with no credential at all.
            virtual std::optional<Secret> get(const std::string& family, const std::string& key) const = 0;
    };
} // namespace containerimages

#endif // _CREDENTIAL_PROVIDER_HPP
