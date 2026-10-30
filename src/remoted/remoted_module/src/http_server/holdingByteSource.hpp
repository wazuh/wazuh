/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_HOLDING_BYTE_SOURCE_HPP
#define _REMOTED_HTTP_SERVER_HOLDING_BYTE_SOURCE_HPP

#include "IHttpServer.hpp"

#include <cstddef>
#include <memory>
#include <utility>

namespace remoted::http
{

    /**
     * @brief Stream source that forwards another source and keeps @p Token alive for as long as the
     *        transport keeps this one.
     *
     * The transport's pump is a source's only owner and drops it when the transfer ends -- finished,
     * failed, peer gone, or the server torn down -- so whatever is held here (an agent's request
     * slot, an in-flight budget reservation) is released exactly when the transfer is, however
     * slowly the peer reads it. It is the one place that tie is written, so a layer that only wants
     * to hold something does not have to be an IByteSource to do it.
     *
     * The token is declared before the inner source, so the inner source is destroyed first: what
     * the token pays for (memory, a descriptor) is gone before the charge for it is released.
     */
    template<typename Token>
    class HoldingByteSource final : public IByteSource
    {
    public:
        HoldingByteSource(std::shared_ptr<IByteSource> inner, Token token)
            : m_token {std::move(token)}
            , m_inner {std::move(inner)}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            return m_inner->read(buffer, capacity);
        }

    private:
        Token m_token;
        std::shared_ptr<IByteSource> m_inner;
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_HOLDING_BYTE_SOURCE_HPP
