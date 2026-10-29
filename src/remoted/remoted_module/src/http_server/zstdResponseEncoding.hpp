/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_ZSTD_RESPONSE_ENCODING_HPP
#define _REMOTED_HTTP_SERVER_ZSTD_RESPONSE_ENCODING_HPP

#include "common/contentEncoding.hpp"
#include "common/zstdEncoder.hpp"
#include "compressingResponder.hpp"
#include "responseEncoding.hpp"
#include "zstdCompressingByteSource.hpp"

#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>

namespace remoted::http
{

    /**
     * @brief The zstd (level 3) response coding: the only file that ties the response path to zstd.
     */
    class ZstdResponseEncoding final : public IResponseEncoding
    {
    public:
        std::string_view token() const noexcept override
        {
            return remoted::common::kZstdContentEncoding;
        }

        std::size_t memoryRequired() const override
        {
            return remoted::common::ZstdEncoder::memoryRequired();
        }

        std::shared_ptr<IByteSource> wrap(std::shared_ptr<IByteSource> inner,
                                          InFlightBudget::Reservation reservation) const override
        {
            return std::make_shared<ZstdCompressingByteSource>(std::move(inner), std::move(reservation));
        }
    };

    /// The decorator remoted installs: zstd is the only response coding the manager offers today.
    inline StreamResponderDecorator makeZstdResponseDecorator()
    {
        return makeResponseEncodingDecorator({std::make_shared<const ZstdResponseEncoding>()});
    }

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_ZSTD_RESPONSE_ENCODING_HPP
