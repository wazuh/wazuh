/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/IHttpServer.hpp"
#include "http_server/holdingByteSource.hpp"
#include "http_server/inFlightBudget.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

using remoted::http::HoldingByteSource;
using remoted::http::IByteSource;
using remoted::http::InFlightBudget;

namespace
{
    class StringSource final : public IByteSource
    {
    public:
        explicit StringSource(std::string data)
            : m_data {std::move(data)}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            const auto count = std::min(capacity, m_data.size() - m_offset);
            std::memcpy(buffer, m_data.data() + m_offset, count);
            m_offset += count;
            return count;
        }

    private:
        std::string m_data;
        std::size_t m_offset {0};
    };

    class ThrowingSource final : public IByteSource
    {
    public:
        std::size_t read(char*, std::size_t) override
        {
            throw std::runtime_error {"the resource was modified while it was being streamed"};
        }
    };

    /// Sets a flag when it dies, so a test can tell the order things were destroyed in.
    class FlagOnDestruction final : public IByteSource
    {
    public:
        explicit FlagOnDestruction(std::shared_ptr<bool> destroyed)
            : m_destroyed {std::move(destroyed)}
        {
        }

        ~FlagOnDestruction() override
        {
            *m_destroyed = true;
        }

        std::size_t read(char*, std::size_t) override
        {
            return 0;
        }

    private:
        std::shared_ptr<bool> m_destroyed;
    };

    /// Records, when it is released, whether the inner source had already been destroyed.
    struct OrderProbe
    {
        std::shared_ptr<bool> innerDestroyed;
        std::shared_ptr<bool> innerWasGoneWhenReleased;

        OrderProbe(std::shared_ptr<bool> destroyed, std::shared_ptr<bool> observed)
            : innerDestroyed {std::move(destroyed)}
            , innerWasGoneWhenReleased {std::move(observed)}
        {
        }

        OrderProbe(OrderProbe&&) = default;
        OrderProbe& operator=(OrderProbe&&) = default;

        ~OrderProbe()
        {
            if (innerWasGoneWhenReleased)
            {
                *innerWasGoneWhenReleased = *innerDestroyed;
            }
        }
    };

    std::string drain(IByteSource& source)
    {
        std::string collected;
        std::string buffer(7, '\0');
        while (const auto count = source.read(buffer.data(), buffer.size()))
        {
            collected.append(buffer.data(), count);
        }
        return collected;
    }
} // namespace

TEST(HoldingByteSource, ForwardsEveryReadToTheInnerSource)
{
    HoldingByteSource<int> source {std::make_shared<StringSource>("the whole body"), 0};

    EXPECT_EQ(drain(source), "the whole body");
}

TEST(HoldingByteSource, AnInnerFailureCrossesTheWrapper)
{
    HoldingByteSource<int> source {std::make_shared<ThrowingSource>(), 0};
    char byte = 0;

    EXPECT_THROW(source.read(&byte, 1), std::runtime_error);
}

TEST(HoldingByteSource, HoldsTheTokenUntilItIsDropped)
{
    auto token = std::make_shared<int>(1);
    auto source = std::make_unique<HoldingByteSource<std::shared_ptr<int>>>(std::make_shared<StringSource>("x"), token);
    EXPECT_EQ(token.use_count(), 2);

    // Still held after the last byte: it is the transfer ending, not the body ending, that releases it.
    EXPECT_EQ(drain(*source), "x");
    EXPECT_EQ(token.use_count(), 2);

    source.reset();
    EXPECT_EQ(token.use_count(), 1);
}

TEST(HoldingByteSource, ReleasesTheInnerSourceBeforeTheToken)
{
    // What the token pays for (memory, a descriptor) must be gone before the charge for it is released.
    auto innerDestroyed = std::make_shared<bool>(false);
    auto observed = std::make_shared<bool>(false);

    {
        HoldingByteSource<OrderProbe> source {std::make_shared<FlagOnDestruction>(innerDestroyed),
                                              OrderProbe {innerDestroyed, observed}};
    }

    EXPECT_TRUE(*innerDestroyed);
    EXPECT_TRUE(*observed) << "the token was released while the inner source was still alive";
}

TEST(HoldingByteSource, HoldsABudgetReservationForTheLifeOfTheTransfer)
{
    InFlightBudget budget {1024U * 1024U};
    auto reservation = budget.tryReserveUncounted(4096);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_EQ(budget.availableBytes(), 1024U * 1024U - 4096U);

    auto source = std::make_unique<HoldingByteSource<InFlightBudget::Reservation>>(
        std::make_shared<StringSource>("body"), std::move(*reservation));

    EXPECT_EQ(drain(*source), "body");
    EXPECT_EQ(budget.availableBytes(), 1024U * 1024U - 4096U);

    source.reset();
    EXPECT_EQ(budget.availableBytes(), 1024U * 1024U);
}
