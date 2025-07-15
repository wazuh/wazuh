#ifndef _METRICS_MOCK_NOOPMETRIC_HPP
#define _METRICS_MOCK_NOOPMETRIC_HPP

#include <metrics/imetric.hpp>

namespace metrics::mocks
{

class NoOpUintMetric : public detail::BaseMetric<uint64_t>
{
public:
    void update(uint64_t value) override {}
    void create() override {}
    void destroy() override {}
    void enable() override {}
    void disable() override {}
    bool isEnabled() const override { return false; }
};

class NoOpDoubleMetric : public detail::BaseMetric<double>
{
public:
    void update(double value) override {}
    void create() override {}
    void destroy() override {}
    void enable() override {}
    void disable() override {}
    bool isEnabled() const override { return false; }
};

class NoOpIntMetric : public detail::BaseMetric<int64_t>
{
public:
    void update(int64_t value) override {}
    void create() override {}
    void destroy() override {}
    void enable() override {}
    void disable() override {}
    bool isEnabled() const override { return false; }
};
} // namespace metrics::mocks

#endif // _METRICS_MOCK_NOOPMETRIC_HPP
