#ifndef _ROUTER2_WORKER_HPP
#define _ROUTER2_WORKER_HPP

#include <memory>

#include <router/types.hpp>

#include "environment.hpp"

namespace router
{

// Table here

class RuntimeEntry : public Entry
{
private:
    std::shared_ptr<Environment> m_environment;

public:
    RuntimeEntry(const Entry& entry) : Entry {entry} {

    };

    const std::shared_ptr<Environment>& environment() const { return m_environment; }

    bool available() const { return m_environment != nullptr && this->m_status == env::State::ACTIVE; }

    base::OptError build();

    const Entry& entry() const
    {
        // Update metada
        return *this;
    }
};

class Worker
{
};

} // namespace router

#endif // _ROUTER2_WORKER_HPP
