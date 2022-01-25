#ifndef _GRAPH_TEST_H
#define _GRAPH_TEST_H

#include <chrono>
#include <thread>
#include <type_traits>

#include "rxcpp/rx.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

template <typename E> class fakeConnectable
{
private:
    rxcpp::subjects::subject<E> m_subj;
    rxcpp::observable<E> m_obs;

public:
    std::string m_name;

    fakeConnectable(std::string name) : m_name(name), m_obs(m_subj.get_observable()){};
    fakeConnectable(std::string name, rxcpp::subjects::subject<E> subj, rxcpp::observable<E> obs)
        : m_name(name), m_subj(subj), m_obs(obs){};

    void connect(std::shared_ptr<fakeConnectable<E>> other)
    {
        this->m_obs.subscribe(other->input());
    }

    auto set(rxcpp::observable<E> obs)
    {
        this->m_obs = obs;
    }
    auto name()
    {
        return this->m_name;
    }
    auto output() const
    {
        return this->m_obs;
    }
    auto input() const
    {
        return this->m_subj.get_subscriber();
    }
};

#endif // _GRAPH_TEST_H
