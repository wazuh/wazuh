#include <type_traits>
#include <chrono>
#include <thread>

#include "rxcpp/rx.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "


template <typename E>
class fakeConnectable
{
private:
    rxcpp::subjects::subject<E> m_subj;
    rxcpp::observable<E> m_obs;

public:
    std::string m_name;

    fakeConnectable(std::string name) : m_name(name), m_obs(m_subj.get_observable()){};
    fakeConnectable(std::string name, rxcpp::subjects::subject<E> subj, rxcpp::observable<E> obs) : m_name(name), m_subj(subj), m_obs(obs){};

    fakeConnectable<E> map(std::function<E(E)> fn)
    {
        return fakeConnectable(this->m_name, this->m_subj, this->m_obs | rxcpp::operators::map(fn));
    }

    fakeConnectable<E> filter(std::function<bool(E)> fn)
    {
        return fakeConnectable(this->m_name, this->m_subj, this->m_obs | rxcpp::operators::filter(fn));
    }

    auto observable() const { return this->m_obs; }
    auto subscriber() const { return this->m_subj.get_subscriber(); }
};

