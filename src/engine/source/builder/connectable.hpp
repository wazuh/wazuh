#ifndef _CONNECTABLE_H
#define _CONNECTABLE_H

#include "json.hpp"
#include "rxcpp/rx.hpp"
#include <string>

namespace builder::internals
{

/**
 * @brief a connectable has the property of being able to be connected
 * with another connectable. A connectable does not know its childs, and only
 * knows about the name of the parents it should be connected to.
 *
 * @tparam T the type of the event which will flow between connected
 * connectables
 */
class Connectable
{
private:
    std::string m_name;
    std::vector<std::string> m_parents;

    rxcpp::subjects::subject<json::Document> m_subj;
    rxcpp::observable<json::Document> m_obs;

public:
    /**
     * @brief Construct a new Connectable object
     *
     * @param name
     * @param parents
     */
    Connectable(std::string name, const std::vector<std::string> & parents)
        : m_name(name), m_parents(parents), m_obs(m_subj.get_observable())
    {
    }
    Connectable(std::string name) : m_name(name), m_obs(m_subj.get_observable())
    {
    }
    /**
     * @brief connects the ouput of this connectable to the input
     * og the other connectable. This does not check against
     * loops.
     *
     * @param other connectable to send our output
     */
    void connect(const Connectable & other)
    {
        this->output().subscribe(other.input());
    }

    /**
     * @brief connects with another connectable holded by a shared_ptr
     *
     * @param other
     */
    void connect(const std::shared_ptr<Connectable> & other)
    {
        this->output().subscribe(other->input());
    }

    /**
     * @brief set the observable of this connectable. Used to
     * apply observers to this connectable oobservable.
     *
     * @param obs
     */
    void set(const rxcpp::observable<json::Document> & obs)
    {
        this->m_obs = obs;
    }

    /**
     * @brief return our subscriber, which will receive the events we want
     *
     * @return rxcpp::subscriber<T> our subscriber
     */

    rxcpp::subscriber<json::Document> input() const
    {
        return this->m_subj.get_subscriber();
    }
    /**
     * @brief returns our observable, to whom other will connect to receive
     * the events we have processed.
     *
     * @return rxcpp::observable<T> our observable
     */
    rxcpp::observable<json::Document> output() const
    {
        return this->m_obs;
    }

    /**
     * @brief return the list of our parents
     *
     * @return std::vector<std::string>
     */
    auto parents()
    {
        return this->m_parents;
    }

    /**
     * @brief returns our name
     *
     * @return std::string
     */
    auto name() const
    {
        return this->m_name;
    }
};

} // namespace builder::internals
#endif // _CONNECTABLE_H
